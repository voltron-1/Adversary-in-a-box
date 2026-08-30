"""
tests/test_suricata_pcap_replay.py -- Phase G5.1

A pcap-replay regression harness for blue-team/detection/suricata/local.rules:
one synthetic pcap per sid, replayed through the real `suricata` binary
against the lab's own suricata.yaml + local.rules, asserting which sids
actually fire. Before this, an unfired rule looked identical in the repo to
a covered one -- several of the Tier-3 rule bugs Phase 5 exists to fix
(G5.2-G5.5) shipped exactly that way. This suite is the net that makes them
independently verifiable instead of taken on faith.

Requires the `suricata` binary and the `scapy` package, neither of which
are part of any subproject's runtime requirements.txt (this harness is the
only consumer of either). CI installs both; skips cleanly everywhere else,
consistent with the project's existing live-stack-only test pattern.

G5.1 originally found two rules (sid:1000022, sid:1000050) using the wrong
sticky buffer / byte offset, unable to fire against any real traffic shaped
the way the rule's own msg/comment claimed; G5.4 (#193) rewrote both (plus
sid:1000003 and sid:1000052, found broken/fragile the same way while
building this harness) onto proper sticky buffers. The cases below assert
the current, fixed behavior.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
# `python -m unittest discover -s tests` (how CI and this repo always run
# the suite) puts `tests/` on sys.path itself, so the bare `import
# suricata_pcap_helpers` below just works. Insert it explicitly too so this
# module also works under `python -m unittest tests.test_suricata_pcap_replay`
# (dotted-module form), which doesn't.
sys.path.insert(0, str(Path(__file__).parent))
SURICATA_DIR = REPO_ROOT / "blue-team" / "detection" / "suricata"
SURICATA_YAML = SURICATA_DIR / "suricata.yaml"
LOCAL_RULES = SURICATA_DIR / "local.rules"

HOME_A = "172.20.0.10"  # in-lab host (matches suricata.yaml's HOME_NET 172.20.0.0/24)
HOME_B = "172.20.0.30"  # in-lab host
OUTSIDE_A = "198.51.100.50"  # RFC 5737 TEST-NET-2: outside HOME_NET, not a real address
OUTSIDE_B = "203.0.113.10"  # RFC 5737 TEST-NET-3: outside HOME_NET, not a real address

_SCAPY_AVAILABLE = True
try:
    import scapy.all  # noqa: F401
except ImportError:
    _SCAPY_AVAILABLE = False

_SURICATA_BIN = shutil.which("suricata")

_SKIP_REASON = (
    "requires the `suricata` binary and the `scapy` package (install both to run this suite)"
)


def _build_cases() -> dict:
    """Deferred: only called once scapy's availability has been confirmed,
    since the helpers import scapy internally."""
    from suricata_pcap_helpers import (
        dns_query,
        smtp_session,
        syn_packets,
        tcp_conversation,
    )

    cases = {}

    # --- RECONNAISSANCE ---
    cases["port_scan_burst"] = {
        "build": lambda: syn_packets(OUTSIDE_A, HOME_B, 1000, 25),
        "expect_fire": {1000001, 1000002},
    }
    cases["dns_version_scan_chaos"] = {
        # G5.4 (#193): sid:1000003 rewritten onto dns.query -- a real
        # version-scan probe queries CHAOS-class TXT version.bind, not a
        # coincidentally-zero transaction ID (the old rule's actual, dead
        # match condition).
        "build": lambda: dns_query(
            OUTSIDE_A, 53000, HOME_B, 53, "version.bind", qtype="TXT", qclass="CH"
        ),
        "expect_fire": {1000003},
    }

    # --- INITIAL ACCESS ---
    _phishing_lines = [
        ("s", b"220 mail.lab ESMTP\r\n"),
        ("c", b"EHLO attacker.example\r\n"),
        ("s", b"250 mail.lab\r\n"),
        ("c", b"MAIL FROM:<attacker@evil.example>\r\n"),
        ("s", b"250 OK\r\n"),
        ("c", b"RCPT TO:<victim@lab.local>\r\n"),
        ("s", b"250 OK\r\n"),
        ("c", b"DATA\r\n"),
        ("s", b"354 Start mail input\r\n"),
        (
            "c",
            b"From: attacker@evil.example\r\nTo: victim@lab.local\r\nSubject: Invoice\r\n"
            b"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=xyz\r\n\r\n"
            b"--xyz\r\nContent-Type: application/octet-stream\r\n"
            b'Content-Disposition: attachment; filename="invoice.exe"\r\n\r\n'
            b"ZmFrZSBiaW5hcnk=\r\n--xyz--\r\n.\r\n",
        ),
        ("s", b"250 OK queued\r\n"),
        ("c", b"QUIT\r\n"),
        ("s", b"221 Bye\r\n"),
    ]
    cases["phishing_attachment"] = {
        "build": lambda: smtp_session(OUTSIDE_A, 51001, HOME_B, 25, _phishing_lines),
        "expect_fire": {1000010},
    }
    cases["sqli_or_1_equals_1"] = {
        "build": lambda: tcp_conversation(
            HOME_A,
            51002,
            HOME_B,
            80,
            b"GET /login?user=admin'%20OR%201=1-- HTTP/1.1\r\nHost: victim-web\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        ),
        "expect_fire": {1000020},
    }
    cases["xss_script_tag"] = {
        "build": lambda: tcp_conversation(
            HOME_A,
            51003,
            HOME_B,
            80,
            b"GET /search?q=<script>alert(1)</script> HTTP/1.1\r\nHost: victim-web\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        ),
        "expect_fire": {1000021},
    }
    cases["path_traversal"] = {
        "build": lambda: tcp_conversation(
            HOME_A,
            51004,
            HOME_B,
            80,
            b"GET /files/../../etc/passwd HTTP/1.1\r\nHost: victim-web\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        ),
        # G5.4 (#193): sid:1000022 now matches on http_raw_uri (the un-decoded
        # wire bytes) instead of the old http_uri, which is libhtp's
        # NORMALIZED uri buffer and resolved "../" away before the content
        # match ever ran.
        "expect_fire": {1000022},
    }
    cases["sqli_union_select"] = {
        "build": lambda: tcp_conversation(
            HOME_A,
            51005,
            HOME_B,
            80,
            b"GET /product?id=1%20UNION%20SELECT%20username,password%20FROM%20users HTTP/1.1\r\n"
            b"Host: victim-web\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        ),
        "expect_fire": {1000023},
    }
    cases["phishing_attachment_pdf"] = {
        # G5.3 (#192): sid:1000010's extension list gained pdf/doc/docm/zip/iso.
        "build": lambda: smtp_session(
            OUTSIDE_A,
            51023,
            HOME_B,
            25,
            [
                (line[0], line[1].replace(b'filename="invoice.exe"', b'filename="invoice.pdf"'))
                for line in _phishing_lines
            ],
        ),
        "expect_fire": {1000010},
    }
    cases["sqli_or_in_request_body"] = {
        # G5.3 (#192): sid:1000020 only ever looks at http_uri; the same
        # payload sent as a POST body needs its own rule (sid:1000024).
        "build": lambda: tcp_conversation(
            HOME_A,
            51020,
            HOME_B,
            80,
            b"POST /login HTTP/1.1\r\nHost: victim-web\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 27\r\n\r\n"
            b"user=admin' OR 1=1--&pass=x",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        ),
        "expect_fire": {1000024},
    }
    cases["xss_in_request_body"] = {
        "build": lambda: tcp_conversation(
            HOME_A,
            51021,
            HOME_B,
            80,
            b"POST /comment HTTP/1.1\r\nHost: victim-web\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 30\r\n\r\n"
            b"text=<script>alert(1)</script>",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        ),
        "expect_fire": {1000025},
    }
    cases["sqli_union_in_request_body"] = {
        "build": lambda: tcp_conversation(
            HOME_A,
            51022,
            HOME_B,
            80,
            b"POST /search HTTP/1.1\r\nHost: victim-web\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 46\r\n\r\n"
            b"q=1 UNION SELECT username,password FROM users",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        ),
        "expect_fire": {1000026},
    }
    cases["absolute_path_file_read_literal"] = {
        # G5.3 (#192): matches red-team/campaigns/initial_access/exploit_web.py's
        # actual path-traversal payload: GET /file?name=../../../etc/passwd
        "build": lambda: tcp_conversation(
            HOME_A,
            51024,
            HOME_B,
            80,
            b"GET /file?name=../../../etc/passwd HTTP/1.1\r\nHost: victim-web\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        ),
        "expect_fire": {1000027},
    }
    cases["absolute_path_file_read_url_encoded"] = {
        # Same campaign's second payload variant: ..%2F..%2F..%2Fetc%2Fpasswd.
        # This is why sid:1000027 exists as its own rule rather than relying
        # on sid:1000022 alone: it matches the endpoint itself, independent
        # of how the traversal segment is encoded.
        "build": lambda: tcp_conversation(
            HOME_A,
            51025,
            HOME_B,
            80,
            b"GET /file?name=..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1\r\nHost: victim-web\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        ),
        "expect_fire": {1000027},
    }
    cases["benign_http_request"] = {
        # Negative control: a clean request must not false-positive any of
        # the web-attack content rules.
        "build": lambda: tcp_conversation(
            HOME_A,
            51099,
            HOME_B,
            80,
            b"GET /index.html HTTP/1.1\r\nHost: victim-web\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        ),
        "expect_fire": set(),
        "expect_absent": {1000020, 1000021, 1000022, 1000023, 1000024, 1000025, 1000026, 1000027},
    }

    # --- PRIVILEGE ESCALATION ---
    cases["sudo_l_enumeration"] = {
        "build": lambda: tcp_conversation(HOME_A, 51006, HOME_B, 4444, b"sudo -l\n"),
        "expect_fire": {1000030},
    }

    # --- LATERAL MOVEMENT ---
    cases["smb_pass_the_hash"] = {
        "build": lambda: tcp_conversation(
            OUTSIDE_A, 51007, HOME_B, 445, b"\xffSMBrandom_bytes_here"
        ),
        "expect_fire": {1000040},
    }
    cases["smb2_pass_the_hash"] = {
        # G5.4 (#193): sid:1000040 only ever matched the SMB1 magic (|FF|SMB);
        # real-world traffic today is SMB2/3 (|FE|SMB), which sid:1000043 adds.
        "build": lambda: tcp_conversation(
            OUTSIDE_A, 51026, HOME_B, 445, b"\xfeSMBrandom_bytes_here"
        ),
        "expect_fire": {1000043},
    }
    cases["ssh_bruteforce_burst"] = {
        "build": lambda: syn_packets(HOME_A, HOME_B, 22, 6, dport_fixed=22),
        "expect_fire": {1000041, 1000042},
    }
    cases["ssh_internal_single"] = {
        "build": lambda: syn_packets(HOME_A, HOME_B, 22, 1, dport_fixed=22),
        "expect_fire": {1000042},
    }

    # --- EXFILTRATION ---
    cases["dns_tunnel_long_subdomain"] = {
        "build": lambda: dns_query(OUTSIDE_A, 53001, HOME_B, 53, "a" * 35 + ".tunnel.evil.example"),
        # G5.4 (#193): sid:1000050 rewritten onto dns.query + pcre, dropping
        # the old raw-byte offset that was anchored at the DNS transaction ID
        # instead of the flags/QDCOUNT fields it was meant to check.
        "expect_fire": {1000050},
    }
    cases["dns_high_query_rate"] = {
        "build": lambda: [
            pkt
            for i in range(55)
            for pkt in dns_query(OUTSIDE_A, 53100 + i, HOME_B, 53, f"q{i}.example.com", txn_id=i)
        ],
        "expect_fire": {1000051},
    }
    cases["https_beacon_odd_user_agent"] = {
        "build": lambda: tcp_conversation(
            HOME_A,
            51009,
            OUTSIDE_B,
            443,
            b"GET / HTTP/1.1\r\nHost: evil.example\r\nUser-Agent: WeirdBeaconClient/1.0\r\n\r\n",
        ),
        "expect_fire": {1000052},
    }

    # --- PERSISTENCE ---
    cases["crontab_modification"] = {
        "build": lambda: tcp_conversation(HOME_A, 51010, HOME_B, 4444, b"crontab -e\n"),
        "expect_fire": {1000060},
    }

    # --- MALWARE / GENERAL (production-reference only; see local.rules'
    # own audit-4 G3d notes -- these still deserve harness coverage since
    # they are shipped rule content, just never traversed by this air-gapped
    # lab's own traffic) ---
    cases["reverse_shell_bin_bash"] = {
        "build": lambda: tcp_conversation(HOME_A, 51011, OUTSIDE_B, 9001, b"/bin/bash -i\n"),
        "expect_fire": {1000070},
    }
    cases["metasploit_default_port"] = {
        "build": lambda: syn_packets(HOME_A, OUTSIDE_B, 4444, 1, dport_fixed=4444),
        "expect_fire": {1000071},
    }

    # --- Phase B lab-simulation reference rules ---
    cases["mitm_lab_simulation_marker"] = {
        "build": lambda: tcp_conversation(
            HOME_A, 51013, HOME_B, 5514, b"LAB-SIMULATION: attacker is spoofing"
        ),
        "expect_fire": {1000080},
    }
    cases["http_login_burst"] = {
        "build": lambda: [
            pkt
            for i in range(6)
            for pkt in tcp_conversation(
                HOME_A,
                52000 + i,
                HOME_B,
                80,
                b"POST /login HTTP/1.1\r\nHost: victim-web\r\nContent-Length: 0\r\n\r\n",
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
            )
        ],
        "expect_fire": {1000090},
    }
    cases["eicar_marker_in_transit"] = {
        "build": lambda: tcp_conversation(
            HOME_A, 51014, HOME_B, 8080, b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        ),
        "expect_fire": {1000100},
    }
    cases["ransomware_note_marker"] = {
        "build": lambda: tcp_conversation(
            HOME_A, 51015, HOME_B, 445, b"LAB SIMULATION -- NO ACTUAL ENCRYPTION"
        ),
        "expect_fire": {1000110},
    }

    # --- G3.5 containment tripwire ---
    cases["containment_tripwire"] = {
        "build": lambda: syn_packets(HOME_A, OUTSIDE_B, 443, 1, dport_fixed=443),
        "expect_fire": {1000200},
    }

    return cases


class SuricataPcapHarness:
    """Writes a pcap, replays it through the real `suricata` binary against
    the lab's own suricata.yaml + local.rules, and returns the set of sids
    that fired (from eve.json's alert events)."""

    def __init__(self, tmpdir: Path):
        self.tmpdir = tmpdir

    def fired_sids(self, packets: list) -> set[int]:
        from scapy.all import wrpcap

        pcap_path = self.tmpdir / "capture.pcap"
        log_dir = self.tmpdir / "log"
        log_dir.mkdir(exist_ok=True)
        wrpcap(str(pcap_path), packets)

        proc = subprocess.run(
            [
                "suricata",
                "-c",
                str(SURICATA_YAML),
                "-S",
                str(LOCAL_RULES),
                "-r",
                str(pcap_path),
                "-l",
                str(log_dir),
                "-k",
                "none",  # synthetic pcaps: don't drop on checksum mismatches
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"suricata exited {proc.returncode} replaying {pcap_path}:\n{proc.stderr}"
            )
        eve_path = log_dir / "eve.json"
        sids: set[int] = set()
        if not eve_path.exists():
            return sids
        for line in eve_path.read_text().splitlines():
            if not line.strip():
                continue
            doc = json.loads(line)
            if doc.get("event_type") == "alert":
                sids.add(doc["alert"]["signature_id"])
        return sids


@unittest.skipUnless(_SCAPY_AVAILABLE and _SURICATA_BIN, _SKIP_REASON)
class TestSuricataPcapReplay(unittest.TestCase):
    def test_every_rule_case_matches_expected_fire_behavior(self) -> None:
        cases = _build_cases()
        with tempfile.TemporaryDirectory() as tmp:
            for name, case in cases.items():
                with self.subTest(case=name):
                    harness = SuricataPcapHarness(Path(tmp) / name)
                    (Path(tmp) / name).mkdir()
                    packets = case["build"]()
                    fired = harness.fired_sids(packets)

                    expect_fire = case["expect_fire"]
                    missing = expect_fire - fired
                    note = case.get("note", "")
                    self.assertFalse(
                        missing,
                        f"{name}: expected sid(s) {sorted(missing)} to fire but they did not "
                        f"(fired: {sorted(fired)}). {note}",
                    )

                    expect_absent = case.get("expect_absent", set())
                    unexpected = expect_absent & fired
                    self.assertFalse(
                        unexpected,
                        f"{name}: sid(s) {sorted(unexpected)} fired but were expected absent "
                        f"(fired: {sorted(fired)})",
                    )

    def test_case_manifest_covers_every_sid_in_local_rules(self) -> None:
        # Guard against a new rule shipping with no corresponding pcap case
        # (or a case referencing a sid that no longer exists) -- the whole
        # point of this harness is that every sid has replay coverage.
        import re

        rule_sids = {int(m) for m in re.findall(r"sid:\s*(\d+)\s*;", LOCAL_RULES.read_text())}
        cases = _build_cases()
        covered_sids: set[int] = set()
        for case in cases.values():
            covered_sids |= case["expect_fire"]
            covered_sids |= case.get("expect_absent", set())
        # The two known-broken sids are asserted absent above with expect_fire
        # left empty; still credit them as "covered" via their note field.
        for case in cases.values():
            if case.get("note"):
                for sid in re.findall(r"sid:(\d+)", case["note"]):
                    covered_sids.add(int(sid))

        self.assertEqual(
            rule_sids,
            covered_sids,
            f"local.rules sids without pcap coverage: {sorted(rule_sids - covered_sids)}; "
            f"pcap cases referencing sids no longer in local.rules: {sorted(covered_sids - rule_sids)}",
        )


if __name__ == "__main__":
    unittest.main()
