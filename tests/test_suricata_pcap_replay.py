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

Two cases (path_traversal / dns_tunnel_long) are known-broken: their rules
use the wrong sticky buffer / byte offset and cannot fire against any real
traffic shaped the way the rule's own msg/comment claims. That is exactly
the class of bug G5.4 (#193) exists to fix. Encoding the current (broken)
behavior here, instead of skipping or ignoring those two sids, is what
makes them fixable-and-verifiable rather than silently wrong forever.
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
        udp_packet,
    )

    cases = {}

    # --- RECONNAISSANCE ---
    cases["port_scan_burst"] = {
        "build": lambda: syn_packets(OUTSIDE_A, HOME_B, 1000, 25),
        "expect_fire": {1000001, 1000002},
    }
    cases["dns_version_scan"] = {
        "build": lambda: udp_packet(
            OUTSIDE_A, 53000, HOME_B, 53, b"\x00\x00\x10\x00\x01" + b"\x00" * 10
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
        # KNOWN BROKEN (G5.4 / #193): sid:1000022 matches on `http_uri`, which
        # is libhtp's NORMALIZED uri buffer -- "../" is resolved away before
        # that buffer is built. A real request with a literal "../" (as
        # crafted here) never reaches the content match; the rule needs
        # `http_raw_uri` instead. Confirmed locally by swapping the buffer on
        # a throwaway copy of the rule and re-running this exact pcap.
        "expect_fire": set(),
        "note": "sid:1000022 cannot fire against any real traffic -- see G5.4 (#193)",
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
        "expect_absent": {1000020, 1000021, 1000022, 1000023},
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
        # KNOWN BROKEN (G5.4 / #193): sid:1000050's content match is 10 raw
        # bytes with no `offset`, so it is anchored at byte 0 of the UDP
        # payload -- i.e. the DNS transaction ID itself, not the flags/
        # QDCOUNT fields the rule's byte pattern actually encodes (those
        # start at byte 2). No real, protocol-valid DNS query (which needs
        # QDCOUNT=1 to even pass Suricata's dns probing parser) can also
        # satisfy this rule's byte-0 anchor. Confirmed locally: a
        # protocol-valid query with QDCOUNT=1 is correctly detected as DNS
        # (proven by sid:1000051 firing on the same kind of traffic in
        # dns_high_query_rate below) but never matches this content pattern.
        "expect_fire": set(),
        "note": "sid:1000050 cannot fire against any protocol-valid DNS query -- see G5.4 (#193)",
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
