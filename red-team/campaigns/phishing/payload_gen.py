"""
campaigns/phishing/payload_gen.py — Benign Payload Generator

Generates test payloads for phishing simulations.
All payloads are completely benign — they contain no malicious code
and are suitable for educational use in isolated lab environments.

OQ-1 (ADR 0001) contract:
    * Every generator method accepts `dry_run: bool`. When True, it returns
      the plan it *would* execute without touching disk.
    * The CLI entry point `python -m campaigns.phishing.payload_gen --dry-run`
      prints a step-by-step plan for every campaign known to the lab.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime

# Industry-standard AV test string. Triggers signatures without executing.
EICAR_STRING = (
    r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)

# Static, lab-internal markers used by non-phishing campaigns. Each one is the
# *behavioral signature* the blue team learns to detect.
LAB_TEST_KEY      = "adversary-in-a-box-test-key"
LAB_DNS_LABEL     = "ADVERSARY-IN-A-BOX-TEST"
LAB_HTTPS_BODY    = '{"test": "adversary-in-a-box"}'
LAB_CRON_COMMAND  = "echo adversary-in-a-box"


@dataclass
class PayloadPlan:
    """A plan for a payload: what would be written, where, and why."""
    technique: str
    description: str
    target_path: str | None
    content_preview: str

    def render(self) -> str:
        path = self.target_path or "<no on-disk artifact>"
        return (
            f"  [{self.technique}] {self.description}\n"
            f"    target: {path}\n"
            f"    preview: {self.content_preview[:80]}{'...' if len(self.content_preview) > 80 else ''}"
        )


class PayloadGenerator:
    """Generates benign test payloads for phishing simulations."""

    OUTPUT_DIR = os.environ.get("EVIDENCE_DIR", "/tmp/lab-payloads")

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        if not dry_run:
            os.makedirs(self.OUTPUT_DIR, exist_ok=True)

    def _write(self, filename: str, content: str) -> tuple[str, str]:
        filepath = os.path.join(self.OUTPUT_DIR, filename)
        if self.dry_run:
            return filepath, hashlib.sha256(content.encode()).hexdigest()
        with open(filepath, "w") as f:
            f.write(content)
        return filepath, hashlib.sha256(content.encode()).hexdigest()

    # -- T1566.001 --------------------------------------------------------------
    def generate_doc_payload(self) -> tuple[str, str]:
        """
        Generate a benign EICAR-bearing 'document' attachment.

        The file is a plain-text container with the EICAR test string embedded
        so AV products fire signatures; nothing executes.
        """
        content = f"""BENEFITS ENROLLMENT FORM — LAB SIMULATION
========================================
This is a simulated phishing payload for the Adversary-in-a-Box lab.
Generated: {datetime.now(UTC).isoformat()}
Technique: T1566.001 — Spearphishing Attachment

[BENIGN AV MARKER]
{EICAR_STRING}

All payloads in this lab are benign and for educational use only.
"""
        filename = f"payload_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        return self._write(filename, content)

    def generate_script_payload(self) -> tuple[str, str]:
        """Benign shell script masquerading as a delivered loader."""
        content = """#!/bin/bash
# LAB SIMULATION PAYLOAD — T1566.001
# This is a benign educational payload for Adversary-in-a-Box
echo "[LAB] Simulated payload execution at $(date)"
echo "[LAB] Attacker would establish persistence here"
echo "[LAB] No actual malicious actions performed"
"""
        filename = f"payload_{datetime.now().strftime('%Y%m%d_%H%M%S')}.sh"
        return self._write(filename, content)

    # -- Plans (used by --dry-run for non-phishing campaigns) --------------------
    @staticmethod
    def all_plans() -> list[PayloadPlan]:
        """Return the plan-of-record for every campaign known to the lab (per ADR OQ-1)."""
        return [
            PayloadPlan("T1566.001",  "Phishing: EICAR string in benefits-form attachment",
                        os.path.join(PayloadGenerator.OUTPUT_DIR, "payload_<ts>.txt"),
                        EICAR_STRING),
            PayloadPlan("T1105",      "Malware drop: EICAR to temp path, deleted post-test",
                        tempfile.gettempdir() + "/eicar.com", EICAR_STRING),
            PayloadPlan("T1048.003",  "DNS tunnel: base32 marker in DNS query labels",
                        None, LAB_DNS_LABEL),
            PayloadPlan("T1041",      "HTTPS exfil: static JSON POST to scoreboard",
                        "http://scoreboard:5002/_lab_exfil_sink", LAB_HTTPS_BODY),
            PayloadPlan("T1563.001",  "SSH hijack: inject test key into authorized_keys",
                        "~/.ssh/authorized_keys", LAB_TEST_KEY),
            PayloadPlan("T1550.002",  "Pass the Hash: simulate NTLM handshake to honeypot socket",
                        None, "<NTLM handshake packet>"),
            PayloadPlan("T1548.003",  "Sudo abuse: run `sudo id` on victim, log escalation",
                        None, "sudo id"),
            PayloadPlan("T1053.003",  "Cron backdoor: write echo entry, removed by playbook",
                        "/etc/cron.d/lab-test", "* * * * * root " + LAB_CRON_COMMAND),
        ]


def _cli() -> int:
    parser = argparse.ArgumentParser(description="Adversary-in-a-Box payload generator")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print step-by-step plan for every campaign without executing.")
    parser.add_argument("--campaign", default=None,
                        help="Run a single payload (doc|script). Ignored with --dry-run.")
    args = parser.parse_args()

    if args.dry_run:
        print("Adversary-in-a-Box — payload plan (no actions taken)\n")
        for plan in PayloadGenerator.all_plans():
            print(plan.render())
        print("\n  All payloads are behavioral signatures only.")
        print("  lab-net is declared internal: true; no external egress is possible.")
        return 0

    gen = PayloadGenerator(dry_run=False)
    if args.campaign in (None, "doc"):
        path, sha = gen.generate_doc_payload()
        print(f"doc payload: {path}\n  sha256: {sha}")
    if args.campaign in (None, "script"):
        path, sha = gen.generate_script_payload()
        print(f"script payload: {path}\n  sha256: {sha}")
    return 0


if __name__ == "__main__":
    sys.exit(_cli())
