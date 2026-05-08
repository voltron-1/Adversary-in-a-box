"""
campaigns/phishing/payload_gen.py — Benign Payload Generator

Generates test payloads for phishing simulations.
All payloads are completely benign — they contain no malicious code
and are suitable for educational use in isolated lab environments.
"""

import hashlib
import os
import tempfile
from datetime import datetime


class PayloadGenerator:
    """Generates benign test payloads for phishing simulations."""

    OUTPUT_DIR = os.environ.get("EVIDENCE_DIR", "/tmp/lab-payloads")

    def __init__(self):
        os.makedirs(self.OUTPUT_DIR, exist_ok=True)

    def generate_doc_payload(self) -> tuple[str, str]:
        """
        Generate a benign text file masquerading as a document.

        Returns:
            Tuple of (file_path, sha256_hash)
        """
        # Benign content — this is NOT a real exploit
        content = """BENEFITS ENROLLMENT FORM — LAB SIMULATION
========================================
This is a simulated phishing payload for the Adversary-in-a-Box lab.
Generated: {timestamp}
Technique: T1566.001 — Spearphishing Attachment

[LAB NOTE] In a real attack, this file might contain:
  - A macro-enabled Office document
  - A PDF with embedded JavaScript
  - An executable disguised with a document icon
  
All payloads in this lab are benign and for educational use only.
""".format(timestamp=datetime.utcnow().isoformat())

        filename = f"payload_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        filepath = os.path.join(self.OUTPUT_DIR, filename)

        with open(filepath, "w") as f:
            f.write(content)

        sha256 = hashlib.sha256(content.encode()).hexdigest()
        return filepath, sha256

    def generate_script_payload(self) -> tuple[str, str]:
        """
        Generate a benign shell script payload.

        Returns:
            Tuple of (file_path, sha256_hash)
        """
        content = """#!/bin/bash
# LAB SIMULATION PAYLOAD — T1566.001
# This is a benign educational payload for Adversary-in-a-Box
echo "[LAB] Simulated payload execution at $(date)"
echo "[LAB] Attacker would establish persistence here"
echo "[LAB] No actual malicious actions performed"
"""
        filename = f"payload_{datetime.now().strftime('%Y%m%d_%H%M%S')}.sh"
        filepath = os.path.join(self.OUTPUT_DIR, filename)
        with open(filepath, "w") as f:
            f.write(content)

        sha256 = hashlib.sha256(content.encode()).hexdigest()
        return filepath, sha256
