"""
campaigns/credential_access/mitm.py -- T1557 Adversary-in-the-Middle

MITRE ATT&CK: T1557 | Tactic: Credential Access

Phase B1a (audit-2 follow-up). Containers on the lab-net bridge share an L2
network; real ARP spoofing is suppressed by the Docker bridge driver in most
configurations. This campaign produces a *behavioral signature* of an
on-path attack rather than mounting one: it advertises a duplicate
MAC/hostname binding via gratuitous-ARP-style log entries that Zeek's
`detect-duplicate-arp` heuristic + the paired Sigma rule will fire on. No
real packets are crafted; the artifact path lets the SIEM exercise its
detection logic safely.
"""

import json
import os
import socket
from datetime import UTC, datetime

from campaigns.base_campaign import BaseCampaign


class MitmCampaign(BaseCampaign):
    TECHNIQUE_ID = "T1557"
    TECHNIQUE_NAME = "Adversary-in-the-Middle"
    TACTIC = "Credential Access"

    # Decoy victim binding the campaign advertises a "duplicate" for.
    SPOOFED_VICTIM = os.environ.get("MITM_VICTIM", "victim-web")
    # Lab attacker MAC marker — clearly synthetic, never a real OUI.
    LAB_FAKE_MAC = "02:AD:BE:EF:00:01"

    def run(self) -> dict:
        self.log_step("init", f"Simulating on-path attack: spoofing {self.SPOOFED_VICTIM}")
        self.simulate_delay(0.5)

        # Step 1: capture the legitimate binding from DNS so the spoofed
        # artifact has a real IP to claim ownership of.
        real_ip = self._resolve_victim()
        self.log_step("dns_lookup", f"{self.SPOOFED_VICTIM} -> {real_ip}")
        self.simulate_delay(0.5)

        # Step 2: write the spoof advisory artifact. This is what the Sigma
        # rule + Zeek heuristic look for.
        spoof_event = {
            "event_type": "arp_spoof_simulation",
            "technique": self.TECHNIQUE_ID,
            "victim_host": self.SPOOFED_VICTIM,
            "victim_ip": real_ip,
            "attacker_mac": self.LAB_FAKE_MAC,
            "message": (
                f"LAB-SIMULATION: attacker {self.LAB_FAKE_MAC} claims "
                f"ownership of {real_ip} ({self.SPOOFED_VICTIM}). "
                "Detection: duplicate MAC/IP binding."
            ),
            "timestamp": datetime.now(UTC).isoformat(),
        }
        self.log_step("spoof_advert", f"Emitted spoof advisory for {real_ip}")

        # Step 3: write to the lab-shared signal channel (/tmp/lab_mitm.log)
        # — both an artifact for the IR investigators and a path the Sigma
        # rule's file-write keyword matches.
        signal_path = "/tmp/lab_mitm.log"
        try:
            with open(signal_path, "a") as f:
                f.write(json.dumps(spoof_event) + "\n")
            self.register_cleanup_path(signal_path)
            self.log_step("signal_emit", f"Wrote spoof advisory to {signal_path}")
        except OSError as exc:
            self.log_step("signal_emit", f"Could not write {signal_path}: {exc}", "warning")

        self.save_artifact("mitm_results.json", json.dumps(spoof_event, indent=2))
        return self.build_result(True, "MITM behavioral signature emitted (simulation)")

    def _resolve_victim(self) -> str:
        try:
            return socket.gethostbyname(self.SPOOFED_VICTIM)
        except socket.gaierror:
            # Outside the lab network — return a placeholder so the artifact
            # still makes sense in tests.
            return os.environ.get("LAB_NET_PREFIX", "172.20.0") + ".30"

    # Audit-2 Gap #10: declare WELL_KNOWN_ARTIFACTS so --cleanup-all can
    # roll back the spoof log even without a preceding run().
    WELL_KNOWN_ARTIFACTS = ("/tmp/lab_mitm.log",)
