"""
campaigns/lateral_movement/pass_the_hash.py — T1550.002 Pass the Hash
MITRE ATT&CK: T1550.002 | Tactic: Lateral Movement
"""

import os
import json
from datetime import datetime
from campaigns.base_campaign import BaseCampaign


class PassTheHashCampaign(BaseCampaign):
    TECHNIQUE_ID = "T1550.002"
    TECHNIQUE_NAME = "Pass the Hash"
    TACTIC = "Lateral Movement"

    TARGET_DB = os.environ.get("TARGET_DB_HOST", "172.20.0.31")
    SIMULATED_HASH = "aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99"

    def run(self) -> dict:
        self.log_step("init", f"Pass-the-Hash attack against {self.TARGET_DB}")
        self.simulate_delay(1)

        # Step 1: Simulate hash extraction from memory (Mimikatz-style)
        extracted_hash = self._extract_hash()
        self.log_step("hash_extraction", f"Extracted NTLM hash: {extracted_hash[:20]}...")
        self.simulate_delay(1)

        # Step 2: Simulate authentication with hash
        auth_result = self._authenticate_with_hash(extracted_hash)
        self.log_step("pth_auth", f"Authentication result: {auth_result['status']}", auth_result["status"])

        results = {
            "technique": self.TECHNIQUE_ID,
            "target": self.TARGET_DB,
            "hash_extracted": extracted_hash,
            "auth_result": auth_result,
            "timestamp": datetime.utcnow().isoformat(),
        }
        self.save_artifact("pth_results.json", json.dumps(results, indent=2))
        return self.build_result(True, f"Pass-the-Hash demonstrated against {self.TARGET_DB}")

    def _extract_hash(self) -> str:
        """Simulate NTLM hash extraction from memory."""
        # In a real attack this would use Mimikatz or secretsdump
        # Here we simulate with a known weak hash (password: 'password')
        return self.SIMULATED_HASH

    def _authenticate_with_hash(self, ntlm_hash: str) -> dict:
        """Simulate authentication using the extracted hash."""
        # Simulate the attack — actual PTH requires impacket in real environments
        return {
            "status": "simulated",
            "target": self.TARGET_DB,
            "method": "impacket smbclient.py",
            "command": f"python3 -m impacket.smbclient admin@{self.TARGET_DB} -hashes {ntlm_hash}",
            "note": "Simulated for lab safety. Real execution requires network access to SMB service.",
        }
