"""
utils/mitre_tagger.py — MITRE ATT&CK Event Tagger

Tags campaign events with ATT&CK metadata and emits enriched events
to the ELK SIEM via HTTP for real-time detection and correlation.
"""

import json
import os
import requests
from datetime import datetime, timezone


# MITRE ATT&CK technique metadata index
TECHNIQUE_METADATA = {
    "T1595": {
        "name": "Active Scanning",
        "tactic": "Reconnaissance",
        "url": "https://attack.mitre.org/techniques/T1595/",
        "severity": "low",
    },
    "T1589": {
        "name": "Gather Victim Identity Information",
        "tactic": "Reconnaissance",
        "url": "https://attack.mitre.org/techniques/T1589/",
        "severity": "low",
    },
    "T1566.001": {
        "name": "Spearphishing Attachment",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1566/001/",
        "severity": "high",
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1190/",
        "severity": "critical",
    },
    "T1548.001": {
        "name": "Setuid and Setgid",
        "tactic": "Privilege Escalation",
        "url": "https://attack.mitre.org/techniques/T1548/001/",
        "severity": "high",
    },
    "T1548.003": {
        "name": "Sudo and Sudo Caching",
        "tactic": "Privilege Escalation",
        "url": "https://attack.mitre.org/techniques/T1548/003/",
        "severity": "high",
    },
    "T1550.002": {
        "name": "Pass the Hash",
        "tactic": "Lateral Movement",
        "url": "https://attack.mitre.org/techniques/T1550/002/",
        "severity": "critical",
    },
    "T1563.001": {
        "name": "SSH Hijacking",
        "tactic": "Lateral Movement",
        "url": "https://attack.mitre.org/techniques/T1563/001/",
        "severity": "high",
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "url": "https://attack.mitre.org/techniques/T1041/",
        "severity": "high",
    },
    "T1048.003": {
        "name": "Exfiltration Over Alternative Protocol: DNS",
        "tactic": "Exfiltration",
        "url": "https://attack.mitre.org/techniques/T1048/003/",
        "severity": "high",
    },
    "T1053.003": {
        "name": "Scheduled Task/Job: Cron",
        "tactic": "Persistence",
        "url": "https://attack.mitre.org/techniques/T1053/003/",
        "severity": "medium",
    },
    "T1098.004": {
        "name": "Account Manipulation: SSH Authorized Keys",
        "tactic": "Persistence",
        "url": "https://attack.mitre.org/techniques/T1098/004/",
        "severity": "medium",
    },
}


class MitreTagger:
    """
    Tags campaign events with ATT&CK metadata and ships them to the SIEM.
    """

    SIEM_HOST = os.environ.get("SIEM_HOST", "172.20.0.50")
    SIEM_PORT = int(os.environ.get("SIEM_PORT", "9200"))

    def get_metadata(self, technique_id: str) -> dict:
        """Return ATT&CK metadata for a given technique ID."""
        return TECHNIQUE_METADATA.get(technique_id, {
            "name": "Unknown Technique",
            "tactic": "Unknown",
            "url": f"https://attack.mitre.org/techniques/{technique_id}/",
            "severity": "unknown",
        })

    def tag_event(self, technique_id: str, event: dict) -> dict:
        """Enrich an event dict with ATT&CK metadata."""
        meta = self.get_metadata(technique_id)
        return {
            **event,
            "threat": {
                "framework": "MITRE ATT&CK",
                "technique": {
                    "id": technique_id,
                    "name": meta["name"],
                    "url": meta["url"],
                },
                "tactic": {
                    "name": meta["tactic"],
                },
                "severity": meta["severity"],
            },
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "event.kind": "alert",
            "event.category": "intrusion_detection",
            "source.ip": os.environ.get("ATTACKER_IP", "172.20.0.10"),
        }

    def tag_and_emit(self, technique_id: str, event: dict):
        """Tag an event and emit it to Elasticsearch."""
        enriched = self.tag_event(technique_id, event)
        index = f"red-team-events-{datetime.now().strftime('%Y.%m.%d')}"
        url = f"http://{self.SIEM_HOST}:{self.SIEM_PORT}/{index}/_doc"
        try:
            resp = requests.post(url, json=enriched, timeout=3)
            resp.raise_for_status()
        except requests.RequestException:
            # Non-fatal — SIEM may not be available during standalone testing
            pass
        return enriched
