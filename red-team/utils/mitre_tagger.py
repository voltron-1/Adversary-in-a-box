"""
utils/mitre_tagger.py — MITRE ATT&CK Event Tagger

Tags campaign events with ATT&CK metadata and emits enriched events
to the ELK SIEM via HTTP for real-time detection and correlation.
"""

import os
from datetime import UTC, datetime

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
    "T1204": {
        "name": "User Execution",
        "tactic": "Execution",
        "url": "https://attack.mitre.org/techniques/T1204/",
        "severity": "high",
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/",
        "severity": "high",
    },
    "T1557": {
        "name": "Adversary-in-the-Middle",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1557/",
        "severity": "high",
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
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "url": "https://attack.mitre.org/techniques/T1486/",
        "severity": "critical",
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
        return TECHNIQUE_METADATA.get(
            technique_id,
            {
                "name": "Unknown Technique",
                "tactic": "Unknown",
                "url": f"https://attack.mitre.org/techniques/{technique_id}/",
                "severity": "unknown",
            },
        )

    def tag_event(self, technique_id: str, event: dict, campaign_id: str | None = None) -> dict:
        """Enrich an event dict with ATT&CK metadata.

        audit-4 G1a: every emitted doc now carries ``campaign_id`` (the
        per-run correlation key the scoreboard joins on) and an
        ``event_type`` discriminator. Before this fix the tagger emitted
        neither, so ``forensics/scoreboard/scorer.py`` -- which keys its
        whole MTTD/MTTA join on those two fields -- always saw zero rows
        and every run scored 0-0.
        """
        meta = self.get_metadata(technique_id)
        return {
            **event,
            "campaign_id": campaign_id,
            "event_type": "attack_technique",
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
            "@timestamp": datetime.now(UTC).isoformat(),
            "event.kind": "alert",
            "event.category": "intrusion_detection",
            "source.ip": os.environ.get("ATTACKER_IP", "172.20.0.10"),
        }

    def _index_name(self) -> str:
        # UTC date so the index bucket matches the UTC `@timestamp` on the
        # docs (audit-4 L7: previously built from local-time now()).
        return f"red-team-events-{datetime.now(UTC).strftime('%Y.%m.%d')}"

    def _post(self, doc: dict) -> dict:
        """POST a doc to the red-team-events index. Non-fatal on failure."""
        url = f"http://{self.SIEM_HOST}:{self.SIEM_PORT}/{self._index_name()}/_doc"
        try:
            import requests  # lazy: lets this module import without the dep

            resp = requests.post(url, json=doc, timeout=3)
            resp.raise_for_status()
        except Exception:
            # Non-fatal — SIEM may not be available during standalone testing
            pass
        return doc

    def tag_and_emit(self, technique_id: str, event: dict, campaign_id: str | None = None):
        """Tag an event and emit it to Elasticsearch."""
        return self._post(self.tag_event(technique_id, event, campaign_id))

    def emit_lifecycle(self, event_type: str, campaign_id: str, extra: dict | None = None) -> dict:
        """Emit a campaign lifecycle event (campaign_start / campaign_end).

        audit-4 G1a: these are the docs the scoreboard reads as the
        attack-start timestamp (MTTD anchor) and the campaigns-completed
        count. They were previously written only to a local log file
        (utils/logger.py) that no Logstash pipeline ingests, so they never
        reached Elasticsearch.
        """
        doc = {
            "campaign_id": campaign_id,
            "event_type": event_type,
            "@timestamp": datetime.now(UTC).isoformat(),
            "source.ip": os.environ.get("ATTACKER_IP", "172.20.0.10"),
            **(extra or {}),
        }
        return self._post(doc)
