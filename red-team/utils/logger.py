"""
utils/logger.py — Structured Attack Event Logger

Writes structured JSON logs for every campaign step, readable by Logstash
for ingestion into the ELK SIEM stack.
"""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path


class AttackLogger:
    """
    Structured logger for red team campaign events.

    Log format is JSON-compatible for Logstash ingestion:
        {
            "timestamp": "...",
            "event_type": "attack_step",
            "technique_id": "T1566.001",
            "step": "send_email",
            "detail": "Sent phishing email to victim@lab.local",
            "outcome": "success",
            "source": "red-team"
        }
    """

    LOG_DIR = os.environ.get("LOG_DIR", "/app/logs")
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")

    def __init__(self):
        os.makedirs(self.LOG_DIR, exist_ok=True)
        log_file = Path(self.LOG_DIR) / f"campaign_{datetime.now().strftime('%Y%m%d')}.json"

        self._logger = logging.getLogger("red-team")
        self._logger.setLevel(getattr(logging, self.LOG_LEVEL, logging.INFO))

        # File handler — JSON lines format
        fh = logging.FileHandler(log_file)
        fh.setFormatter(logging.Formatter("%(message)s"))
        self._logger.addHandler(fh)

        # Console handler
        ch = logging.StreamHandler()
        ch.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        self._logger.addHandler(ch)

    def _emit(self, event: dict):
        """Emit a structured JSON log event."""
        event.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        event.setdefault("source", "red-team")
        self._logger.info(json.dumps(event))

    def log_step(self, technique_id: str, step: str, detail: str, outcome: str = "success"):
        """Log a campaign step."""
        self._emit({
            "event_type": "attack_step",
            "technique_id": technique_id,
            "step": step,
            "detail": detail,
            "outcome": outcome,
        })

    def log_campaign_start(self, campaign_name: str, target: str, techniques: list):
        """Log campaign initialization."""
        self._emit({
            "event_type": "campaign_start",
            "campaign": campaign_name,
            "target": target,
            "techniques": techniques,
        })

    def log_campaign_end(self, campaign_name: str, success: bool, duration_seconds: float):
        """Log campaign completion."""
        self._emit({
            "event_type": "campaign_end",
            "campaign": campaign_name,
            "success": success,
            "duration_seconds": duration_seconds,
        })

    def log_error(self, campaign_name: str, error: str):
        """Log a campaign error."""
        self._emit({
            "event_type": "campaign_error",
            "campaign": campaign_name,
            "error": error,
            "outcome": "failure",
        })

    def log_artifact(self, technique_id: str, artifact_path: str, artifact_type: str):
        """Log a forensic artifact created during the campaign."""
        self._emit({
            "event_type": "artifact_created",
            "technique_id": technique_id,
            "artifact_path": artifact_path,
            "artifact_type": artifact_type,
        })
