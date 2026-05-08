"""
Base Campaign — Abstract base class for all ATT&CK campaigns.

All campaign modules must inherit from BaseCampaign and implement the `run()` method.
"""

import abc
import os
import time
import json
from datetime import datetime, timezone
from typing import Optional


class BaseCampaign(abc.ABC):
    """
    Abstract base class for Adversary-in-a-Box attack campaigns.

    Every campaign must:
    - Define a TECHNIQUE_ID (MITRE ATT&CK)
    - Define a TACTIC (e.g., "Initial Access")
    - Implement the run() method
    - Call self.log_step() for each significant action
    """

    TECHNIQUE_ID: str = "T0000"
    TECHNIQUE_NAME: str = "Base Technique"
    TACTIC: str = "Unknown"

    def __init__(self, target: str, logger=None, tagger=None):
        self.target = target
        self.logger = logger
        self.tagger = tagger
        self.start_time = datetime.now(timezone.utc)
        self.steps: list = []
        self.artifacts: list = []
        self.success = False

    @abc.abstractmethod
    def run(self) -> dict:
        """
        Execute the campaign.

        Returns:
            dict with keys:
                - success (bool)
                - message (str)
                - steps (list of step dicts)
                - artifacts (list of file paths)
                - technique_id (str)
        """
        raise NotImplementedError

    def log_step(self, step_name: str, detail: str, outcome: str = "success"):
        """Record a campaign step for reporting."""
        step = {
            "step": step_name,
            "detail": detail,
            "outcome": outcome,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.steps.append(step)
        if self.logger:
            self.logger.log_step(self.TECHNIQUE_ID, step_name, detail, outcome)
        return step

    def save_artifact(self, filename: str, content: str) -> str:
        """Save an artifact to the evidence directory."""
        evidence_dir = os.environ.get("EVIDENCE_DIR", "/evidence")
        os.makedirs(evidence_dir, exist_ok=True)
        path = os.path.join(evidence_dir, filename)
        with open(path, "w") as f:
            f.write(content)
        self.artifacts.append(path)
        return path

    def build_result(self, success: bool, message: str) -> dict:
        """Build the standardized result dict returned by run()."""
        self.success = success
        return {
            "success": success,
            "message": message,
            "technique_id": self.TECHNIQUE_ID,
            "technique_name": self.TECHNIQUE_NAME,
            "tactic": self.TACTIC,
            "target": self.target,
            "start_time": self.start_time.isoformat(),
            "end_time": datetime.now(timezone.utc).isoformat(),
            "steps": self.steps,
            "artifacts": self.artifacts,
        }

    def simulate_delay(self, seconds: float = 1.0):
        """Add realistic timing between attack steps."""
        time.sleep(seconds)
