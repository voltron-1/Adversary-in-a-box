"""
Base Campaign — Abstract base class for all ATT&CK campaigns.

All campaign modules must inherit from BaseCampaign and implement the `run()` method.
"""

import abc
import os
import shutil
import time
from datetime import UTC, datetime


class BaseCampaign(abc.ABC):
    """
    Abstract base class for Adversary-in-a-Box attack campaigns.

    Every campaign must:
    - Define a TECHNIQUE_ID (MITRE ATT&CK)
    - Define a TACTIC (e.g., "Initial Access")
    - Implement the run() method
    - Call self.log_step() for each significant action

    Campaigns that write to disk (cron entries, SSH keys, planted files) MUST
    register paths via self.register_cleanup_path() OR override cleanup() so
    `runner.py --cleanup-all` and the IR playbook engine can roll back any
    persistent state. OQ-1 (ADR 0001) requires every disk-touching technique
    to be self-cleaning.
    """

    TECHNIQUE_ID: str = "T0000"
    TECHNIQUE_NAME: str = "Base Technique"
    TACTIC: str = "Unknown"

    def __init__(self, target: str, logger=None, tagger=None):
        self.target = target
        self.logger = logger
        self.tagger = tagger
        self.start_time = datetime.now(UTC)
        self.steps: list = []
        self.artifacts: list = []
        self._cleanup_paths: list[str] = []
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
            "timestamp": datetime.now(UTC).isoformat(),
        }
        self.steps.append(step)
        if self.logger:
            self.logger.log_step(self.TECHNIQUE_ID, step_name, detail, outcome)
        return step

    def save_artifact(self, filename: str, content: str) -> str:
        """
        Save an artifact to the evidence directory.

        Audit-2 note: artifacts written here are CHAIN-OF-CUSTODY EVIDENCE,
        not attacker persistence — they go to /evidence/ which the scoreboard
        scans for manifest.sha256 bonuses and which students hash via
        forensics/chain_of_custody.py. cleanup() must NOT delete these. If a
        campaign also writes persistent attacker state (cron entries, planted
        keys, beacon scripts), call register_cleanup_path() explicitly for
        those paths only.
        """
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
            "end_time": datetime.now(UTC).isoformat(),
            "steps": self.steps,
            "artifacts": self.artifacts,
        }

    def simulate_delay(self, seconds: float = 1.0):
        """Add realistic timing between attack steps."""
        time.sleep(seconds)

    # ------------------------------------------------------------------ cleanup
    def register_cleanup_path(self, path: str) -> None:
        """Mark a file/dir as something `cleanup()` should remove."""
        if path and path not in self._cleanup_paths:
            self._cleanup_paths.append(path)

    def cleanup(self) -> dict:
        """
        Remove any persistent state this campaign created. Default behavior:
        delete every path registered via register_cleanup_path(). Subclasses
        that touch resources other than the filesystem (crontab entries,
        firewall rules, etc.) MUST override this method and either call
        super().cleanup() at the end or replicate the path-removal loop.

        Returns a dict suitable for logging:
            {"technique": <id>, "removed": [...], "missing": [...], "errors": [...]}
        """
        removed: list[str] = []
        missing: list[str] = []
        errors: list[dict] = []
        for path in self._cleanup_paths:
            try:
                if os.path.isdir(path) and not os.path.islink(path):
                    shutil.rmtree(path)
                    removed.append(path)
                elif os.path.exists(path) or os.path.islink(path):
                    os.remove(path)
                    removed.append(path)
                else:
                    missing.append(path)
            except OSError as exc:
                errors.append({"path": path, "error": str(exc)})
        return {
            "technique": self.TECHNIQUE_ID,
            "removed": removed,
            "missing": missing,
            "errors": errors,
        }
