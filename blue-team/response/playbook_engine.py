"""
blue-team/response/playbook_engine.py -- IR Playbook Execution Engine

Loads and executes YAML-defined incident response playbooks.
"""

import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import yaml

PLAYBOOK_DIR = Path(__file__).parent / "playbooks"
ACTIONS_DIR = Path(__file__).parent / "actions"
EVIDENCE_DIR = Path(os.environ.get("EVIDENCE_DIR", "/evidence"))


class PlaybookEngine:
    """Loads and executes YAML incident response playbooks step by step."""

    def __init__(self, playbook_name: str):
        self.playbook_name = playbook_name
        self.playbook = self._load_playbook(playbook_name)
        self.execution_log: list[dict] = []
        self.start_time = datetime.now(UTC)

    def _load_playbook(self, name: str) -> dict:
        path = PLAYBOOK_DIR / f"{name}.yml"
        if not path.exists():
            raise FileNotFoundError(f"Playbook not found: {path}")
        with open(path) as f:
            data: dict = yaml.safe_load(f)
            return data

    def execute(self, context: dict | None = None) -> dict:
        """Execute all steps in the playbook."""
        context = context or {}
        results = []

        print(f"\n[IR] Executing playbook: {self.playbook['name']}")
        print(f"[IR] Incident type: {self.playbook.get('incident_type', 'Unknown')}")
        print(f"[IR] Steps: {len(self.playbook.get('steps', []))}\n")

        for step in self.playbook.get("steps", []):
            result = self._execute_step(step, context)
            results.append(result)
            if not result["success"] and step.get("required", False):
                print(f"[IR] CRITICAL step failed: {step['name']} -- halting playbook")
                break

        summary = {
            "playbook": self.playbook_name,
            "start_time": self.start_time.isoformat(),
            "end_time": datetime.now(UTC).isoformat(),
            "steps_total": len(self.playbook.get("steps", [])),
            "steps_completed": sum(1 for r in results if r["success"]),
            "results": results,
            "context": context,
        }

        # Save execution log to evidence
        EVIDENCE_DIR.mkdir(exist_ok=True)
        log_path = (
            EVIDENCE_DIR
            / f"playbook_{self.playbook_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        with open(log_path, "w") as f:
            json.dump(summary, f, indent=2)

        return summary

    def _execute_step(self, step: dict, context: dict) -> dict:
        step_name = step.get("name", "Unknown")
        action = step.get("action", "log")
        print(f"  -> {step_name}...")

        try:
            if action == "run_script":
                result = self._run_script(step, context)
            elif action == "log":
                result = {"output": step.get("message", "Logged"), "success": True}
            elif action == "collect_evidence":
                result = self._collect_evidence(step, context)
            elif action == "cleanup_persistence":
                result = self._cleanup_persistence(step, context)
            elif action == "notify":
                result = self._notify(step, context)
            else:
                result = {"output": f"Unknown action: {action}", "success": False}

            result["step"] = step_name
            result["timestamp"] = datetime.now(UTC).isoformat()
            print(f"    [ok] {result.get('output', 'Done')}")
            return result

        except Exception as exc:
            error = {
                "step": step_name,
                "success": False,
                "error": str(exc),
                "timestamp": datetime.now(UTC).isoformat(),
            }
            print(f"    [FAIL] Failed: {exc}")
            return error

    def _run_script(self, step: dict, context: dict) -> dict:
        script = ACTIONS_DIR / step["script"]
        args = step.get("args", [])
        # Substitute context variables
        args = [a.format(**context) for a in args]
        cmd = ["bash", str(script)] + args
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return {
            "success": proc.returncode == 0,
            "output": proc.stdout.strip() or proc.stderr.strip(),
            "returncode": proc.returncode,
        }

    def _collect_evidence(self, step: dict, context: dict) -> dict:
        collector = ACTIONS_DIR / "collect_evidence.py"
        proc = subprocess.run(
            ["python3", str(collector)], capture_output=True, text=True, timeout=30
        )
        return {"success": proc.returncode == 0, "output": proc.stdout.strip()}

    def _notify(self, step: dict, context: dict) -> dict:
        msg = step.get("message", "Alert").format(**context)
        print(f"    NOTIFY: {msg}")
        return {"success": True, "output": f"Notification sent: {msg}"}

    def _cleanup_persistence(self, step: dict, context: dict) -> dict:
        """
        Audit-2 Gap #4: invoke `runner.py --cleanup-all` on the red-team
        container to roll back persistent state (cron entries, planted SSH
        keys, beacon scripts). Requires that blue-team has /var/run/docker.sock
        mounted (the same OQ-3 capability isolate_host.sh needs).
        """
        service = step.get("service", "red-team")
        # Find the compose-managed container name for the target service so
        # this works regardless of the per-student COMPOSE_PROJECT_NAME.
        try:
            ps = subprocess.run(
                [
                    "docker",
                    "ps",
                    "--filter",
                    f"label=com.docker.compose.service={service}",
                    "--format",
                    "{{.Names}}",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            names = [n for n in ps.stdout.split("\n") if n.strip()]
            if not names:
                return {"success": False, "output": f"No running container for service '{service}'"}
            container = names[0]
            proc = subprocess.run(
                ["docker", "exec", container, "python", "runner.py", "--cleanup-all"],
                capture_output=True,
                text=True,
                timeout=60,
            )
            return {
                "success": proc.returncode == 0,
                "output": (proc.stdout or proc.stderr).strip()[:500],
                "returncode": proc.returncode,
            }
        except Exception as exc:
            return {"success": False, "output": f"cleanup_persistence failed: {exc}"}
