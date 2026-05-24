"""
tests/test_playbooks.py — Unit tests for IR playbook engine and playbooks
"""
import sys
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from pathlib import Path

# Add blue-team to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'blue-team'))

PLAYBOOKS_DIR = Path(__file__).parent.parent / "blue-team" / "response" / "playbooks"


class TestPlaybookEngine(unittest.TestCase):
    """Tests for the PlaybookEngine class."""

    def _make_engine(self, playbook_name):
        sys.path.insert(0, str(Path(__file__).parent.parent / "blue-team"))
        from response.playbook_engine import PlaybookEngine
        return PlaybookEngine(playbook_name)

    def test_phishing_playbook_loads(self):
        engine = self._make_engine("phishing_ir")
        self.assertEqual(engine.playbook["name"], "Phishing Incident Response")
        self.assertIn("steps", engine.playbook)
        self.assertGreater(len(engine.playbook["steps"]), 0)

    def test_ransomware_playbook_loads(self):
        engine = self._make_engine("ransomware_ir")
        self.assertEqual(engine.playbook["incident_type"], "ransomware")
        self.assertEqual(engine.playbook["severity"], "critical")

    def test_lateral_movement_playbook_loads(self):
        engine = self._make_engine("lateral_movement_ir")
        self.assertIn("steps", engine.playbook)

    def test_data_exfil_playbook_loads(self):
        engine = self._make_engine("data_exfil_ir")
        self.assertIn("steps", engine.playbook)

    def test_unknown_playbook_raises_file_not_found(self):
        from response.playbook_engine import PlaybookEngine
        with self.assertRaises(FileNotFoundError):
            PlaybookEngine("nonexistent_playbook")

    def test_playbook_execution_log_step(self):
        engine = self._make_engine("phishing_ir")
        step = {"name": "Test Step", "action": "log", "message": "Testing"}
        result = engine._execute_step(step, {})
        self.assertTrue(result["success"])
        self.assertIn("timestamp", result)

    def test_playbook_execute_returns_summary(self):
        engine = self._make_engine("phishing_ir")
        # Run with empty context — log steps don't need real scripts
        with tempfile.TemporaryDirectory() as tmpdir:
            import response.playbook_engine as pe
            original = pe.EVIDENCE_DIR
            pe.EVIDENCE_DIR = Path(tmpdir)
            summary = engine.execute({"attacker_ip": "1.2.3.4", "affected_host": "10.0.0.1"})
            pe.EVIDENCE_DIR = original

        self.assertIn("playbook", summary)
        self.assertIn("steps_total", summary)
        self.assertIn("steps_completed", summary)
        self.assertIn("results", summary)

    def test_playbook_steps_have_required_fields(self):
        engine = self._make_engine("phishing_ir")
        for step in engine.playbook["steps"]:
            self.assertIn("name", step, f"Step missing 'name': {step}")
            self.assertIn("action", step, f"Step missing 'action': {step}")


class TestCleanupPersistenceAction(unittest.TestCase):
    """
    Phase C5: cover the playbook engine's cleanup_persistence action
    handler (audit-2 Gap #4). The handler does two subprocess calls:
      1. docker ps --filter label=com.docker.compose.service=<service>
         to resolve the compose-managed container name
      2. docker exec <container> python runner.py --cleanup-all
    These tests mock subprocess.run and assert the invocation shape.
    """

    def _make_engine(self, playbook_name="lateral_movement_ir"):
        sys.path.insert(0, str(Path(__file__).parent.parent / "blue-team"))
        from response.playbook_engine import PlaybookEngine
        return PlaybookEngine(playbook_name)

    def test_cleanup_resolves_container_then_execs_runner(self):
        engine = self._make_engine()
        # Two subprocess.run results -- ps first, then exec.
        ps_result = MagicMock(stdout="adversary-in-a-box-red-team-1\n",
                              returncode=0)
        exec_result = MagicMock(stdout="all good", stderr="", returncode=0)
        with patch("response.playbook_engine.subprocess.run",
                   side_effect=[ps_result, exec_result]) as run_mock:
            result = engine._cleanup_persistence(
                {"action": "cleanup_persistence", "service": "red-team"},
                {},
            )

        self.assertTrue(result["success"])
        self.assertEqual(result["returncode"], 0)

        # First call: docker ps filter by compose service label.
        ps_call = run_mock.call_args_list[0]
        ps_cmd = ps_call.args[0]
        self.assertEqual(ps_cmd[0], "docker")
        self.assertEqual(ps_cmd[1], "ps")
        self.assertIn("label=com.docker.compose.service=red-team", ps_cmd)

        # Second call: docker exec on the resolved container name.
        exec_call = run_mock.call_args_list[1]
        exec_cmd = exec_call.args[0]
        self.assertEqual(exec_cmd[:2], ["docker", "exec"])
        self.assertEqual(exec_cmd[2], "adversary-in-a-box-red-team-1")
        self.assertIn("--cleanup-all", exec_cmd)

    def test_cleanup_returns_failure_when_no_container_running(self):
        engine = self._make_engine()
        ps_result = MagicMock(stdout="\n", returncode=0)
        with patch("response.playbook_engine.subprocess.run",
                   return_value=ps_result):
            result = engine._cleanup_persistence(
                {"action": "cleanup_persistence", "service": "red-team"}, {},
            )
        self.assertFalse(result["success"])
        self.assertIn("red-team", result["output"])

    def test_cleanup_default_service_is_red_team(self):
        engine = self._make_engine()
        ps_result = MagicMock(stdout="\n", returncode=0)
        with patch("response.playbook_engine.subprocess.run",
                   return_value=ps_result) as run_mock:
            engine._cleanup_persistence({"action": "cleanup_persistence"}, {})
        ps_cmd = run_mock.call_args_list[0].args[0]
        self.assertIn("label=com.docker.compose.service=red-team", ps_cmd,
                      "step without explicit service should default to red-team")

    def test_cleanup_surfaces_nonzero_exec_returncode(self):
        engine = self._make_engine()
        ps_result = MagicMock(stdout="container-name\n", returncode=0)
        exec_result = MagicMock(stdout="", stderr="oops", returncode=2)
        with patch("response.playbook_engine.subprocess.run",
                   side_effect=[ps_result, exec_result]):
            result = engine._cleanup_persistence(
                {"action": "cleanup_persistence", "service": "red-team"}, {},
            )
        self.assertFalse(result["success"])
        self.assertEqual(result["returncode"], 2)
        self.assertEqual(result["output"], "oops")


class TestPlaybookYAMLSchema(unittest.TestCase):
    """Validate YAML structure of all playbook files."""

    PLAYBOOKS = ["phishing_ir", "ransomware_ir", "lateral_movement_ir", "data_exfil_ir"]

    def test_all_playbooks_exist(self):
        for name in self.PLAYBOOKS:
            path = PLAYBOOKS_DIR / f"{name}.yml"
            self.assertTrue(path.exists(), f"Missing playbook: {name}.yml")

    def test_all_playbooks_have_valid_schema(self):
        import yaml
        for name in self.PLAYBOOKS:
            path = PLAYBOOKS_DIR / f"{name}.yml"
            with open(path) as f:
                data = yaml.safe_load(f)
            self.assertIn("name", data, f"{name}: missing 'name'")
            self.assertIn("incident_type", data, f"{name}: missing 'incident_type'")
            self.assertIn("severity", data, f"{name}: missing 'severity'")
            self.assertIn("steps", data, f"{name}: missing 'steps'")
            self.assertIsInstance(data["steps"], list, f"{name}: steps must be a list")
            self.assertGreater(len(data["steps"]), 0, f"{name}: must have at least one step")

    def test_playbook_severities_are_valid(self):
        import yaml
        valid_severities = {"low", "medium", "high", "critical"}
        for name in self.PLAYBOOKS:
            path = PLAYBOOKS_DIR / f"{name}.yml"
            with open(path) as f:
                data = yaml.safe_load(f)
            self.assertIn(data["severity"], valid_severities,
                          f"{name}: invalid severity '{data['severity']}'")

    def test_playbook_step_actions_are_valid(self):
        import yaml
        # Audit-2 Gap #4 adds cleanup_persistence — the action handler is in
        # response/playbook_engine.py:_cleanup_persistence.
        valid_actions = {"log", "run_script", "collect_evidence", "notify",
                         "cleanup_persistence"}
        for name in self.PLAYBOOKS:
            path = PLAYBOOKS_DIR / f"{name}.yml"
            with open(path) as f:
                data = yaml.safe_load(f)
            for step in data["steps"]:
                self.assertIn(step["action"], valid_actions,
                              f"{name} step '{step['name']}': invalid action '{step['action']}'")


class TestSigmaRules(unittest.TestCase):
    """Validate Sigma detection rule YAML files."""

    SIGMA_DIR = Path(__file__).parent.parent / "blue-team" / "detection" / "sigma"

    @classmethod
    def setUpClass(cls):
        # Phase B1: rules are now auto-discovered so a new campaign's paired
        # Sigma rule is validated automatically without touching this test.
        # `compiled/` is gitignored build output; skip it.
        cls.RULES = sorted(
            p.name for p in cls.SIGMA_DIR.glob("*.yml")
            if "compiled" not in p.parts
        )
        assert cls.RULES, "no Sigma rules found in blue-team/detection/sigma/"

    def test_all_sigma_rules_exist(self):
        for rule in self.RULES:
            path = self.SIGMA_DIR / rule
            self.assertTrue(path.exists(), f"Missing Sigma rule: {rule}")

    def test_sigma_rules_have_valid_schema(self):
        import yaml
        required_fields = ["title", "id", "status", "description", "tags", "logsource", "detection"]
        for rule in self.RULES:
            path = self.SIGMA_DIR / rule
            with open(path) as f:
                data = yaml.safe_load(f)
            for field in required_fields:
                self.assertIn(field, data, f"{rule}: missing required field '{field}'")

    def test_sigma_rules_have_attack_tags(self):
        import yaml
        for rule in self.RULES:
            path = self.SIGMA_DIR / rule
            with open(path) as f:
                data = yaml.safe_load(f)
            tags = data.get("tags", [])
            attack_tags = [t for t in tags if t.startswith("attack.")]
            self.assertGreater(len(attack_tags), 0,
                               f"{rule}: must have at least one ATT&CK tag")


if __name__ == "__main__":
    unittest.main(verbosity=2)
