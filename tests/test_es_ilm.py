"""
tests/test_es_ilm.py — Wave 2 / P7 (S3)

Validates the Elasticsearch retention bootstrap: a 7-day delete ILM policy and
an index template that attaches it to every lab telemetry index pattern, plus
the one-shot es-init service that installs them before data producers start.

These are static checks (no live ES in CI unit runs); the integration suite
exercises the running cluster.
"""

import json
import unittest
from pathlib import Path

REPO = Path(__file__).parent.parent
ILM_DIR = REPO / "siem" / "elasticsearch" / "ilm"
POLICY = ILM_DIR / "ilm-policy.json"
TEMPLATE = ILM_DIR / "index-template.json"
COMPOSE = REPO / "docker-compose.yml"

POLICY_NAME = "aib-retention-7d"
EXPECTED_PATTERNS = {
    "suricata-*",
    "zeek-*",
    "syslog-*",
    "red-team-events-*",
    "ir-events-*",
}


class TestIlmPolicy(unittest.TestCase):
    def test_policy_is_valid_json(self):
        self.assertTrue(POLICY.exists(), f"missing {POLICY}")
        json.loads(POLICY.read_text())

    def test_policy_deletes_after_7d(self):
        policy = json.loads(POLICY.read_text())["policy"]
        delete = policy["phases"]["delete"]
        self.assertEqual(delete["min_age"], "7d")
        self.assertIn("delete", delete["actions"])


class TestIndexTemplate(unittest.TestCase):
    def test_template_is_valid_json(self):
        self.assertTrue(TEMPLATE.exists(), f"missing {TEMPLATE}")
        json.loads(TEMPLATE.read_text())

    def test_template_covers_all_lab_indices(self):
        tpl = json.loads(TEMPLATE.read_text())
        self.assertEqual(set(tpl["index_patterns"]), EXPECTED_PATTERNS)

    def test_template_attaches_policy(self):
        tpl = json.loads(TEMPLATE.read_text())
        settings = tpl["template"]["settings"]
        self.assertEqual(settings["index.lifecycle.name"], POLICY_NAME)


class TestComposeWiring(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import yaml
        except ImportError as exc:  # pragma: no cover
            raise unittest.SkipTest("PyYAML not installed") from exc
        cls.compose = yaml.safe_load(COMPOSE.read_text())

    def test_es_init_service_exists(self):
        self.assertIn("es-init", self.compose["services"])

    def test_es_init_waits_for_es_healthy(self):
        dep = self.compose["services"]["es-init"]["depends_on"]
        self.assertEqual(dep["elasticsearch"]["condition"], "service_healthy")

    def test_es_init_installs_policy_and_template(self):
        # The entrypoint script references both the policy and the template.
        script = "".join(self.compose["services"]["es-init"]["entrypoint"])
        self.assertIn("_ilm/policy/" + POLICY_NAME, script)
        self.assertIn("_index_template/aib-logs", script)

    def test_logstash_waits_for_es_init(self):
        dep = self.compose["services"]["logstash"]["depends_on"]
        self.assertEqual(dep["es-init"]["condition"], "service_completed_successfully")


if __name__ == "__main__":
    unittest.main()
