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
PIPELINE = ILM_DIR / "ingest-pipeline.json"
COMPOSE = REPO / "docker-compose.yml"

POLICY_NAME = "aib-retention-7d"
PIPELINE_NAME = "aib-ingest-stamp"
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

    def test_template_attaches_ingest_pipeline(self):
        # G1.3: every lab index gets a server-side event.ingested stamp no
        # poster can forge, so the scorer can detect a backdated @timestamp.
        tpl = json.loads(TEMPLATE.read_text())
        settings = tpl["template"]["settings"]
        self.assertEqual(settings["index.default_pipeline"], PIPELINE_NAME)


class TestIngestPipeline(unittest.TestCase):
    def test_pipeline_is_valid_json(self):
        self.assertTrue(PIPELINE.exists(), f"missing {PIPELINE}")
        json.loads(PIPELINE.read_text())

    def test_pipeline_sets_event_ingested_from_ingest_timestamp(self):
        pipeline = json.loads(PIPELINE.read_text())
        set_processors = [p["set"] for p in pipeline["processors"] if "set" in p]
        matches = [p for p in set_processors if p.get("field") == "event.ingested"]
        self.assertEqual(len(matches), 1, "expected exactly one set-event.ingested processor")
        self.assertIn("_ingest.timestamp", matches[0]["value"])


class TestComposeWiring(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # PyYAML is a declared project dependency (red-team / blue-team /
        # forensics-scoreboard requirements.txt, all installed in CI), so a
        # missing import is a real breakage. Import it hard rather than
        # SkipTest, which would silently drop these compose-wiring assertions.
        import yaml

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

    def test_es_init_installs_ingest_pipeline_before_template(self):
        # G1.3: the pipeline must exist before the template that references
        # it as its default_pipeline, or the template PUT would reference an
        # unknown pipeline (ES accepts it either way, but installing the
        # pipeline first keeps the bootstrap order intentional and matches
        # the ILM-policy-before-template pattern already established here).
        script = "".join(self.compose["services"]["es-init"]["entrypoint"])
        self.assertIn("_ingest/pipeline/" + PIPELINE_NAME, script)
        self.assertLess(
            script.index("_ingest/pipeline/" + PIPELINE_NAME),
            script.index("_index_template/aib-logs"),
        )

    def test_logstash_waits_for_es_init(self):
        dep = self.compose["services"]["logstash"]["depends_on"]
        self.assertEqual(dep["es-init"]["condition"], "service_completed_successfully")


if __name__ == "__main__":
    unittest.main()
