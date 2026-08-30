"""
tests/test_falco_rules.py -- #233

Content-level regression guard for blue-team/detection/falco/lab_rules.yaml
and its docker-compose.yml/syslog.conf wiring.

Unlike the Zeek scripts (no interpreter available anywhere this session),
this rules file WAS validated against the real `falco` binary during
development (`falco -V` alongside Falco's own default rules, and a
`--dry-run` confirming all four custom rules load and enable) -- see
findings/20260830-g233-auditd-portability-spike.md for the transcript. No
falco binary is available in this test environment or CI, so that
validation isn't re-run automatically here; these are the same class of
static content assertions used throughout this repo for interpreters that
can't run in CI (Zeek, PKI shell scripts under other users), guarding the
specific rule names/conditions/tags this phase shipped from silently
drifting or being typo'd.
"""

from __future__ import annotations

import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).parent.parent
FALCO_RULES = REPO_ROOT / "blue-team" / "detection" / "falco" / "lab_rules.yaml"
COMPOSE_FILE = REPO_ROOT / "docker-compose.yml"
SYSLOG_CONF = REPO_ROOT / "siem" / "logstash" / "pipelines" / "syslog.conf"

EXPECTED_RULES = {
    "Lab Cron Persistence Write": "T1053.003",
    "Lab SUID Bit Set": "T1548.001",
    "Lab SSH Authorized Keys Write": "T1098.004",
    "Lab Ransomware-Style File Rename": "T1486",
}


class TestFalcoRulesSchema(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.docs = list(yaml.safe_load_all(FALCO_RULES.read_text(encoding="utf-8")))
        # Falco rules files are a flat list of {list:...}/{rule:...} objects
        # under one YAML document, not a multi-document stream.
        cls.items = cls.docs[0]
        cls.rules_by_name = {
            item["rule"]: item for item in cls.items if isinstance(item, dict) and "rule" in item
        }

    def test_file_parses_as_valid_yaml(self):
        self.assertIsInstance(self.items, list)

    def test_all_four_techniques_have_a_rule(self):
        self.assertEqual(set(self.rules_by_name), set(EXPECTED_RULES))

    def test_every_rule_has_the_required_falco_fields(self):
        for name, rule in self.rules_by_name.items():
            with self.subTest(rule=name):
                for field in ("condition", "output", "priority", "tags"):
                    self.assertIn(field, rule, f"{name} missing '{field}'")

    def test_every_rule_is_tagged_with_its_technique_id(self):
        for name, technique in EXPECTED_RULES.items():
            with self.subTest(rule=name):
                self.assertIn(technique, self.rules_by_name[name]["tags"])

    def test_no_required_engine_version_pin(self):
        # A prior draft pinned required_engine_version to a made-up hex
        # value that the real falco binary rejected outright ("Rules
        # require engine version 0.96256.0, but engine version is
        # 0.43.0") -- validated against the real binary and dropped
        # rather than guessed again. Guard against it silently coming back.
        for item in self.items:
            if isinstance(item, dict):
                self.assertNotIn("required_engine_version", item)

    def test_ransomware_rule_documents_the_no_aggregation_limitation(self):
        # Falco's condition language has no count()/timeframe primitive
        # (unlike Zeek's SumStats, used for the equivalent Zeek rate
        # signals) -- this rule fires per rename, not on a burst
        # threshold. The limitation must stay documented, not silently
        # dropped in a future edit. Checked as two fragments rather than
        # one phrase since the source wraps across commented lines.
        text = FALCO_RULES.read_text(encoding="utf-8")
        self.assertIn("no built-in", text)
        self.assertIn("count()/timeframe primitive", text)


class TestFalcoComposeWiring(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = COMPOSE_FILE.read_text(encoding="utf-8")

    def test_falco_service_defined(self):
        self.assertIn("\n  falco:\n", self.text)

    def test_no_pid_host_granted(self):
        # The whole point of re-scoping #233 from auditd to Falco: Falco's
        # blocker (CAP_SYS_RESOURCE) is an ordinary per-container grant,
        # not --pid=host's host-wide process visibility. Guard against a
        # future edit re-adding it to "fix" some other Falco issue without
        # re-litigating that tradeoff.
        falco_block = self.text.split("\n  falco:\n", 1)[1].split("\n  elasticsearch:", 1)[0]
        self.assertNotIn("pid: host", falco_block)
        self.assertNotIn('pid: "host"', falco_block)

    def test_no_docker_socket_mount(self):
        # Checks for an actual mount source, not the word "docker.sock" --
        # the service's own cap_add comment block explains *why* there
        # isn't one, and legitimately contains the string.
        falco_block = self.text.split("\n  falco:\n", 1)[1].split("\n  elasticsearch:", 1)[0]
        self.assertNotIn("/var/run/docker.sock:", falco_block)

    def test_lab_rules_mounted_into_rules_d(self):
        self.assertIn(
            "blue-team/detection/falco/lab_rules.yaml:/etc/falco/rules.d/lab_rules.yaml", self.text
        )

    def test_falco_ships_over_the_syslog_pipeline_not_a_new_port(self):
        # #233's own decision precedent (G-INFRA.2) was reuse the existing
        # syslog.conf pipeline rather than stand up a new ingest path.
        falco_block = self.text.split("\n  falco:\n", 1)[1].split("\n  elasticsearch:", 1)[0]
        self.assertIn("logger", falco_block)
        self.assertIn("5514", falco_block)

    def test_scoreboard_gets_falco_host_ip(self):
        self.assertIn("FALCO_HOST_IP=${LAB_NET_PREFIX:-172.20.0}.80", self.text)


class TestSyslogConfFalcoParsing(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = SYSLOG_CONF.read_text(encoding="utf-8")

    def test_falco_program_conditional_present(self):
        self.assertIn('if [program] == "falco"', self.text)

    def test_json_parses_syslog_message_into_falco_field(self):
        self.assertIn('source => "syslog_message"', self.text)
        self.assertIn('target => "falco"', self.text)

    def test_every_rule_name_maps_to_its_technique(self):
        for name, technique in EXPECTED_RULES.items():
            with self.subTest(rule=name):
                self.assertIn(f'[falco][rule] == "{name}"', self.text)
                # The mapping's mutate block must set the matching technique
                # id somewhere after that rule-name check.
                idx = self.text.index(f'[falco][rule] == "{name}"')
                window = self.text[idx : idx + 200]
                self.assertIn(technique, window)

    def test_falco_alert_tagged_for_scorer_gating(self):
        # forensics/scoreboard/scorer.py's _falco_ts() filters on this tag.
        self.assertIn('add_tag => ["falco_alert"]', self.text)


if __name__ == "__main__":
    unittest.main()
