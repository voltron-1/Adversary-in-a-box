"""
tests/test_detection_ingest.py -- audit-4 G2b.

Every shipped Sigma rule must declare a `logsource` that an actual
Logstash pipeline feeds into ES, so the rule has real data to match. The
audit found 5 of 7 rules sourced from webserver / webproxy / file_event /
auth -- none of which the lab ships anywhere -- so they advertised
detections that could never fire. The fix routes every campaign's
behavioral advisory over syslog (the one pipeline that ingests
campaign-authored signals); this guard asserts no rule drifts back to an
orphaned logsource.
"""

import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).parent.parent
SIGMA_DIR = REPO_ROOT / "blue-team" / "detection" / "sigma"
PIPELINE_DIR = REPO_ROOT / "siem" / "logstash" / "pipelines"

# The only Logstash pipeline that ingests campaign-authored detection
# signals is syslog.conf (UDP :5514 -> syslog-*). suricata.conf and
# zeek.conf ingest IDS/NSM telemetry, not Sigma `logsource.service`
# values. So every shipped Sigma rule must source from syslog.
LIVE_SIGMA_SERVICES = {"syslog"}


class TestSigmaRulesHaveLiveIngest(unittest.TestCase):
    def _rules(self):
        for path in sorted(SIGMA_DIR.glob("*.yml")):
            with open(path, encoding="utf-8") as fh:
                yield path.name, yaml.safe_load(fh)

    def test_every_rule_sources_from_a_live_pipeline(self) -> None:
        orphaned = []
        for name, rule in self._rules():
            logsource = rule.get("logsource", {})
            service = logsource.get("service")
            if service not in LIVE_SIGMA_SERVICES:
                orphaned.append(f"{name}: logsource={logsource}")
        self.assertFalse(
            orphaned,
            "Sigma rules whose logsource has no live Logstash ingest path "
            "(audit-4 G2b) -- route the campaign's advisory over syslog and "
            "set logsource.service: syslog:\n  - " + "\n  - ".join(orphaned),
        )

    def test_syslog_pipeline_actually_exists(self) -> None:
        syslog_conf = PIPELINE_DIR / "syslog.conf"
        self.assertTrue(syslog_conf.exists(), "siem/logstash/pipelines/syslog.conf is missing")
        text = syslog_conf.read_text(encoding="utf-8")
        self.assertIn("5514", text, "syslog pipeline no longer listens on :5514")
        self.assertIn("syslog-", text, "syslog pipeline no longer writes the syslog-* index")


if __name__ == "__main__":
    unittest.main()
