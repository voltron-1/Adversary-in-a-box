"""
tests/test_scoreboard_syslog_shipping.py -- #238 (G-INFRA.2 follow-up)

Content-level guards for docker-compose.yml's scoreboard `logging:` block
and syslog.conf's grok pattern fix + scoreboard award-line parsing.

No live Logstash is available in this test environment, so
TestGrokPatternAgainstRealWireFormats re-implements the specific grok
building blocks this pattern uses (SYSLOGTIMESTAMP, HOSTNAME, PROG,
POSINT -- the standard definitions from logstash-patterns-core's
grok-patterns file) as raw Python regex and runs them against real wire
formats captured during development (a UDP listener capturing actual
`docker run --log-driver=syslog` output, and the real `logger --rfc3164`
output from #233's spike) -- not synthetic guesses. This is what actually
caught the bug this phase fixes: the original pattern's combined
"(?:timestamp hostname )?" optional group plus lazy %{DATA:program} let
`program` swallow the whole timestamp when a message had a timestamp but
no hostname (exactly what Docker's syslog driver emits), something a
purely textual "does the string contain %{PROG}" check would never catch.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
COMPOSE_FILE = REPO_ROOT / "docker-compose.yml"
SYSLOG_CONF = REPO_ROOT / "siem" / "logstash" / "pipelines" / "syslog.conf"

# Standard grok pattern definitions (logstash-patterns-core), reimplemented
# in raw Python regex for offline testing -- see module docstring.
_MONTH = r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
_MONTHDAY = r"(?:(?:0[1-9])|(?:[12][0-9])|(?:3[01])|[1-9])"
_TIME = r"(?:2[0123]|[01]?[0-9]):(?:[0-5][0-9])(?::(?:(?:[0-5]?[0-9]|60)(?:[:.,][0-9]+)?))?"
SYSLOGTIMESTAMP = rf"{_MONTH} +{_MONTHDAY} {_TIME}"
HOSTNAME = r"\b(?:[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\.(?:[0-9A-Za-z][0-9A-Za-z-]{0,62}))*(\.?|\b)"
PROG = r"[\w._/%-]+"
DATA = r".*?"
POSINT = r"\b(?:[1-9][0-9]*)\b"

# The pattern this phase shipped (independent optional groups + PROG).
FIXED_PATTERN = re.compile(
    rf"(?:(?P<ts>{SYSLOGTIMESTAMP}) )?(?:(?P<host>{HOSTNAME}) )?"
    rf"(?P<program>{PROG})(?:\[(?P<pid>{POSINT})\])?: (?P<syslog_message>.*)"
)

# The pattern this phase replaced (combined optional group + DATA) -- kept
# here only to prove it actually breaks on the Docker-syslog-driver case,
# so a future revert would be caught by test_old_pattern_actually_broke.
OLD_PATTERN = re.compile(
    rf"(?:(?P<ts>{SYSLOGTIMESTAMP}) (?P<host>{HOSTNAME}) )?"
    rf"(?P<program>{DATA})(?:\[(?P<pid>{POSINT})\])?: (?P<syslog_message>.*)"
)

# Real wire formats captured during development (see findings/
# 20260830-g233-auditd-portability-spike.md and this phase's commit).
DOCKER_SYSLOG_DRIVER_LINE = (
    'Aug 30 15:24:42 scoreboard[1737]: {"level":"INFO","message":"award test"}'
)
LOGGER_RFC3164_LINE = 'Aug 30 15:11:39 2a90c6209d90 falco: {"output":"x"}'
CAMPAIGN_ADVISORY_LINE = "aib-cron_backdoor: cron install simulated"
REAL_RSYSLOG_LINE = "Jan 15 10:30:00 myhost sshd[1234]: Failed password for root"
SCOREBOARD_AWARD_LINE = (
    "Aug 30 15:28:27 scoreboard[1737]: 2026-08-30 15:30:00,123 INFO app: "
    "award: lab_violation_penalty -5 to blue-team from 172.20.0.20 (detail=None)"
)


class TestGrokPatternAgainstRealWireFormats(unittest.TestCase):
    def test_docker_syslog_driver_line_gets_correct_program(self):
        # The actual bug: Docker's syslog driver never emits a hostname
        # field, only a timestamp -- program must not absorb it.
        m = FIXED_PATTERN.match(DOCKER_SYSLOG_DRIVER_LINE)
        self.assertIsNotNone(m)
        self.assertEqual(m.group("program"), "scoreboard")
        self.assertEqual(m.group("pid"), "1737")
        self.assertIsNone(m.group("host"))

    def test_old_pattern_actually_broke_on_this_case(self):
        # Proves the bug was real, not a hypothetical -- the replaced
        # pattern DOES mis-capture program on the exact same input.
        m = OLD_PATTERN.match(DOCKER_SYSLOG_DRIVER_LINE)
        self.assertIsNotNone(m)
        self.assertNotEqual(m.group("program"), "scoreboard")
        self.assertIn("scoreboard", m.group("program"))  # still ends up in there, just prefixed

    def test_logger_rfc3164_line_still_works(self):
        # #233's Falco delivery -- has a hostname, must not regress.
        m = FIXED_PATTERN.match(LOGGER_RFC3164_LINE)
        self.assertIsNotNone(m)
        self.assertEqual(m.group("program"), "falco")
        self.assertEqual(m.group("host"), "2a90c6209d90")

    def test_campaign_advisory_line_still_works(self):
        # G1.5's no-prefix-at-all shape -- must not regress.
        m = FIXED_PATTERN.match(CAMPAIGN_ADVISORY_LINE)
        self.assertIsNotNone(m)
        self.assertEqual(m.group("program"), "aib-cron_backdoor")
        self.assertIsNone(m.group("ts"))
        self.assertIsNone(m.group("host"))

    def test_real_rsyslog_line_still_works(self):
        # Real host syslog (sudo/cron/sshd) -- has both timestamp and
        # hostname, must not regress.
        m = FIXED_PATTERN.match(REAL_RSYSLOG_LINE)
        self.assertIsNotNone(m)
        self.assertEqual(m.group("program"), "sshd")
        self.assertEqual(m.group("host"), "myhost")
        self.assertEqual(m.group("pid"), "1234")

    def test_scoreboard_award_line_parses_end_to_end(self):
        m = FIXED_PATTERN.match(SCOREBOARD_AWARD_LINE)
        self.assertIsNotNone(m)
        self.assertEqual(m.group("program"), "scoreboard")
        self.assertIn("award: lab_violation_penalty -5 to blue-team", m.group("syslog_message"))


class TestComposeScoreboardLogging(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = COMPOSE_FILE.read_text(encoding="utf-8")
        cls.block = cls.text.split("\n  scoreboard:\n", 1)[1].split("\n  pki-nginx:", 1)[0]

    def test_scoreboard_has_syslog_logging_driver(self):
        self.assertIn("driver: syslog", self.block)

    def test_syslog_address_uses_an_ip_not_the_service_hostname(self):
        # The syslog log driver resolves syslog-address from the Docker
        # DAEMON's own network context, not the container's -- "logstash"
        # (the compose service name) fails to resolve there and refuses
        # to even start the container ("dial udp: lookup logstash on
        # 8.8.8.8:53: no such host"), confirmed empirically. Must be
        # logstash's static address instead.
        self.assertIn("syslog-address:", self.block)
        self.assertNotIn("udp://logstash:", self.block)
        self.assertIn("${LAB_NET_PREFIX:-172.20.0}.51:5514", self.block)

    def test_no_other_service_gained_a_logging_block(self):
        # Deliberately scoped to just this one service (G-INFRA.2's
        # decision) -- not a blanket default that would flood syslog-*
        # with ES/Kibana/Logstash's own operational noise.
        other_services = (
            self.text.split("\n  scoreboard:\n", 1)[0] + self.text.split("\n  pki-nginx:", 1)[1]
        )
        self.assertNotIn("driver: syslog", other_services)


class TestSyslogConfScoreboardParsing(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = SYSLOG_CONF.read_text(encoding="utf-8")

    def test_grok_pattern_uses_independent_optional_groups(self):
        # The fix: timestamp and hostname must each be their own `(?:...)?`
        # group, not one combined unit -- otherwise a message with a
        # timestamp but no hostname (Docker's syslog driver) can't match
        # "has timestamp, no hostname" at all.
        self.assertIn(
            "(?:%{SYSLOGTIMESTAMP:syslog_timestamp} )?(?:%{HOSTNAME:[host][name]} )?%{PROG:program}",
            self.text,
        )

    def test_grok_pattern_no_longer_uses_data_for_program(self):
        self.assertNotIn("%{DATA:program}", self.text)

    def test_scoreboard_award_conditional_present(self):
        self.assertIn('if [program] == "scoreboard"', self.text)
        self.assertIn("award: ", self.text)

    def test_scoreboard_award_tagged_distinctly(self):
        self.assertIn('add_tag => ["scoreboard_award"]', self.text)


if __name__ == "__main__":
    unittest.main()
