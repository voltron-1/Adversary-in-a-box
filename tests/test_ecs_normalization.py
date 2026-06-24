"""
tests/test_ecs_normalization.py — Wave 2 / P9 (S4)

The three Logstash pipelines must use ONE ECS field convention. ECS fields are
declared with Logstash nested syntax ([source][ip], [event][kind], ...) rather
than dotted string keys ("event.kind"), and the core fields are named
identically across the suricata-*/zeek-*/syslog-* indices.
"""

import re
import unittest
from pathlib import Path

PIPELINE_DIR = Path(__file__).parent.parent / "siem" / "logstash" / "pipelines"
PIPELINES = ["suricata.conf", "zeek.conf", "syslog.conf"]

# A complete quoted field-key token in dotted ECS form, e.g. "event.kind" or
# "source.geo" -- the mixed convention we eliminated. The trailing quote keeps
# this from matching Ruby calls like "event.set('@timestamp', ...)".
DOTTED_ECS = re.compile(
    r'"(?:event|observer|threat|source|destination|host|process|user|network)'
    r'(?:\.\w+)+"'
)


class TestEcsNormalization(unittest.TestCase):
    def _text(self, name):
        path = PIPELINE_DIR / name
        self.assertTrue(path.exists(), f"missing pipeline: {name}")
        return path.read_text(encoding="utf-8")

    def _code_text(self, name):
        """Pipeline text with comment lines removed."""
        lines = [
            ln for ln in self._text(name).splitlines() if not ln.lstrip().startswith("#")
        ]
        return "\n".join(lines)

    def test_no_dotted_ecs_field_keys(self):
        for name in PIPELINES:
            text = self._code_text(name)
            hits = DOTTED_ECS.findall(text)
            self.assertEqual(
                hits,
                [],
                f"{name} still declares dotted ECS field keys (use nested "
                f"[a][b] syntax instead): {hits}",
            )

    def test_source_ip_present_and_consistent(self):
        # [source][ip] must appear in all three pipelines, named identically.
        # Use code-only text: every pipeline mentions [source][ip] in a header
        # comment, so checking raw text would pass even if the field were
        # dropped from the actual filter logic.
        for name in PIPELINES:
            text = self._code_text(name)
            self.assertIn(
                "[source][ip]",
                text,
                f"{name} does not produce the ECS [source][ip] field",
            )

    def test_destination_ip_in_network_pipelines(self):
        # IDS/NSM pipelines carry a destination; syslog (host events) need not.
        for name in ("suricata.conf", "zeek.conf"):
            self.assertIn("[destination][ip]", self._text(name))

    def test_ssh_auth_failure_has_authentication_category(self):
        # The SSH brute-force block must set ECS [event][category] so its alerts
        # are not dropped by category-filtered detection queries. Regression for
        # the wave-2 gap where only the sudo/cron blocks set a category.
        text = self._code_text("syslog.conf")
        self.assertIn(
            '"[event][category]" => "authentication"',
            text,
            "syslog.conf SSH auth-failure block must set [event][category]=authentication",
        )

    def test_event_kind_nested_form(self):
        # event.kind=alert must be set via nested syntax where used.
        for name in PIPELINES:
            text = self._text(name)
            if "alert" in text and "event" in text:
                self.assertIn("[event][kind]", text, f"{name} missing nested [event][kind]")


if __name__ == "__main__":
    unittest.main()
