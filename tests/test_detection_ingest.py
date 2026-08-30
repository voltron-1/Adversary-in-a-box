"""
tests/test_detection_ingest.py -- audit-4 G2b, extended for G1.2.

Every shipped Sigma rule must declare a `logsource` that an actual
Logstash pipeline feeds into ES, so the rule has real data to match. The
audit found 5 of 7 rules sourced from webserver / webproxy / file_event /
auth -- none of which the lab ships anywhere -- so they advertised
detections that could never fire. The fix routes every campaign's
behavioral advisory over syslog (the one pipeline that ingests
campaign-authored signals); this guard asserts no rule drifts back to an
orphaned logsource.

G1.2 adds the same idea for the operator-facing Kibana dashboards: every
Lens panel in siem/kibana/dashboards/*.ndjson queries or aggregates on a
specific field, and before this phase NONE of the three pipelines emitted
`event.dataset` at all -- every panel in operator-view.ndjson filters on
`event.dataset:suricata`, so the dashboard rendered zero data. This guard
walks the dashboard NDJSON for referenced fields and asserts each one is
either emitted by a pipeline (add_field/rename/grok) or is a documented
native passthrough field, so this class of "field the dashboard needs
doesn't exist anywhere" bug can't silently return.
"""

import json
import re
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).parent.parent
SIGMA_DIR = REPO_ROOT / "blue-team" / "detection" / "sigma"
PIPELINE_DIR = REPO_ROOT / "siem" / "logstash" / "pipelines"
DASHBOARD_DIR = REPO_ROOT / "siem" / "kibana" / "dashboards"

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


# G1.2: fields present verbatim on the source JSON documents before they
# ever reach a Logstash pipeline -- no add_field/rename/grok in any .conf
# creates them, so the bracket-notation scan below can never find them.
# @timestamp is a universal Logstash/ES meta field every event carries
# (either from a `date` filter targeting it explicitly, as suricata.conf
# and syslog.conf both do, or Logstash's own default). alert.signature/
# alert.severity are nested fields Suricata's own eve.json already ships
# under "alert": {...} -- suricata.conf reads and branches on
# [alert][severity] but never renames it, so it reaches ES exactly as
# Suricata wrote it.
NATIVE_PASSTHROUGH_FIELDS = {"@timestamp", "alert.signature", "alert.severity"}

# Matches a bracket-notation field target, e.g. [event][dataset] or
# [source][ip] -- one or more "[...]" groups back to back.
_BRACKET_FIELD_RE = r"(?:\[[^\]\[]+\])+"


def _bracket_to_dotted(bracket_field: str) -> str:
    return ".".join(re.findall(r"\[([^\]]+)\]", bracket_field))


def _pipeline_emitted_fields() -> set[str]:
    """Every field name a Logstash pipeline conf can produce, in dotted
    form, via add_field's key, rename's target (right-hand side), or a
    grok pattern's bracket-notation field capture."""
    fields: set[str] = set()
    for conf in PIPELINE_DIR.glob("*.conf"):
        text = conf.read_text(encoding="utf-8")
        # add_field => { "[a][b]" => ... }  -- the key is the new field.
        for m in re.finditer(rf'add_field\s*=>\s*\{{\s*"({_BRACKET_FIELD_RE})"', text):
            fields.add(_bracket_to_dotted(m.group(1)))
        # rename => { "old" => "[a][b]" }  -- the value is the new field.
        # Bracket-notation only ever appears as a rename *target* in these
        # pipelines (sources are plain Suricata/Zeek field names), so a
        # global scan for "=> \"[...]\"" is unambiguous here.
        for m in re.finditer(rf'=>\s*"({_BRACKET_FIELD_RE})"', text):
            fields.add(_bracket_to_dotted(m.group(1)))
        # grok's own bracket-notation field capture, e.g. %{IP:[source][ip]}
        for m in re.finditer(rf"%\{{[A-Z_]+:({_BRACKET_FIELD_RE})\}}", text):
            fields.add(_bracket_to_dotted(m.group(1)))
    return fields


def _dashboard_referenced_fields() -> dict[str, list[str]]:
    """Every field name a dashboard NDJSON references, either via a KQL
    query string (`event.dataset:suricata and event.kind:alert`) or a
    Lens column's `sourceField`. Returns {dashboard_filename: [fields]}."""
    referenced: dict[str, list[str]] = {}

    def walk(node: object, out: list[str]) -> None:
        if isinstance(node, dict):
            if node.get("language") == "kuery" and isinstance(node.get("query"), str):
                out.extend(re.findall(r"([a-zA-Z_][\w.]*)\s*:", node["query"]))
            source_field = node.get("sourceField")
            if isinstance(source_field, str) and source_field != "___records___":
                out.append(source_field)
            for value in node.values():
                walk(value, out)
        elif isinstance(node, list):
            for item in node:
                walk(item, out)

    for path in sorted(DASHBOARD_DIR.glob("*.ndjson")):
        fields: list[str] = []
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                walk(json.loads(line), fields)
        if fields:
            referenced[path.name] = fields

    return referenced


class TestDashboardFieldsAreEmitted(unittest.TestCase):
    """G1.2: every field a Kibana dashboard queries or aggregates on must
    actually exist on some document a Logstash pipeline produces --
    otherwise the panel silently renders empty, which is exactly what
    happened to every panel in operator-view.ndjson before this phase."""

    def test_every_dashboard_field_is_emitted_or_native(self) -> None:
        emitted = _pipeline_emitted_fields() | NATIVE_PASSTHROUGH_FIELDS
        missing = []
        for dashboard, fields in _dashboard_referenced_fields().items():
            for field in sorted(set(fields)):
                if field not in emitted:
                    missing.append(f"{dashboard}: {field}")
        self.assertFalse(
            missing,
            "Dashboard field(s) with no emitting pipeline and no "
            "NATIVE_PASSTHROUGH_FIELDS entry (G1.2) -- add_field it in the "
            "relevant siem/logstash/pipelines/*.conf, or if it's a field "
            "native to the source JSON, add it to NATIVE_PASSTHROUGH_FIELDS "
            "with a comment explaining why:\n  - " + "\n  - ".join(missing),
        )

    def test_operator_view_dashboard_actually_has_panels(self) -> None:
        # A dashboard with zero referenced fields would trivially pass the
        # assertion above -- guard against operator-view.ndjson itself
        # regressing into an empty stub (network-traffic.ndjson and
        # threat-overview.ndjson already are; that's a separate, known,
        # out-of-scope gap, not one G1.2 covers).
        referenced = _dashboard_referenced_fields()
        self.assertIn("operator-view.ndjson", referenced)
        self.assertTrue(referenced["operator-view.ndjson"])

    def test_event_dataset_is_emitted_by_every_pipeline(self) -> None:
        # The specific regression this phase fixes: event.dataset didn't
        # exist anywhere before G1.2, so every operator-view.ndjson panel
        # (all of which filter on event.dataset:suricata) matched nothing.
        for conf_name, dataset_value in (
            ("suricata.conf", "suricata"),
            ("zeek.conf", "zeek"),
            ("syslog.conf", "syslog"),
        ):
            text = (PIPELINE_DIR / conf_name).read_text(encoding="utf-8")
            self.assertIn(
                f'"[event][dataset]" => "{dataset_value}"',
                text,
                f'{conf_name} no longer sets [event][dataset] to "{dataset_value}"',
            )

    def test_zeek_notice_alert_tag_matches_both_path_field_spellings(self) -> None:
        text = (PIPELINE_DIR / "zeek.conf").read_text(encoding="utf-8")
        self.assertIn('if [_path] == "notice"', text)
        self.assertIn(r"[path] =~ /notice\.log$/", text)

    def test_suricata_observer_fields_are_not_gated_on_alert(self) -> None:
        # G1.2: before this phase [observer][type]/[observer][name] were
        # only set inside `if [event_type] == "alert"`, so flow/dns/http
        # records (the majority of suricata-* docs) carried neither.
        text = (PIPELINE_DIR / "suricata.conf").read_text(encoding="utf-8")
        alert_guard_start = text.index('if [event_type] == "alert"')
        observer_type_pos = text.index('"[observer][type]" => "ids"')
        self.assertLess(
            observer_type_pos,
            alert_guard_start,
            "[observer][type] must be set before (outside) the "
            "event_type==alert guard so non-alert records carry it too",
        )


if __name__ == "__main__":
    unittest.main()
