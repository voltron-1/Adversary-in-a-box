"""
tests/test_scorer.py — Unit tests for the OQ-5 MTTD/MTTA tier scorer.
"""

import os
import sys
import unittest
from pathlib import Path

# Make forensics/scoreboard importable.
sys.path.insert(0, str(Path(__file__).parent.parent / "forensics" / "scoreboard"))


class TestScoreTiers(unittest.TestCase):
    """Verify each of the four detection/response tiers fires at the right boundary."""

    def setUp(self):
        # Defaults from ADR 0001 (seconds). Reset via env in case another test
        # overrode them in the same process.
        os.environ.pop("MTTD_GOLD_S", None)
        os.environ.pop("MTTD_SILVER_S", None)
        os.environ.pop("MTTD_BRONZE_S", None)
        os.environ.pop("MTTA_GOLD_S", None)
        os.environ.pop("MTTA_SILVER_S", None)
        os.environ.pop("MTTA_BRONZE_S", None)
        # Re-import after env reset so module-level constants pick up defaults.
        if "scorer" in sys.modules:
            del sys.modules["scorer"]
        import scorer  # noqa: F401

        self.scorer_mod = sys.modules["scorer"]

    # ------------------------------------------------------------- detection (MTTD)
    def test_detection_gold(self):
        mult, label = self.scorer_mod.score_tier(60, self.scorer_mod.DETECTION_THRESHOLDS)
        self.assertEqual(label, "Gold")
        self.assertEqual(mult, 1.0)

    def test_detection_silver(self):
        mult, label = self.scorer_mod.score_tier(180, self.scorer_mod.DETECTION_THRESHOLDS)
        self.assertEqual(label, "Silver")
        self.assertAlmostEqual(mult, 0.6)

    def test_detection_bronze(self):
        mult, label = self.scorer_mod.score_tier(500, self.scorer_mod.DETECTION_THRESHOLDS)
        self.assertEqual(label, "Bronze")
        self.assertAlmostEqual(mult, 0.25)

    def test_detection_miss(self):
        mult, label = self.scorer_mod.score_tier(9999, self.scorer_mod.DETECTION_THRESHOLDS)
        self.assertEqual(label, "Miss")
        self.assertEqual(mult, 0.0)

    # ------------------------------------------------------------- response (MTTA)
    def test_response_gold(self):
        mult, label = self.scorer_mod.score_tier(120, self.scorer_mod.RESPONSE_THRESHOLDS)
        self.assertEqual(label, "Gold")
        self.assertEqual(mult, 1.0)

    def test_response_silver(self):
        mult, label = self.scorer_mod.score_tier(600, self.scorer_mod.RESPONSE_THRESHOLDS)
        self.assertEqual(label, "Silver")
        self.assertAlmostEqual(mult, 0.6)

    def test_response_bronze(self):
        mult, label = self.scorer_mod.score_tier(1500, self.scorer_mod.RESPONSE_THRESHOLDS)
        self.assertEqual(label, "Bronze")
        self.assertAlmostEqual(mult, 0.25)

    def test_response_miss(self):
        mult, label = self.scorer_mod.score_tier(99999, self.scorer_mod.RESPONSE_THRESHOLDS)
        self.assertEqual(label, "Miss")
        self.assertEqual(mult, 0.0)


class TestBoundaryAndEnvOverride(unittest.TestCase):
    """Boundary checks and confirmation that env vars override defaults."""

    def _fresh_scorer(self):
        if "scorer" in sys.modules:
            del sys.modules["scorer"]
        import scorer  # noqa: F401

        return sys.modules["scorer"]

    def test_boundary_inclusive_upper_gold(self):
        # ADR: "< 2 minutes -> Gold". The implementation uses <= for inclusivity
        # at the boundary; verify 120s lands as Gold, 121s falls to Silver.
        s = self._fresh_scorer()
        _, label_at = s.score_tier(120, s.DETECTION_THRESHOLDS)
        _, label_over = s.score_tier(121, s.DETECTION_THRESHOLDS)
        self.assertEqual(label_at, "Gold")
        self.assertEqual(label_over, "Silver")

    def test_env_override_takes_effect(self):
        os.environ["MTTD_GOLD_S"] = "30"  # 0.5 min
        os.environ["MTTD_SILVER_S"] = "60"
        os.environ["MTTD_BRONZE_S"] = "90"
        try:
            s = self._fresh_scorer()
            _, label = s.score_tier(45, s.DETECTION_THRESHOLDS)
            self.assertEqual(label, "Silver")  # 30 < 45 <= 60
        finally:
            del os.environ["MTTD_GOLD_S"]
            del os.environ["MTTD_SILVER_S"]
            del os.environ["MTTD_BRONZE_S"]


class TestG13ProvenanceIntegrity(unittest.TestCase):
    """G1.3: reject forged/backdated red-team-events-* and syslog-* docs."""

    def _fresh_scorer(self):
        if "scorer" in sys.modules:
            del sys.modules["scorer"]
        import scorer  # noqa: F401

        return sys.modules["scorer"]

    # ------------------------------------------------ orphan campaign_end
    def test_orphan_campaign_end_is_dropped(self):
        s = self._fresh_scorer()
        starts = [{"campaign_id": "real"}]
        ends = [{"campaign_id": "real"}, {"campaign_id": "forged-no-start"}]
        kept_starts, kept_ends = s.Scorer._drop_anomalous_lifecycle_events(starts, ends)
        self.assertEqual(kept_starts, starts)
        self.assertEqual([e["campaign_id"] for e in kept_ends], ["real"])

    # ------------------------------------------------ backdated @timestamp
    def test_backdated_timestamp_is_dropped(self):
        s = self._fresh_scorer()
        fresh = {
            "campaign_id": "a",
            "@timestamp": "2026-05-31T10:00:00+00:00",
            "event": {"ingested": "2026-05-31T10:00:10+00:00"},  # 10s lag, fine
        }
        backdated = {
            "campaign_id": "b",
            "@timestamp": "2026-05-31T09:00:00+00:00",
            "event": {"ingested": "2026-05-31T10:00:00+00:00"},  # 1h "before" ingest
        }
        starts, ends = s.Scorer._drop_anomalous_lifecycle_events([fresh, backdated], [])
        self.assertEqual([d["campaign_id"] for d in starts], ["a"])

    def test_missing_ingested_field_is_not_penalized(self):
        # Docs written before the G1.3 pipeline existed (or if ES's default
        # pipeline is somehow bypassed) have no event.ingested -- don't treat
        # "we can't evaluate this" as "this is forged."
        s = self._fresh_scorer()
        doc = {"campaign_id": "a", "@timestamp": "2026-05-31T10:00:00+00:00"}
        starts, _ends = s.Scorer._drop_anomalous_lifecycle_events([doc], [])
        self.assertEqual(starts, [doc])

    # ------------------------------------------------ ATTACKER_IP gating
    def test_sigma_query_filters_on_attacker_ip(self):
        os.environ["ATTACKER_IP"] = "172.20.0.10"
        try:
            s = self._fresh_scorer()
            seen_queries = []

            class _Fake(s.Scorer):
                def _es_search(self, index, body, default):
                    seen_queries.append(body.get("query"))
                    return default

            scorer = _Fake(es_url="http://fake-es:9200")
            scorer._sigma_rules = {"fake": "rule"}  # bypass "no rules" early-return
            scorer._sigma_detection_ts()
            self.assertEqual(seen_queries, [{"term": {"observer.ingress.ip": "172.20.0.10"}}])
        finally:
            del os.environ["ATTACKER_IP"]

    def test_sigma_query_fails_closed_without_attacker_ip(self):
        os.environ.pop("ATTACKER_IP", None)
        s = self._fresh_scorer()
        self.assertEqual(s.ATTACKER_IP, "")

        class _Fake(s.Scorer):
            def _es_search(self, index, body, default):
                # A real cluster would return zero hits for must_not/match_all;
                # simulate that rather than asserting on the exact query shape.
                return {"hits": {"hits": []}}

        scorer = _Fake(es_url="http://fake-es:9200")
        scorer._sigma_rules = {"fake": "rule"}
        self.assertEqual(scorer._sigma_detection_ts(), [])


class TestG61ZeekNoticeScoring(unittest.TestCase):
    """G6.1: Zeek notice.log entries (real behavioral detections) must count
    toward MTTD scoring, the same trust level as a Suricata alert -- not
    gated behind ATTACKER_IP/Sigma the way a self-reported syslog marker is,
    since a notice comes from Zeek parsing real observed packets."""

    def _fresh_scorer(self):
        if "scorer" in sys.modules:
            del sys.modules["scorer"]
        import scorer  # noqa: F401

        return sys.modules["scorer"]

    def test_queries_zeek_index_for_docs_with_a_note_field(self):
        s = self._fresh_scorer()
        seen = []

        class _Fake(s.Scorer):
            def _es_search(self, index, body, default):
                seen.append((index, body.get("query")))
                return default

        scorer = _Fake(es_url="http://fake-es:9200")
        scorer._zeek_notice_ts()
        self.assertEqual(seen, [("zeek-*", {"exists": {"field": "note"}})])

    def test_extracts_timestamps_from_matching_docs(self):
        s = self._fresh_scorer()

        class _Fake(s.Scorer):
            def _es_search(self, index, body, default):
                return {
                    "hits": {
                        "hits": [
                            {
                                "_source": {
                                    "note": "DnsExfil::High_Entropy_Subdomain",
                                    "@timestamp": "2026-05-31T10:00:00+00:00",
                                }
                            },
                        ]
                    }
                }

        scorer = _Fake(es_url="http://fake-es:9200")
        self.assertEqual(len(scorer._zeek_notice_ts()), 1)

    def test_not_gated_on_attacker_ip(self):
        # Unlike _sigma_detection_ts, a missing/unset ATTACKER_IP must not
        # suppress zeek notice scoring -- notices aren't forgeable the way a
        # raw syslog datagram is.
        os.environ.pop("ATTACKER_IP", None)
        s = self._fresh_scorer()
        self.assertEqual(s.ATTACKER_IP, "")

        class _Fake(s.Scorer):
            def _es_search(self, index, body, default):
                return {
                    "hits": {
                        "hits": [
                            {
                                "_source": {
                                    "note": "ArpSpoof::Duplicate_IP_MAC_Binding",
                                    "@timestamp": "2026-05-31T10:00:00+00:00",
                                }
                            },
                        ]
                    }
                }

        scorer = _Fake(es_url="http://fake-es:9200")
        self.assertEqual(len(scorer._zeek_notice_ts()), 1)

    def test_fetch_merges_suricata_sigma_and_zeek_detections(self):
        # The whole point of G6.1: a Zeek-only detection must show up in the
        # same alert_ts list a Suricata alert would, not a separate,
        # uncounted stream.
        s = self._fresh_scorer()

        class _Fake(s.Scorer):
            def _es_search(self, index, body, default):
                if index == "suricata-*":
                    return {
                        "hits": {
                            "hits": [
                                {"_source": {"@timestamp": "2026-05-31T10:00:00+00:00"}},
                            ]
                        }
                    }
                if index == "zeek-*":
                    return {
                        "hits": {
                            "hits": [
                                {
                                    "_source": {
                                        "note": "ExfilVolume::High_Outbound_Volume",
                                        "@timestamp": "2026-05-31T10:05:00+00:00",
                                    }
                                },
                            ]
                        }
                    }
                return default

        scorer = _Fake(es_url="http://fake-es:9200")
        _starts, _ends, alert_ts, _responses = scorer._fetch()
        self.assertEqual(len(alert_ts), 2)


class TestG233FalcoScoring(unittest.TestCase):
    """#233: real Falco alerts (kernel-observed syscall telemetry) must
    count toward MTTD scoring, the same trust tier as a Suricata alert or
    Zeek notice -- but unlike Zeek (its own log files, not a network
    listener), Falco delivers over the same open UDP syslog port a
    self-reported campaign advisory uses, so it needs the same
    FALCO_HOST_IP forgery guard _sigma_detection_ts uses for ATTACKER_IP."""

    def setUp(self):
        os.environ.pop("FALCO_HOST_IP", None)

    def _fresh_scorer(self):
        if "scorer" in sys.modules:
            del sys.modules["scorer"]
        import scorer  # noqa: F401

        return sys.modules["scorer"]

    def test_fails_closed_when_falco_host_ip_unset(self):
        s = self._fresh_scorer()
        self.assertEqual(s.FALCO_HOST_IP, "")

        class _Fake(s.Scorer):
            def _es_search(self, index, body, default):
                raise AssertionError("must not query ES when FALCO_HOST_IP is unset")

        scorer = _Fake(es_url="http://fake-es:9200")
        self.assertEqual(scorer._falco_ts(), [])

    def test_queries_syslog_index_gated_on_falco_host_ip_and_tag(self):
        os.environ["FALCO_HOST_IP"] = "172.20.0.80"
        s = self._fresh_scorer()
        seen = []

        class _Fake(s.Scorer):
            def _es_search(self, index, body, default):
                seen.append((index, body.get("query")))
                return default

        scorer = _Fake(es_url="http://fake-es:9200")
        scorer._falco_ts()
        self.assertEqual(
            seen,
            [
                (
                    "syslog-*",
                    {
                        "bool": {
                            "must": [
                                {"term": {"observer.ingress.ip": "172.20.0.80"}},
                                {"term": {"tags": "falco_alert"}},
                            ]
                        }
                    },
                )
            ],
        )

    def test_extracts_timestamps_from_matching_docs(self):
        os.environ["FALCO_HOST_IP"] = "172.20.0.80"
        s = self._fresh_scorer()

        class _Fake(s.Scorer):
            def _es_search(self, index, body, default):
                return {
                    "hits": {
                        "hits": [
                            {
                                "_source": {
                                    "falco": {"rule": "Lab Cron Persistence Write"},
                                    "@timestamp": "2026-05-31T10:00:00+00:00",
                                }
                            },
                        ]
                    }
                }

        scorer = _Fake(es_url="http://fake-es:9200")
        self.assertEqual(len(scorer._falco_ts()), 1)

    def test_fetch_merges_falco_detections(self):
        # Mirrors TestG61ZeekNoticeScoring.test_fetch_merges_...: a
        # Falco-only detection must show up in the same alert_ts list a
        # Suricata alert would, not a separate, uncounted stream.
        os.environ["FALCO_HOST_IP"] = "172.20.0.80"
        s = self._fresh_scorer()

        class _Fake(s.Scorer):
            def _es_search(self, index, body, default):
                if index == "suricata-*":
                    return {
                        "hits": {
                            "hits": [
                                {"_source": {"@timestamp": "2026-05-31T10:00:00+00:00"}},
                            ]
                        }
                    }
                if index == "syslog-*":
                    return {
                        "hits": {
                            "hits": [
                                {
                                    "_source": {
                                        "falco": {"rule": "Lab SUID Bit Set"},
                                        "@timestamp": "2026-05-31T10:05:00+00:00",
                                    }
                                },
                            ]
                        }
                    }
                return default

        scorer = _Fake(es_url="http://fake-es:9200")
        _starts, _ends, alert_ts, _responses = scorer._fetch()
        self.assertEqual(len(alert_ts), 2)


if __name__ == "__main__":
    unittest.main()
