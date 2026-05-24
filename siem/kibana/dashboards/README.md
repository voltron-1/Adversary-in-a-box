# Kibana Dashboards

Three NDJSON exports live here:

| File | Contents |
|---|---|
| `operator-view.ndjson` | **Phase E1** -- the headline dashboard. Three Lens visualizations bound to `suricata-*`: Alerts Over Time (line), Top Alert Signatures (pie), Alerts by Severity (pie). 30-minute window, 15-second auto-refresh. Pair with the MTTD/MTTA scoreboard at `:5002` for the full operator view. |
| `threat-overview.ndjson` | Original scaffolded dashboard (empty panels). Kept as a placeholder so the import command picks up the title. Replace with your own viz when ready. |
| `network-traffic.ndjson` | Original scaffolded dashboard for Zeek + Suricata flow viz. Same status as `threat-overview`. |

## Import

```bash
# Kibana running on the default lab port:
KIBANA_URL=http://localhost:5601

curl -X POST "$KIBANA_URL/api/saved_objects/_import?overwrite=true" \
     -H "kbn-xsrf: true" \
     --form file=@siem/kibana/dashboards/operator-view.ndjson
```

Or via the UI: **Management → Stack Management → Saved Objects → Import**
and pick the file.

## After import

The dashboard expects:

- `suricata-*` index pattern (the import creates it if missing).
- `@timestamp`, `event.dataset`, `event.kind`, `alert.signature`,
  `alert.severity` fields populated. The Logstash pipeline at
  `siem/logstash/pipelines/suricata.conf` produces these by default.

If any panel shows "No data" after a campaign run, check that
`event.dataset:suricata` actually matches your ingest -- the Logstash
pipeline tags events on its way through. You may need to adjust the
KQL in the visualization's "Query" field (use the Lens editor) if you
re-label.
