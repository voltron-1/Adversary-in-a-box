# SIEM Security Audit — 2026-08-13

**Scope:** `siem/elasticsearch/` (elasticsearch.yml, ilm/), `siem/kibana/` (kibana.yml, dashboards/), `siem/logstash/` (logstash.yml, pipelines/). Supporting evidence pulled from `docker-compose.yml`, `.env.example`, `blue-team/detection/suricata/suricata.yaml`, `blue-team/detection/zeek/local.zeek`, `scripts/setup/compile_sigma.sh`, `red-team/campaigns/base_campaign.py`.
**Out of scope:** blue-team Flask app internals, PKI lab, red-team campaign logic (referenced only as data sources).
**Assumption:** this is a training lab, so *intentional* weakness is expected. Findings are rated on impact to the lab host, cross-student isolation, and — most importantly — whether a defect silently defeats the lab's own teaching objective (a working detection pipeline).
**Constraint:** no execution capability in this session; runtime-behavior claims are flagged where they need `tester-debugger` confirmation.

## Summary

**19 findings: 1 CRITICAL, 6 HIGH, 8 MEDIUM, 4 LOW** (+3 INFO). No committed secrets were found in `siem/` — that grep came back clean.

**Most important:** Elasticsearch runs with `xpack.security.enabled: false` *and* publishes 9200 to `0.0.0.0` on the host, so any user on the lab host or its LAN has unauthenticated cluster-admin — including `DELETE /suricata-*` — which silently breaks the repo's own per-student isolation guarantee and leaves no audit trail because SIEM audit logging is entirely absent.

**Notable in the "suricata logstash pipeline bugs" fix area:** two live false-negative bugs remain — no pipeline ever sets `event.dataset`, yet all three panels of the headline `operator-view` dashboard filter on `event.dataset:suricata` (permanently empty dashboard), and `zeek.conf`'s `if [_path] == "notice"` can never match under Zeek's base JSON writer, so every Zeek notice (port scan, lateral movement, DNS exfil) is ingested without `event.kind:alert`.

---

**[CRITICAL] Elasticsearch has no authentication and is published to all host interfaces**
- **MITRE ATT&CK**: T1485 (Data Destruction), T1070.001 (Clear Windows/Linux Event Logs), T1213 (Data from Information Repositories)
- **Red Team**: `xpack.security.enabled: false` means zero auth, zero TLS, zero RBAC on port 9200 — and compose publishes it with no bind address, so it listens on `0.0.0.0` on the host. Any user on the lab host, and anyone who can reach the host's IP on the LAN, gets unauthenticated cluster-admin: `GET /_cat/indices`, `POST /suricata-*/_search` (read every alert, every captured payload), `DELETE /suricata-*,zeek-*,syslog-*` (destroy all evidence in one request), and `PUT /_cluster/settings` for persistent cluster changes. Compose explicitly anticipates a shared host ("two students on the same host do not collide"), and per-student `LAB_NET_PREFIX`/network isolation does nothing here — the published port bypasses `internal: true` entirely, so student A can wipe student B's SIEM.
- **Blue Team**: No detection exists. With security disabled, ES audit logging (`xpack.security.audit.enabled`) is unavailable by construction, and `logger.org.elasticsearch: WARN` suppresses what little remains. An index deletion produces no artifact anywhere in the lab.
- **Evidence**:
  - `siem/elasticsearch/elasticsearch.yml:4,9` — `network.host: 0.0.0.0` / `xpack.security.enabled: false`
  - `docker-compose.yml:275-276` — `ports: - "${ELASTICSEARCH_PORT:-9200}:9200"`
  - `docker-compose.yml:282` — `- xpack.security.enabled=false`
- **Recommendation**: Change the publish to loopback-only: `"127.0.0.1:${ELASTICSEARCH_PORT:-9200}:9200"`. That alone kills LAN exposure and keeps every documented workflow (`curl http://localhost:9200/...` in `docs/tutorials/blue-team.md:40`) working. For shared hosts, additionally set `xpack.security.enabled: true` with `ELASTIC_PASSWORD` from `.env` and add `user`/`password` to the three Logstash `elasticsearch` outputs plus `elasticsearch.username`/`elasticsearch.password` in kibana.yml. Do not rely on `internal: true` — it does not constrain published ports.

---

**[HIGH] Kibana is unauthenticated on 0.0.0.0:5601, exposing an ES admin console and the Detection Engine API**
- **MITRE ATT&CK**: T1562.001 (Impair Defenses: Disable or Modify Tools)
- **Red Team**: Same root cause as the finding above, but a distinct attack surface. Unauthenticated Kibana provides (a) Dev Tools — a GUI for arbitrary ES requests, so the CRITICAL finding is exploitable by a browser with no tooling; (b) Saved Objects import/export — an attacker can overwrite or delete the operator dashboards; (c) `/api/detection_engine/rules` — attacker deletes or disables every Sigma-derived detection rule *before* running their campaign, then re-imports them afterward. `compile_sigma.sh` proves no credential is needed: it POSTs to that endpoint with only a `kbn-xsrf` header and no `Authorization`.
- **Blue Team**: No authentication, no audit log, and `logging.root.level: warn` means saved-object and rule mutations are not recorded. There is no detection for "detection rules were deleted," which is the highest-value pre-attack action available.
- **Evidence**:
  - `siem/kibana/kibana.yml:2,10-12` — `server.host: "0.0.0.0"` and the comment `"this Kibana runs in unsecured mode for lab use"`
  - `docker-compose.yml:411-412` — `ports: - "${KIBANA_PORT:-5601}:5601"`
  - `scripts/setup/compile_sigma.sh:71-75` — `curl -fsS -X POST "$KIBANA_URL/api/detection_engine/rules" -H 'kbn-xsrf: true'` with no auth header
- **Recommendation**: Bind to loopback (`"127.0.0.1:${KIBANA_PORT:-5601}:5601"`). If Kibana must be reachable by other machines, enable ES security and set `elasticsearch.username`/`elasticsearch.password`; then add an API-key or basic-auth header to `compile_sigma.sh:71`. Also set `logging.root.level: info` so saved-object mutations are at least logged.

---

**[HIGH] Unauthenticated UDP syslog ingest lets any lab container forge alerts with an attacker-chosen `source.ip`**
- **MITRE ATT&CK**: T1036 (Masquerading), T1565.001 (Stored Data Manipulation), T1211 (Exploitation for Defense Evasion)
- **Red Team**: The syslog input accepts unauthenticated UDP on 5514 from any source with no allowlist. Every field the detection logic keys on comes from that untrusted datagram: `program`, `syslog_message`, `host.name`, and the timestamp. An attacker sends `<38>Aug 13 10:00:00 victim-web sshd[1]: Failed password for root from 10.9.9.9` and the pipeline stamps `event.kind: alert`, `event.category: authentication`, `threat.technique.id: T1110`, and `source.ip: 10.9.9.9` — an IP of the attacker's choosing, on an alert-kind document, attributed to a host of the attacker's choosing. That poisons every IP-pivot dashboard and misdirects the analyst toward an innocent host. UDP means the datagram source is spoofable too, and the source is not used for attribution anyway since `[host][name]` is groked out of the message body. The red team already uses this exact channel (`base_campaign.py:146-176` ships attacker-authored JSON over `SOCK_DGRAM` with a caller-chosen `program`), so the path is live and proven. The port is not published to the host, which caps this at lab-net containers plus the host itself — that is the only thing keeping it out of CRITICAL. Note `block_ip.sh` is simulated (no `iptables`), so this does *not* chain into automated enforcement.
- **Blue Team**: Nothing distinguishes a forged datagram from a real one — no source allowlist, no `[observer][ingress]` provenance field, no cross-check between the datagram's network source and the groked `host.name`. Detection opportunity: alert when `host.name` from the message body disagrees with the syslog input's own `host` field (the sender address), which is a reliable forgery signal.
- **Evidence**:
  - `siem/logstash/pipelines/syslog.conf:11-16` — `syslog { port => 5514 }` with no `host` restriction
  - `siem/logstash/pipelines/syslog.conf:54-69` — `if [program] == "sshd" and [syslog_message] =~ /Failed/`, then `grok { match => { "syslog_message" => "from %{IP:[source][ip]}" } }` and `add_field => { "[event][kind]" => "alert" }`
  - `red-team/campaigns/base_campaign.py:158-172` — attacker container writes to `logstash:5514` over `SOCK_DGRAM`
- **Recommendation**: Preserve the input's own sender address before the grok overwrites attribution — copy it to `[observer][ingress][ip]` and add a `[log][provenance]: "untrusted-syslog"` tag on every `syslog-*` document. Restrict the input to the victim subnet if the lab layout permits. Most importantly, do not let a groked field named `[source][ip]` on a forgeable input share a name with sensor-derived `[source][ip]` in `suricata-*` — analysts and dashboards cannot tell them apart.

---

**[HIGH] Attacker-controlled `@timestamp` gives the attacker control of index routing (timestomping)**
- **MITRE ATT&CK**: T1070.006 (Timestomp), T1562.001 (Impair Defenses)
- **Red Team**: The `date` filter parses `syslog_timestamp` — extracted from the untrusted message body — into `@timestamp`, and the output builds the index name from that same `@timestamp` via `syslog-%{+YYYY.MM.dd}`. The attacker therefore chooses which index their events land in. Backdate by six days and the events land in an index that ILM deletes within 24 hours (`min_age: 7d`), destroying the evidence on a timer. Backdate or forward-date at all and the events fall outside the operator dashboard's 30-minute window (`siem/kibana/dashboards/README.md:7`), so a live attack renders as zero activity. Because `action.auto_create_index: true`, arbitrary historical and future index names are created on demand with no error. This also corrupts MTTD scoring, which the repo treats as the lab's primary metric.
- **Blue Team**: No guard against timestamp skew. Detection opportunity: compare `@timestamp` against Logstash's `event.ingested` and tag any document where the delta exceeds a few minutes. Neither field comparison nor `event.ingested` currently exists in the pipeline.
- **Evidence**:
  - `siem/logstash/pipelines/syslog.conf:24-27` — `date { match => ["syslog_timestamp", ...] target => "@timestamp" }`
  - `siem/logstash/pipelines/syslog.conf:78` — `index => "syslog-%{+YYYY.MM.dd}"`
  - `siem/elasticsearch/ilm/ilm-policy.json:14-17` — `"delete": { "min_age": "7d" }`
- **Recommendation**: Add `ruby { code => "event.set('[event][ingested]', LogStash::Timestamp.now)" }` before the `date` filter, keep the parsed value in `[event][created]` rather than `@timestamp`, and route the index off `event.ingested` so an attacker cannot select their own index. If `@timestamp` must carry the parsed value, add a post-`date` conditional that tags `_timestamp_skew` and rewrites `@timestamp` to ingest time when the delta exceeds 15 minutes.

---

**[HIGH] `event.dataset` is never set, so every panel of the headline operator dashboard is permanently empty**
- **MITRE ATT&CK**: N/A (defect producing a total visibility failure)
- **Red Team**: Nothing to exploit actively — the attacker simply is not seen. The operator watches a live dashboard that structurally cannot render data, so every campaign appears undetected. This is the most dangerous class of detection gap: silent, and indistinguishable from "no attack in progress."
- **Blue Team**: All three Lens panels in the Phase E1 dashboard filter on `event.dataset:suricata`, and no Logstash pipeline in the repo ever sets `[event][dataset]`. A repo-wide grep for `event.dataset` returns matches only in the dashboard NDJSON and documentation — never in `siem/logstash/pipelines/`. The suricata pipeline sets `[event][kind]`, `[event][category]`, `[observer][type]`, `[observer][name]` and a lab-local `[event][severity_label]`, but never `dataset`. The dashboard README even anticipates this failure ("If any panel shows 'No data' ... check that `event.dataset:suricata` actually matches your ingest") without noticing the pipeline does not produce the field at all.
- **Evidence**:
  - `siem/kibana/dashboards/operator-view.ndjson:2-4` — `event.dataset:suricata` and `event.dataset:suricata and event.kind:alert`
  - `siem/logstash/pipelines/suricata.conf:54-61` — the only `[event][*]` fields added are `kind` and `category`
  - `siem/kibana/dashboards/README.md:30-32` — claims "The Logstash pipeline ... produces these by default"
- **Recommendation**: Add `add_field => { "[event][dataset]" => "suricata" }` to the suricata filter (outside the `event_type == "alert"` guard so flow/dns/http events carry it too), and the matching `zeek` / `syslog` values in the other two pipelines. Then add a CI assertion in `tests/test_detection_ingest.py` that every field referenced by a dashboard NDJSON query is emitted by at least one pipeline — this class of bug will otherwise recur on the next dashboard edit.

---

**[HIGH] `if [_path] == "notice"` can never match, so no Zeek detection is ever labeled an alert**
- **MITRE ATT&CK**: N/A (detection logic false negative)
- **Red Team**: Port scanning, SSH lateral movement, and DNS exfiltration all trigger Zeek notices from this repo's own custom scripts — and every one of them lands in `zeek-*` with no `event.kind`, no `event.category`, and no alert semantics. Any query, dashboard, or scorer filtering on `event.kind:alert` misses 100% of Zeek detections. The attacker gets three detection capabilities neutralized for free.
- **Blue Team**: The `_path` key is a convention of the `json-streaming-logs` Zeek package and Corelight sensors; Zeek's base ASCII writer in JSON mode (`redef LogAscii::use_json = T`) writes only the log record's own fields and does not inject `_path`. Nothing in `blue-team/detection/zeek/` loads `json-streaming-logs`. The conditional therefore evaluates false for every event. The file input already provides a reliable discriminator — its `path` field — which the pipeline ignores. **This needs a one-line runtime confirmation** (`head -1` on `/var/log/zeek/notice.log` inside the container to check for a `_path` key); recommend `tester-debugger` before the fix lands.
- **Evidence**:
  - `siem/logstash/pipelines/zeek.conf:49-54` — `if [_path] == "notice" { ... add_field => { "[event][kind]" => "alert" } }`
  - `blue-team/detection/zeek/local.zeek:26` and `.../entrypoint.sh:32` — `redef LogAscii::use_json = T;` with no `json-streaming-logs` load
  - `siem/logstash/pipelines/zeek.conf:9-10` — the input enumerates `notice.log` explicitly, so `path` is available
- **Recommendation**: Replace the conditional with `if [path] =~ /notice\.log$/`, which keys off a field the file input always populates. Keep `_path` as a secondary `or` clause so the pipeline still works if the lab later adopts `json-streaming-logs`. Add an assertion to the integration test that `zeek-*` contains at least one `event.kind:alert` document after a port-scan campaign.

---

**[HIGH] Unbounded dynamic mapping with no field limit and no dead-letter queue lets one crafted event blind the SIEM**
- **MITRE ATT&CK**: T1562.001 (Impair Defenses: Disable or Modify Tools)
- **Red Team**: This failure mode is already documented in the repo as something that happened in practice — "Stale eve.json events ... trip an ES mapping conflict in Logstash that then rejects ALL subsequent alerts" — and it was worked around by truncating logs at startup rather than fixed at the mapping layer. The index template sets only ILM and replicas; it defines no `mappings` block, so dynamic mapping is fully enabled on attacker-influenced data. Suricata's EVE output carries `payload_printable`, `http_body_printable`, HTTP hostnames, URLs, DNS names and TLS SNI values straight from the wire. An attacker who gets a field typed one way in the first document of the day (a string where the next document has an object, or an array of mixed types) causes ES to reject every subsequent document for that field for the rest of the day — the SIEM goes dark, and Logstash has no dead-letter queue, so the rejected events are gone permanently. Field-count explosion is the same attack by a different route: no `index.mapping.total_fields.limit` is set, so the default 1000 can be exhausted deliberately.
- **Blue Team**: Rejections surface only as Logstash WARN log lines that nothing monitors, and `log.level: warn` in logstash.yml is the floor, so they are visible but unalerted. There is no healthcheck or dashboard panel for "ingest rejection rate," and the Logstash healthcheck only probes `/_node/pipelines`, which stays 200 while every document is being rejected downstream.
- **Evidence**:
  - `siem/elasticsearch/ilm/index-template.json:14-19` — `"template": { "settings": { ... } }` with no `mappings` and no `total_fields.limit`
  - `siem/logstash/logstash.yml:1-5` — no `dead_letter_queue.enable`, no `queue.type: persisted`
  - `docker-compose.yml:216-222` — the truncation workaround and its explanation
  - `blue-team/detection/suricata/suricata.yaml:47-56` — `payload: yes`, `payload-printable: yes`, `packet: yes`, `http-body-printable: yes`
- **Recommendation**: Add to `index-template.json`: `"index.mapping.total_fields.limit": 2000`, `"index.mapping.ignore_malformed": true`, and a `mappings` block with `"dynamic": "runtime"` (or explicit types for the ECS core fields plus `dynamic: false` for the rest) so a type conflict degrades one field instead of rejecting the document. Enable `dead_letter_queue.enable: true` in logstash.yml so rejected events are recoverable and countable. Then the `: > eve.json` truncation in compose becomes a convenience rather than the only thing preventing a total outage.

---

**[MEDIUM] No TLS on any SIEM data path**
- **MITRE ATT&CK**: T1040 (Network Sniffing), T1557 (Adversary-in-the-Middle)
- **Red Team**: Every SIEM hop is plaintext `http://` — Logstash→ES, Kibana→ES, blue-team dashboard→ES, scoreboard→ES, es-init→ES, and the red-team tagger→ES. An attacker with a foothold on lab-net (which the red-team container has by design, at `.10`) can sniff or ARP-spoof the `.50`/`.51`/`.52` triangle and read or modify alert traffic in flight. The lab ships an ARP-spoofing campaign and a MITM Suricata rule, so the capability is literally part of the curriculum. Since the payloads include Suricata's captured `payload_printable`, sniffed SIEM traffic yields the plaintext of everything Suricata already captured.
- **Blue Team**: Nothing detects SIEM-to-SIEM tampering. `validate-certs` is loaded in `local.zeek:14` but has nothing to validate because no lab TLS exists on these paths.
- **Evidence**:
  - `siem/logstash/pipelines/suricata.conf:77`, `.../zeek.conf:66`, `.../syslog.conf:77` — `hosts => ["http://elasticsearch:9200"]`
  - `siem/kibana/kibana.yml:5` — `elasticsearch.hosts: ["http://elasticsearch:9200"]`
  - `.env.example:60-61`
- **Recommendation**: The repo already has a working two-tier CA (`pki-init` in compose issues leaf certs). Issue an `elasticsearch.lab.local` leaf from it, set `xpack.security.http.ssl.enabled: true`, and point the four clients at `https://` with `ca-chain.cert.pem`. This converts an existing lab asset into a real control and gives students a genuine cert-validation exercise.

---

**[MEDIUM] `action.auto_create_index: true` allows index squatting on indices the scoreboard trusts**
- **MITRE ATT&CK**: T1565.001 (Stored Data Manipulation)
- **Red Team**: Combined with unauthenticated ES, any lab participant can `POST /red-team-events-2026.08.13/_doc` or `/ir-events-.../_doc` with forged content. The scoreboard joins MTTD/MTTA on `campaign_id` + `event_type` from exactly those indices, so scores are directly forgeable — a student can write `playbook_complete` documents to award themselves response points without running a playbook. Auto-create also means an attacker can pre-create an index whose name matches the template pattern but with a mapping that conflicts with what Logstash will write, poisoning the day's ingest before it starts.
- **Blue Team**: No index-creation auditing (see the audit-logging finding), and the index template applies only to indices created after it is installed, so a pre-created index silently misses ILM and never expires.
- **Evidence**:
  - `siem/elasticsearch/elasticsearch.yml:13` — `action.auto_create_index: true`
  - `siem/elasticsearch/ilm/index-template.json:2-8` — the five trusted patterns
  - `blue-team/response/playbook_engine.py:93-98` — scoreboard-trusted `ir-events-*` writes
- **Recommendation**: Restrict to the known patterns: `action.auto_create_index: "suricata-*,zeek-*,syslog-*,red-team-events-*,ir-events-*,.monitoring-*,-*"`. That preserves every legitimate write while blocking arbitrary index creation, and it is a one-line change with no workflow impact.

---

**[MEDIUM] Logstash monitoring API bound to 0.0.0.0:9600 with no authentication**
- **MITRE ATT&CK**: T1046 (Network Service Discovery), T1518 (Software Discovery)
- **Red Team**: `http.host: "0.0.0.0"` exposes the Logstash node API to every container on lab-net, including the attacker at `.10`, with no `api.auth.type` configured. `GET http://172.20.0.51:9600/_node/pipelines?graph=true` returns the pipeline graph — the attacker reads the blue team's entire ingest and tagging logic and learns exactly which conditions produce alerts (`program == "sudo"`, `/Failed/`, `_path == "notice"`) and therefore exactly how to avoid them. `/_node/stats` also reveals event throughput, which is a reliable oracle for whether an action was ingested at all.
- **Blue Team**: No access logging on the API, no allowlist. Detection opportunity: Zeek already sees lab-net HTTP, so a notice on any non-healthcheck source connecting to `:9600` is cheap and effective — it does not exist today.
- **Evidence**: `siem/logstash/logstash.yml:2` — `http.host: "0.0.0.0"`
- **Recommendation**: Set `api.http.host: "127.0.0.1"`. The compose healthcheck already probes `http://localhost:9600` from inside the container (`docker-compose.yml:398`), so loopback binding keeps the healthcheck working and removes lab-net reachability entirely. If cross-container access is ever needed, add `api.auth.type: basic` with credentials from `.env`.

---

**[MEDIUM] Grok on untrusted `message` with no timeout override or rate limiting enables ingest DoS**
- **MITRE ATT&CK**: T1499 (Endpoint Denial of Service), T1562.001 (Impair Defenses)
- **Red Team**: The syslog grok chains a lazy `%{DATA:program}`, an optional bracketed group, and a trailing `%{GREEDYDATA}` against a fully attacker-controlled string. A message padded with many `[` and `:` characters drives heavy backtracking in the Java regex engine. Logstash's default per-event grok timeout (30s) prevents a permanent hang, but 30 seconds of a worker thread per crafted event is more than enough — a modest UDP flood of crafted datagrams stalls the shared pipeline, and because all three `.conf` files load into a single pipeline from one config directory, stalling it also stops Suricata and Zeek ingestion. The attacker gets a window in which nothing at all reaches the SIEM. There is no `throttle` filter, no queue backpressure config, and the in-memory queue drops events silently under pressure.
- **Blue Team**: No detection for ingest stall. The Logstash healthcheck probes `/_node/pipelines`, which returns 200 for a stalled-but-alive pipeline, so the container stays "healthy" while dropping everything.
- **Evidence**:
  - `siem/logstash/pipelines/syslog.conf:20-22` — `%{SYSLOGTIMESTAMP:syslog_timestamp} %{HOSTNAME:[host][name]} %{DATA:program}(?:\[%{POSINT:pid}\])?: %{GREEDYDATA:syslog_message}`
  - `siem/logstash/logstash.yml:1-5` — no `queue.type`, no `pipeline.workers` tuning
- **Recommendation**: Add `timeout_millis => 2000` and `timeout_scope => "event"` to the grok, and anchor the pattern with `^`. Add a `throttle` filter keyed on the sender address (`before_count => -1, after_count => 500, period => 60`) that drops-and-tags excess syslog. Move the healthcheck to a throughput-aware probe against `/_node/stats/events` so a stalled pipeline reports unhealthy.

---

**[MEDIUM] ILM policy has no size-based condition, so a log flood exhausts disk before the 7-day delete can help**
- **MITRE ATT&CK**: T1499.001 (Endpoint DoS: OS Exhaustion Flood)
- **Red Team**: The policy's stated purpose is "so a long-running lab host does not fill its disk," but it only deletes on age with no rollover and no size cap — the `_meta` explicitly says "no rollover is required." An attacker flooding syslog (or generating high-volume alertable traffic) creates one enormous daily index that cannot be deleted for seven days. Full raw `message` content is retained with no `prune` or truncation, and Suricata's `payload`/`packet`/`http-body` options make each alert document large. When ES crosses the 95% flood-stage watermark it applies `index.blocks.read_only_allow_delete` to every index — the SIEM stops accepting data entirely and requires manual intervention to recover. This is a low-effort, high-impact way to blind the lab.
- **Blue Team**: No disk-usage alerting, no document-count monitoring, and the ES healthcheck accepts `yellow`, which a flood-stage cluster still reports.
- **Evidence**:
  - `siem/elasticsearch/ilm/ilm-policy.json:4` — `"delete lab telemetry indices 7 days after creation so a long-running lab host does not fill its disk ... no rollover is required"`
  - `siem/elasticsearch/ilm/ilm-policy.json:7-18` — hot phase has only `set_priority`; no `rollover`
- **Recommendation**: Add a `rollover` action to the hot phase with `max_primary_shard_size: 5gb` and `max_age: 1d`, switch the pipelines to write to a data stream or rollover alias, and shorten the delete `min_age` to `3d`. Separately add a `truncate { fields => ["message"] length_bytes => 8192 }` filter to the syslog pipeline so a single datagram cannot carry unbounded content into the index.

---

**[MEDIUM] The SIEM keeps no audit trail of its own access or modification**
- **MITRE ATT&CK**: T1070 (Indicator Removal), T1562.008 (Impair Defenses: Disable or Modify Cloud Logs)
- **Red Team**: An attacker who deletes indices, alters detection rules, or exfiltrates every stored alert leaves no record anywhere. Post-incident there is no way to establish what was read, changed, or destroyed — the forensic exercise the lab is built around has no evidence to work from for attacks against the SIEM itself. `logger.org.elasticsearch: WARN` further suppresses operational detail, and Kibana's `logging.root.level: warn` drops request-level logging.
- **Blue Team**: This is the enabling gap behind the CRITICAL and the Kibana finding — both are undetectable purely because nothing is recorded. ES audit logging requires `xpack.security.enabled: true`, so this cannot be fixed without also fixing authentication; the two changes go together.
- **Evidence**:
  - `siem/elasticsearch/elasticsearch.yml:17-18` — `logger.org.elasticsearch: WARN`
  - `siem/kibana/kibana.yml:9` — `logging.root.level: warn`
- **Recommendation**: When enabling ES security (see CRITICAL), also set `xpack.security.audit.enabled: true` and `xpack.security.audit.logfile.events.include: [access_denied, authentication_failed, run_as_denied, tampered_request, delete_index]`. In Kibana, set `logging.root.level: info`. Even without full security, raising both to `info` restores a minimal trail.

---

**[MEDIUM] Syslog detection logic has exploitable false negatives and forgeable false positives**
- **MITRE ATT&CK**: T1110 (Brute Force), T1548.003 (Sudo and Sudo Caching), T1053.003 (Cron)
- **Red Team**: Three separate evasions, all trivially reachable:
  1. The SSH rule requires the literal case-sensitive substring `Failed`. Real sshd emits `Invalid user admin from 10.0.0.5` for user enumeration, `Connection closed by authenticating user`, `error: maximum authentication attempts exceeded`, and `authentication failure` (lowercase) from PAM. A username-enumeration or key-based brute force therefore produces zero T1110 alerts.
  2. The sudo rule is an exact match on `program == "sudo"`. Escalation via `su`, `pkexec`, `doas`, or a systemd unit is invisible.
  3. `if [program] =~ /cron/` is unanchored, so an attacker who names a process `not-cron-really` or `cronjob-helper` both triggers a bogus T1053.003 tag and — more usefully — floods the analyst with false positives that bury real detections. The same trick works against the sudo and sshd rules to manufacture noise.
- **Blue Team**: No coverage for the sshd message variants, no baseline for expected `program` values, and no rate limiting on tag generation. Detection opportunity: match a set of sshd failure patterns rather than one substring, and alert on tag volume anomalies rather than individual tags.
- **Evidence**:
  - `siem/logstash/pipelines/syslog.conf:54` — `if [program] == "sshd" and [syslog_message] =~ /Failed/`
  - `siem/logstash/pipelines/syslog.conf:35` — `if [program] == "sudo"`
  - `siem/logstash/pipelines/syslog.conf:45` — `if [program] =~ /cron/`
- **Recommendation**: Broaden the sshd condition to `=~ /(?i)(failed password|invalid user|authentication failure|maximum authentication attempts)/`; extend the sudo condition to `in ["sudo", "su", "pkexec", "doas"]`; anchor the cron condition as `=~ /^(cron|crond|anacron)$/`. Add a test case per variant to `tests/test_detection_ingest.py`.

---

**[MEDIUM] Suricata captures raw payloads and credentials into an unauthenticated datastore**
- **MITRE ATT&CK**: T1552.001 (Unsecured Credentials: Credentials in Files), T1005 (Data from Local System)
- **Red Team**: The EVE config enables `payload: yes`, `payload-printable: yes`, `packet: yes`, `http-body: yes`, `http-body-printable: yes`. Every alerting flow's plaintext content — including the lab's own `admin`/`password123` credentials in HTTP form posts and the MySQL traffic those generate — is written into `suricata-*` verbatim, with no redaction in the Logstash filter. Combined with unauthenticated ES, a single `_search` returns a corpus of captured plaintext. In a shared-host deployment that includes other students' traffic.
- **Blue Team**: No redaction filter, no field-level access control (unavailable with security disabled), and 7-day retention of captured payloads. There is no detection for bulk `_search` retrieval.
- **Evidence**:
  - `blue-team/detection/suricata/suricata.yaml:47-56` — the full alert capture block
  - `siem/logstash/pipelines/suricata.conf:24-72` — no redaction, no `prune`, no `mutate { remove_field }` for payload fields
  - `.env.example:53-57` — the credentials that will appear in captures
- **Recommendation**: Add a `mutate { gsub => ["payload_printable", "(?i)(password|passwd|pwd|token|authorization)=[^&\s]+", "\1=[REDACTED]"] }` to the suricata filter, and drop `packet` (base64 full frames) from the EVE config unless a specific exercise needs it — `payload-printable` alone covers the teaching use case at a fraction of the exposure and index size.

---

**[LOW] Kibana has no `xpack.encryptedSavedObjects.encryptionKey`, so imported detection rules break on restart**
- **MITRE ATT&CK**: N/A (availability of detection capability)
- **Red Team**: Not directly exploitable, but an attacker who can restart or crash the Kibana container degrades detection capability persistently rather than temporarily.
- **Blue Team**: With the key unset, Kibana generates a random one at each startup and logs a warning. Saved objects with encrypted attributes — alerting/detection rules, which is exactly what `compile_sigma.sh REBASE=1` creates via `/api/detection_engine/rules` — become undecryptable after a restart, and the rules stop executing while still appearing present in the UI. This is a plausible contributor to the flakiness that prompted the "add retry loop to flaky sigma compile step" commit, though confirming that link requires runtime inspection — recommend `tester-debugger`.
- **Evidence**: `siem/kibana/kibana.yml:1-13` — the setting is absent from the complete file; `scripts/setup/compile_sigma.sh:67-76` — the rule import path
- **Recommendation**: Add `xpack.encryptedSavedObjects.encryptionKey` sourced from a new `.env` variable (32+ chars), generated by `scripts/lab/student-env.sh` alongside the existing `FLASK_SECRET_KEY` and `PLAYBOOK_AUTH_TOKEN`, which already follow exactly this pattern.

---

**[LOW] Syslog date patterns carry no year and no timezone**
- **MITRE ATT&CK**: T1070.006 (Timestomp) — minor contributing factor
- **Red Team**: RFC3164 timestamps have no year, so Logstash assumes the current one. Across a year boundary, December events are stamped with January's year and land in a future index. No `timezone` is specified either, so parsing follows the JVM default while `%{+YYYY.MM.dd}` index naming uses UTC — a fixed skew between event time and index bucket on any non-UTC host, which corrupts MTTD arithmetic near midnight.
- **Blue Team**: Nothing validates timestamp sanity. This compounds the attacker-controlled-`@timestamp` finding by making legitimate skew look normal.
- **Evidence**: `siem/logstash/pipelines/syslog.conf:24-27` — `match => ["syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss"]`
- **Recommendation**: Add `timezone => "UTC"` to the date filter and set `TZ=UTC` on the logstash service so parsing, index naming, and scoring all agree.

---

**[LOW] Legacy monitoring collection writes indices outside the lab's ILM template**
- **MITRE ATT&CK**: N/A
- **Red Team**: Minor — `.monitoring-*` indices reveal cluster topology and index names to any unauthenticated reader, adding reconnaissance value to the CRITICAL finding.
- **Blue Team**: `xpack.monitoring.collection.enabled` is the deprecated self-monitoring path in 8.x. The resulting `.monitoring-*` indices are not matched by the `aib-logs` template's five patterns, so they follow ES's built-in policy rather than lab retention, and they add continuous write load to a 1GB-heap node.
- **Evidence**: `siem/elasticsearch/elasticsearch.yml:10` — `xpack.monitoring.collection.enabled: true`; `siem/elasticsearch/ilm/index-template.json:2-8` — patterns exclude `.monitoring-*`
- **Recommendation**: Set to `false` unless the Stack Monitoring UI is part of an exercise. Nothing in the repo currently consumes it.

---

**[LOW] Suricata non-alert events are ingested without `observer` or `event.kind`, contradicting the pipeline's own uniformity claim**
- **MITRE ATT&CK**: N/A (data-model inconsistency causing query gaps)
- **Red Team**: Flow, DNS, HTTP and TLS records — the pivot data an analyst needs after an alert fires — carry no `observer.name` or `event.kind`. A hunt query scoped by `observer.name:suricata` silently excludes all of them, so the attacker's non-alerting activity is invisible to the most natural pivot.
- **Blue Team**: The file header asserts "Core fields are named identically across all three pipelines," listing `[event][kind]` and `[observer][*]` — but those are set only inside `if [event_type] == "alert"`. Zeek sets `observer` unconditionally, so the two indices genuinely disagree.
- **Evidence**:
  - `siem/logstash/pipelines/suricata.conf:54-61` — the `observer` fields are nested inside the alert guard
  - `siem/logstash/pipelines/zeek.conf:56-59` — Zeek sets them unconditionally
  - `siem/logstash/pipelines/suricata.conf:6-10` — the uniformity claim
- **Recommendation**: Move the `[observer][type]`/`[observer][name]` (and the new `[event][dataset]`) `add_field` calls out of the alert conditional to the top level of the suricata filter, matching zeek.conf's structure. Keep only `[event][kind]`/`[event][category]` inside the guard.

---

**[INFO] No secrets found in `siem/`; scope of what was checked**
A case-insensitive grep for `password|passwd|secret|api_key|apikey|token|bearer|credential|auth` across all of `siem/` returned only six hits, every one a comment or an ECS field name in `syslog.conf` (`event.category: authentication`, `ssh_auth_failure`, `T1110` commentary). No credentials, API keys, or tokens are committed in the SIEM configs. The weak credentials in the repo (`DB_ROOT_PASS=root`, `DB_PASS=password123` at `.env.example:53-57`) are deliberate victim-service credentials, documented as such, and outside this scope. The three dashboard NDJSON files were checked for embedded scripted/runtime fields and external URLs; they contain only `kuery`-language queries and index-pattern references.

**[INFO] Controls that are correctly implemented**
Config files are mounted `:ro` throughout (`docker-compose.yml:279, 368-369, 414`); the Suricata image is pinned to a manifest digest (`:188`); `lab-net` is `internal: true`; the ES healthcheck quoting bug was correctly fixed and documented (`:293-297`); the blue-team container's Docker-socket privilege is profile-gated and documented; `block_ip.sh` is explicitly simulated rather than a misleading no-op, which correctly prevents forged alerts from chaining into enforcement. `mutate` blocks with repeated `rename`/`add_field` keys were checked and are valid — Logstash deep-merges duplicate plugin attributes, so both renames apply.

**[INFO] Requires runtime verification**
Two items need execution to confirm and should go to `tester-debugger`: (1) whether Zeek's `LogAscii::use_json` output contains a `_path` key, which determines whether the HIGH Zeek finding is a total or partial failure; (2) the interaction between the compose entrypoint truncating `eve.json` at each Suricata start (`docker-compose.yml:222`) and the now-persistent sincedb (`suricata.conf:18`) — filewatch is expected to detect the shrink and reset to offset 0, but the combination of a persisted sincedb and an externally truncated file is worth a direct test given that duplicate ingestion previously corrupted MTTD scoring.

---

| Severity | Count | Top Finding |
|----------|-------|-------------|
| CRITICAL | 1 | Elasticsearch unauthenticated and published on `0.0.0.0:9200` — LAN-reachable cluster-admin, cross-student data destruction, no audit trail |
| HIGH | 6 | `event.dataset` never emitted by any pipeline while all three operator-dashboard panels filter on it — the headline dashboard is permanently empty |
| MEDIUM | 8 | No TLS on any SIEM data path, in a lab that ships a working CA and teaches ARP spoofing on the same network |
| LOW | 4 | Missing `xpack.encryptedSavedObjects.encryptionKey` — imported detection rules silently stop executing after a Kibana restart |
| INFO | 3 | No secrets committed in `siem/`; two items need runtime verification |
