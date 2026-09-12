# Blue-Team Security Audit — 2026-08-13

**Scope:** `blue-team/dashboard`, `blue-team/detection` (zeek, suricata, sigma), `blue-team/response` (playbooks, IR action scripts, engine), `blue-team/Dockerfile`, `blue-team/requirements.txt`. Adjacent files pulled in as evidence: `docker-compose.yml`, `scripts/setup/compile_sigma.sh`, `siem/logstash/pipelines/*`, `.env.example`, `forensics/scoreboard/sigma_eval.py`.
**Out of scope:** red-team campaigns, target-env, pki-lab, scoreboard app internals.
**Constraint:** static analysis only — Bash was unavailable, so nothing was executed. Items marked *(verify)* need `tester-debugger`.
**Baseline:** `docs/THREAT_MODEL.md` §4.1 already accepts the `docker.sock` mount on `blue-team` as a known HIGH. Findings below flag only the compounding factors that are *not* covered there.

**Summary: 40 findings — 1 CRITICAL, 8 HIGH, 15 MEDIUM, 13 LOW, 3 INFO.**
**Most important: the Sigma compile pipeline is invoking the wrong `sigma` binary** (the bioinformatics sequence-alignment tool, not `sigma-cli`); all 7 files in `blue-team/detection/sigma/compiled/` contain that tool's help text instead of EQL, the script exits 0, and the Kibana import path swallows every error — the SIEM detection layer deploys zero working rules with a green build.
Runner-up: the Zeek sensor sniffs `eth0` inside a Docker bridge network, so it sees essentially no peer-to-peer lab traffic — all three custom Zeek detections are inert while the container reports healthy.

---

## CRITICAL

---
**[CRITICAL] Sigma compile pipeline silently emits the wrong binary's help text as "compiled detections"**
- **MITRE ATT&CK**: T1562.001 (Impair Defenses — self-inflicted); detection coverage loss across T1041, T1053.003, T1110, T1204, T1486, T1548.003, T1557
- **Red Team**: Every technique the Sigma layer is supposed to catch runs undetected in Kibana, and the build reports success. An attacker doesn't even need to evade — nothing is deployed.
- **Blue Team**: No output validation between compile and deploy. There is no assertion that the artifact is JSON, no check that `sigma --version` is `sigma-cli`, and CI added a retry loop (commit `7bacb08 ci: add retry loop to flaky sigma compile step`) that makes a deterministic failure look intermittent.
- **Evidence**: All 7 files in `blue-team/detection/sigma/compiled/` begin:
  `blue-team/detection/sigma/compiled/exfil_https.eql.json:1` — `Sigma, version 1.1.3: simple greedy multiple alignment` / `Copyright (C) 2006-2009 Rahul Siddharthan <rsidd@imsc.res.in>`
  That is the Debian `sigma` bioinformatics package, not `sigma-cli`. The guard at `scripts/setup/compile_sigma.sh:31` only checks `command -v sigma >/dev/null` — the wrong binary satisfies it, `sigma convert ...` prints usage and exits 0, and `> "$out"` (line 64) captures it under `set -euo pipefail` without tripping.
  The Kibana import stage double-masks it: `compile_sigma.sh:75` — `|| echo "  [warn] import failed for $(basename "$compiled") (may already exist)"` reports every 400 as benign.
- **Recommendation**: Replace the `command -v` guard with a positive identity check (`sigma --version 2>&1 | grep -q '^sigma-cli'` or invoke `python -m sigma.cli`); after each convert, assert the output parses as JSON and is non-empty (`jq -e . "$out" >/dev/null`) and fail the loop otherwise; drop `|| echo warn` on the Kibana POST in favour of `-f` + explicit `409` handling; remove the CI retry loop so this fails loudly.
---

## HIGH

---
**[HIGH] Zeek sniffs a bridge-attached `eth0` and therefore sees almost no lab traffic**
- **MITRE ATT&CK**: T1046, T1048.003, T1021.004, T1550.002 (all uncovered)
- **Red Team**: Attacker→victim unicast between `172.20.0.10` and `.30` is forwarded by the Linux bridge only to the destination's veth port. Zeek's container receives broadcast/multicast and its own traffic only. Port scans, DNS tunnelling and internal SSH/SMB never reach the sensor; `conn.log` will be near-empty while the container is `healthy`.
- **Blue Team**: `port_scan.zeek`, `dns_exfil.zeek`, `lateral_movement.zeek` are all inert, and `siem/logstash/pipelines/zeek.conf` ingests empty logs — no alarm distinguishes "no attacks" from "no visibility". Suricata gets this right and the contrast is the proof.
- **Evidence**: `docker-compose.yml:248-264` — zeek is `networks: lab-net: ipv4_address: ...53` with `ZEEK_IFACE=eth0`; `blue-team/detection/zeek/entrypoint.sh:37-39` — `IFACE="${ZEEK_IFACE:-eth0}"` … `exec zeek -i "$IFACE"`.
  Compare `docker-compose.yml:190` (`network_mode: "host"`) and `:230` where Suricata deliberately auto-detects the `br-*` bridge master: `IFACE=$$(ip -o -4 addr show ... '$$4 ~ "^"ip {print $$2; exit}')`.
- **Recommendation**: Move zeek to `network_mode: host` with `NET_RAW`/`NET_ADMIN` and reuse Suricata's bridge auto-detect to set `ZEEK_IFACE=br-<lab-net>`. Add a startup assertion (fail the healthcheck if `conn.log` has zero entries after N seconds of known lab traffic). *(verify: inspect `zeek-logs` volume `conn.log` after a campaign run.)*
---

**[HIGH] Two playbooks isolate a host and never restore it, violating their own stated invariant**
- **Red Team**: Not attacker-driven — this is self-inflicted denial of service. Running the ransomware or data-exfil playbook strands the victim on `quarantine-net` permanently; the next exercise starts against a host that is off the lab network, and the strand is invisible until someone reads `isolation_log.json`.
- **Blue Team**: No reconciliation loop and no alert on "host still quarantined after playbook completion".
- **Evidence**: `blue-team/response/playbooks/ransomware_ir.yml:17-22` isolates (`script: isolate_host.sh`, `args: ["{affected_host}"]`, `required: true`) and the file ends at line 66 with no `restore_host.sh` step. Same in `blue-team/response/playbooks/data_exfil_ir.yml:39-43`, file ends line 53.
  The invariant is written down in `blue-team/response/playbooks/lateral_movement_ir.yml:64-66`: *"OQ-3 (ADR 0001): every playbook that isolates a host must restore it before the playbook terminates."*
- **Recommendation**: Append the `restore_host.sh` step to both playbooks (mirroring `lateral_movement_ir.yml:67-71`), and add a CI test that asserts every playbook containing `isolate_host.sh` also contains `restore_host.sh` for the same `{var}`.
---

**[HIGH] `restore_host.sh` is non-idempotent and aborts before undoing quarantine**
- **Red Team**: Any container already attached to `lab-net` — including one left in the half-isolated state described below — can never be restored by the shipped tool. Recovery requires manual `docker network` surgery an operator under incident pressure may not know.
- **Blue Team**: The failure surfaces only as a non-zero return code inside the playbook log; nothing alerts on "restore failed, host still quarantined".
- **Evidence**: `blue-team/response/actions/restore_host.sh:8` `set -euo pipefail`, then line 20 `docker network connect "$LAB_NET" "$TARGET"` — this errors with *"endpoint already exists in network"* if the host is already on `lab-net`, and `set -e` exits **before** line 23 `docker network disconnect "$QUARANTINE_NET" "$TARGET" || true`. Note the defensive `|| true` is on the wrong line.
  The half-isolated state is produced by `blue-team/response/actions/isolate_host.sh:25,28` — connect-then-disconnect with no rollback: if line 28 fails, the host sits on both networks and `set -e` exits.
- **Recommendation**: Make both scripts idempotent — tolerate "already connected"/"not connected" (`docker network connect ... 2>/dev/null || true` guarded by a `docker network inspect` membership check), and wrap `isolate_host.sh` in a trap that reconnects `LAB_NET` if the disconnect fails.
---

**[HIGH] `isolate_host.sh` accepts any container name — including the SIEM and itself**
- **MITRE ATT&CK**: T1489 (Service Stop) via misuse of a legitimate admin tool
- **Red Team**: Anyone holding `PLAYBOOK_AUTH_TOKEN` (or any operator typo) can quarantine `elasticsearch`, `logstash` or `kibana`, destroying the SIEM mid-incident — a defence-evasion primitive delivered by the defenders' own tooling. Isolating `blue-team` severs the dashboard that would undo it.
- **Blue Team**: No allowlist, no confirmation prompt, no "this is an infrastructure container" guard, and no SIEM event for the action (see the logging finding below).
- **Evidence**: `blue-team/response/actions/isolate_host.sh:15,25,28` — `TARGET="${1:-}"`; the only check is `[[ -z "$TARGET" ]]` at line 19. `TARGET` goes straight to `docker network connect "$QUARANTINE_NET" "$TARGET"`.
  Secondary: a `TARGET` beginning with `-` reaches `docker`'s pflag parser as a flag (CWE-88 argument injection). The dashboard blocks this at `blue-team/dashboard/app.py:176` (`_SAFE_HOST_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,252}\Z")`), but the scripts' own documented usage (`bash isolate_host.sh <container_name>`, line 7) has no such guard.
- **Recommendation**: In the script, validate against the same charset regex, reject a leading `-`, insert `--` before positionals (`docker network connect "$NET" -- "$TARGET"`), and add a denylist of infrastructure services (`elasticsearch`, `logstash`, `kibana`, `blue-team`, `scoreboard`) resolved via `com.docker.compose.service` labels.
---

**[HIGH] Suricata forces stream checksum validation on a veth/bridge capture** *(verify)*
- **MITRE ATT&CK**: Blind to anything requiring stream reassembly — T1190, T1110, T1566.001, T1041
- **Red Team**: Container-generated packets carry offloaded (unfilled) checksums when captured off the bridge. With validation forced on, the stream engine discards them, so no TCP reassembly happens and every `http`/`smtp` rule silently stops matching. The attacker gets full app-layer coverage loss for free.
- **Blue Team**: Nothing monitors Suricata's `stats.log` invalid-checksum counters, so the sensor looks healthy.
- **Evidence**: `blue-team/detection/suricata/suricata.yaml:118` — `checksum-validation: yes` under `stream:`. The `af-packet` block (lines 85-91) sets no `checksum-checks`, so only the stream engine is forced.
- **Recommendation**: Set `checksum-validation: no` (standard for virtualized/offloaded capture) and add a startup check on `stats.log` for `tcp.invalid_checksum`. *(verify: `suricata --dump-config | grep checksum` plus the `stats.log` counters during a campaign.)*
---

**[HIGH] The DNS-tunnel Suricata rule cannot match — two independent logic errors**
- **MITRE ATT&CK**: T1048.003 (network-side detection absent)
- **Red Team**: DNS exfiltration produces no Suricata alert. Combined with the Zeek blindness above, the entire network-side DNS-tunnel detection path is gone; only the red team's own syslog advisory produces a "detection".
- **Blue Team**: No rule-firing regression test (a pcap replay) exists, so a rule that has never fired is indistinguishable from a rule with nothing to catch.
- **Evidence**: `blue-team/detection/suricata/local.rules:45` —
  `alert dns any any -> any 53 (... content:"|01 00 00 01 00 00 00 00 00 00|"; depth:10; pcre:"/^[a-z2-7]{30,}\./"; ... sid:1000050;)`
  (1) The 10-byte content begins at DNS header offset 2 and therefore ends at offset 12, but `depth:10` requires the whole match inside the first 10 bytes — unsatisfiable. (2) The `^`-anchored pcre is evaluated against the payload start (the binary DNS header), not the QNAME, so it can never match a base32 label.
- **Recommendation**: Drop the raw `content`/`depth` pair and rewrite against the sticky buffer: `dns.query; content:"."; pcre:"/^[a-z2-7]{30,}\./";` (or `dns.query; bsize:>50;`). Add a pcap-replay test to CI for every sid.
---

**[HIGH] Two SSH rules generate per-packet alert storms and are mislabelled**
- **MITRE ATT&CK**: T1499 (self-inflicted), enabling T1562 by alert-fatigue burial
- **Red Team**: `sid:1000042` has no `flow`, no `content` and no `threshold`, so it alerts on *every packet* of every internal SSH session. An attacker can trivially flood `eve.json` with a benign SSH loop, burying real alerts and blowing out the disk under a bind-mounted log directory.
- **Blue Team**: No `threshold.config`, no rate-limiting, no eve.json size monitoring.
- **Evidence**: `blue-team/detection/suricata/local.rules:32` — `alert tcp $HOME_NET any -> $HOME_NET 22 (msg:"... Internal SSH Connection - Possible Hijacking"; classtype:policy-violation; sid:1000042; rev:1;)` — no qualifiers at all.
  Line 31 — `alert tcp any any -> $HOME_NET 22 (msg:"... Multiple SSH Authentication Failures"; threshold:type both,track by_src,count 5,seconds 30; ...)` — has no content match, so it counts *packets*, not auth failures. A single legitimate SSH login exceeds 5 packets, so this fires on every SSH connection while never actually detecting brute force.
- **Recommendation**: Add `flow:established,to_server;` plus `threshold:type limit,track by_src,count 1,seconds 300;` to sid:1000042. Rewrite sid:1000041 against the real signal — Logstash already extracts it at `siem/logstash/pipelines/syslog.conf:54-69` (`sshd` + `/Failed/` → `T1110`); delete the network rule or key it on `ssh.protoversion`/repeated connection teardown.
---

**[HIGH] Dashboard silently serves fabricated alerts when Elasticsearch is unreachable**
- **MITRE ATT&CK**: Masks T1562.001 (Impair Defenses) — a SIEM outage is indistinguishable from normal operation
- **Red Team**: Kill or partition Elasticsearch (or simply let it OOM against its `mem_limit: 2g`) and the SOC dashboard keeps showing five plausible, colour-coded alerts. Analysts triage fiction while the real attack runs unlogged. No banner, no status change, no HTTP error.
- **Blue Team**: The failure path is a bare `except Exception: pass`. There is no health indicator on the page, no `[i] demo data` badge, and no log line.
- **Evidence**: `blue-team/dashboard/app.py:204-215` —
  ```python
  try:
      resp = requests.get(f"{ELASTICSEARCH_URL}/red-team-events-*/_search?size=50", timeout=3)
      if resp.ok: ...
  except Exception:
      pass
  return DEMO_ALERTS
  ```
  `DEMO_ALERTS` (lines 76-132) are indistinguishable from live data in the UI — realistic techniques, IPs and severities, only the 2024 timestamps hint at it.
- **Recommendation**: Return `(alerts, source)` and render an unmissable `SIEM UNREACHABLE — SHOWING DEMO DATA` banner in `index.html`/`alerts.html`; make `/api/stats` include `"source": "demo"|"elasticsearch"`; log the exception at `ERROR`. Consider gating demo data behind an explicit `DEMO_MODE=1`.
---

## MEDIUM

---
**[MEDIUM] Every Sigma rule keys on a literal marker the attacker chose to emit**
- **MITRE ATT&CK**: T1041, T1110, T1204, T1486, T1557 — all "covered" tautologically
- **Red Team**: Detection depends entirely on the red-team campaign self-reporting. Change the marker string, the file path, or suppress the syslog advisory and coverage drops to zero while the technique still succeeds. The red team effectively controls the blue team's score.
- **Blue Team**: No behavioural fallback — no file-rename-burst rule for T1486, no auth-failure-rate rule for T1110, no duplicate-MAC rule for T1557.
- **Evidence**: `blue-team/detection/sigma/impact_ransomware.yml:23-28` requires `'.locked'`/`'ransom_note.txt'` **and** `'/tmp/ransom-decoys'`; `malware_drop_eicar.yml:26-27` requires `'/tmp/lab_malware_drop.eicar'`; `mitm_arp_spoof.yml:29-31` requires `'/tmp/lab_mitm.log'`; `exfil_https.yml:19-26` requires `'https_exfil_simulation'` **and** `'python-requests'`.
  The matching emitters confirm the coupling: `red-team/campaigns/exfiltration/https_exfil.py:55-57` (`"signature": "https_exfil_simulation"`, `"user_agent": "python-requests/2.34"`), `red-team/campaigns/credential_access/brute_force.py:101-102` (`"authentication failed -- Invalid credentials"`, `"params": "username=admin&password=REDACTED"`).
- **Recommendation**: Keep the marker rules for scoreboard wiring, but ship a second, path-independent rule per technique (extension-change burst, auth-failure rate, DNS label-entropy) and score those separately. Document explicitly which rules are lab-instrumentation vs. real detection.
---

**[MEDIUM] Any container on lab-net can inject arbitrary events into the SIEM's detection path**
- **MITRE ATT&CK**: T1565.001 (Stored Data Manipulation), T1070 (Indicator Removal)
- **Red Team**: `logstash:5514` accepts syslog from every container on `lab-net`, including `red-team` and any compromised victim. Because the scoreboard evaluates Sigma rules directly against `syslog-*`, an attacker can forge detections (inflating the blue score), flood to bury genuine advisories, or inject strings that trip `privesc_sudo.yml` for false positives that subtract from the score.
- **Blue Team**: No source-IP allowlist on the syslog input, no separate trusted-vs-untrusted index, no volume anomaly detection.
- **Evidence**: `siem/logstash/pipelines/syslog.conf:11-16` — `input { syslog { port => 5514 type => "syslog" } }` with no host filter; every service sits on the same `lab-net` (`docker-compose.yml:18-24`). Matching is unanchored substring: `forensics/scoreboard/sigma_eval.py:55` — `return any(str(kw).lower() in low for kw in selection)`.
- **Recommendation**: Add a Logstash `if ![host][ip] in [<allowed>] { drop {} }` guard or route untrusted advisories to a distinct index (`syslog-untrusted-*`) that the scorer treats separately; tag events with the observed source IP and require it to match the expected emitter.
---

**[MEDIUM] The shipped playbook UI never sends the auth token — `/api/run-playbook` always returns 401**
- **Red Team**: Not directly exploitable, but a control that breaks the documented workflow invites an operator to blank `PLAYBOOK_AUTH_TOKEN` or patch out `_playbook_auth_ok` — turning a fail-closed design into an open RCE-adjacent endpoint on a container holding `docker.sock`.
- **Blue Team**: No test covers the browser path; `tests/test_dashboard_security.py` exercises the API with explicit headers only, so the gap is invisible to CI.
- **Evidence**: `blue-team/dashboard/templates/playbooks.html:49-52` —
  `fetch('/api/run-playbook', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: ... })` — no `X-Auth-Token`, no `Authorization`. The server requires one at `blue-team/dashboard/app.py:59-66`.
- **Recommendation**: Add a token field to the page (operator pastes it per session into `sessionStorage`) and send it as `X-Auth-Token`; do **not** template the token into the HTML, which would expose it to anyone who can load the page. Add a Playwright/requests test that drives the documented UI path end to end.
---

**[MEDIUM] Malformed alert documents crash the dashboard (Jinja `UndefinedError` → HTTP 500)**
- **MITRE ATT&CK**: T1499 (Endpoint Denial of Service)
- **Red Team**: Index one document into `red-team-events-*` without a `technique` field (or with an integer one) and both the index and alerts pages return 500. Elasticsearch has `xpack.security.enabled=false` and port 9200 is published, so writing that document requires no credentials.
- **Blue Team**: No error handler, no defensive default, no template-render alerting.
- **Evidence**: `blue-team/dashboard/templates/index.html:73` — `href="https://attack.mitre.org/techniques/{{ alert.technique.replace('.', '/') }}/"`; identical at `blue-team/dashboard/templates/alerts.html:36`. Data comes straight from ES via `app.py:211` — `return [h["_source"] for h in hits]` — with no schema validation.
- **Recommendation**: Use `{{ alert.technique|default('')|string|replace('.', '/') }}` and wrap the row in `{% if alert.technique %}`; normalise/validate documents in `get_alerts()` before rendering; register a Flask `errorhandler(500)`.
---

**[MEDIUM] No logging, no rate limiting, and no auth on the dashboard's read surface**
- **MITRE ATT&CK**: T1110.001 (Password Guessing against the token), T1213 (Data from Information Repositories)
- **Red Team**: `PLAYBOOK_AUTH_TOKEN` can be brute-forced at full speed with zero forensic trace — there is no app logger, no failed-auth counter, and no lockout. `/`, `/alerts`, `/api/alerts`, `/api/stats` are fully unauthenticated and disclose the SIEM's alert corpus, internal IPs and technique coverage to anyone who can reach port 5000.
- **Blue Team**: The one genuinely privileged endpoint is gated but not *observed*. `hmac.compare_digest` correctly prevents timing attacks, but nothing records that a guess occurred.
- **Evidence**: `blue-team/dashboard/app.py:249-253` — the 401 path returns `jsonify({"success": False, "error": "unauthorized"}), 401` with no logging. There is no `logging` import anywhere in the file; `app.run(host="0.0.0.0", port=5000, debug=False)` at line 301 leaves only ephemeral Werkzeug stderr.
- **Recommendation**: Log every `/api/run-playbook` attempt (source IP, outcome, `playbook_id`, context) at `WARNING` on failure and ship it to `ir-events-*`; add Flask-Limiter (e.g. 5/min per IP) on the endpoint; put the read pages behind the same token or bind them to localhost.
---

**[MEDIUM] Compounding factors on the accepted `docker.sock` risk: 0.0.0.0 binding, root user, writable app mount**
- **MITRE ATT&CK**: T1610 (Deploy Container) / T1611 (Escape to Host) post-RCE
- **Red Team**: `docs/THREAT_MODEL.md` §4.1 accepts the socket mount, but three details widen it beyond what's documented: (1) the port is published on all host interfaces, so the dashboard is reachable from the operator's entire LAN, not just localhost; (2) the container runs as root — no `USER` directive — so socket access is unconstrained; (3) `./blue-team:/app` is mounted read-write, so any file-write primitive lets an attacker persist a webshell into the host's git working tree, surviving `docker compose down`.
- **Blue Team**: No socket proxy filtering the Docker API surface (the IR scripts need only `network connect`/`disconnect` and `ps`/`exec`), and no filesystem-integrity check on `/app`.
- **Evidence**: `docker-compose.yml:96-97` — `ports: - "${BLUE_TEAM_PORT:-5000}:5000"`; line 104 — `- ./blue-team:/app`; line 109 — `- /var/run/docker.sock:/var/run/docker.sock`; lines 110-112 `cap_add: - NET_ADMIN`. `blue-team/Dockerfile` has no `USER` directive (ends at line 37 with `CMD ["python", "dashboard/app.py"]`).
- **Recommendation**: Bind to loopback (`"127.0.0.1:${BLUE_TEAM_PORT:-5000}:5000"`); add `USER 1000:1000` to the Dockerfile and grant socket access via a `docker-socket-proxy` restricted to `NETWORKS=1`, `CONTAINERS=1`, `EXEC=1`; mount `./blue-team:/app:ro` and write only to `/evidence`.
---

**[MEDIUM] The attacker container has read-write access to the blue team's evidence store**
- **MITRE ATT&CK**: T1070.004 (File Deletion), T1565.001 (Stored Data Manipulation)
- **Red Team**: `red-team` mounts the same `./evidence` directory read-write as `blue-team`. A campaign (or a student with shell in the attacker container) can delete `isolation_log.json`, rewrite `playbook_*.json` execution logs, alter collected artifacts, and recompute `manifest.json` hashes to match — anti-forensics that defeats the collector's own chain of custody, because the manifest lives inside the directory it attests to.
- **Blue Team**: `forensics/chain_of_custody.py --hash-dir evidence/` (THREAT_MODEL §4.3) partially mitigates, but it is an after-the-fact manual step; nothing detects mid-exercise tampering, and `collect_evidence.py` hashes the *copy*, not the source, so copy-time substitution is invisible.
- **Evidence**: `docker-compose.yml:57-59` — red-team `volumes: - ./red-team:/app` / `- ./evidence:/evidence` (no `:ro`); `docker-compose.yml:105` — blue-team `- ./evidence:/evidence`. `blue-team/response/actions/collect_evidence.py:56-57` — `shutil.copy2(src, dest)` then `sha256_file(dest)`; `manifest.json` is written to `session_dir` (line 64), i.e. inside the attacker-writable tree.
- **Recommendation**: Split the mounts — give red-team a separate `./evidence/red-drop` (or drop the mount entirely) and keep `./evidence` blue-only; hash the *source* at read time in `collect_evidence.py`; write `manifest.json` outside `session_dir` and emit each artifact hash to `ir-events-*` at collection time so a later local edit is detectable.
---

**[MEDIUM] Containment actions are never emitted to the SIEM and carry no operator attribution**
- **MITRE ATT&CK**: Detection gap for T1489 / abuse of legitimate admin tooling
- **Red Team**: An adversary who obtains the playbook token can quarantine hosts, and the only record is a file inside the container that `scripts/lab/reset.sh` clears. Nothing in Elasticsearch shows *who* isolated *what*.
- **Blue Team**: `${USER:-unknown}` is unset in container processes, so every entry reads `"operator":"unknown"`. Only an aggregate `playbook_complete` document reaches ES — individual containment actions do not.
- **Evidence**: `blue-team/response/actions/isolate_host.sh:33` — `{"timestamp":"...","action":"isolate","host":"$TARGET","operator":"${USER:-unknown}"}`; identical at `restore_host.sh:28`. The only SIEM emission is `blue-team/response/playbook_engine.py:83-100` (`_emit_ir_event`, `event_type: playbook_complete`), which carries no per-action detail.
- **Recommendation**: Pass an explicit `IR_OPERATOR` env var from the dashboard (derived from the authenticated request) into the scripts, and POST an `ir-events-*` document per containment action with `action`, `target`, `operator`, `source_ip` and `campaign_id`.
---

**[MEDIUM] Silent-failure `except` blocks hide the IR telemetry and SIEM paths**
- **Red Team**: If `ir-events-*` writes fail (ES down, network partition, index blocked), the response score silently reads zero and no one learns why — the same class of bug the code comment says it was written to fix.
- **Blue Team**: A bare `except Exception: pass` around the audit emission means the audit trail's own failure is unauditable.
- **Evidence**: `blue-team/response/playbook_engine.py:94-100` —
  ```python
  resp = requests.post(f"{ELASTICSEARCH_URL}/{index}/_doc", json=doc, timeout=3)
  resp.raise_for_status()
  except Exception:
      pass
  ```
  Same pattern at `blue-team/dashboard/app.py:213-214`.
- **Recommendation**: Catch `requests.RequestException` specifically, log at `WARNING` with the exception, and surface an `ir_event_emitted: false` flag in the playbook summary returned to the UI.
---

**[MEDIUM] `sudo` and `crontab` Suricata rules are simultaneously false-positive machines and structurally unable to detect the technique**
- **MITRE ATT&CK**: T1548.003, T1053.003 — neither is actually covered
- **Red Team**: Real sudo/cron abuse happens over encrypted SSH or locally, so the payload never appears on the wire; the rules can never fire on the technique. Meanwhile `content:"-l"` is a two-byte match against any internal TCP stream — an attacker can deliberately generate matching cleartext traffic to flood the analyst queue.
- **Blue Team**: The real coverage already exists host-side (`siem/logstash/pipelines/syslog.conf:35-51` tags `sudo` → T1548.003 and `cron` → T1053.003); these network rules add only noise.
- **Evidence**: `blue-team/detection/suricata/local.rules:25` — `alert tcp $HOME_NET any -> $HOME_NET any (... content:"sudo"; content:"-l"; ... sid:1000030;)`; line 53 — `alert tcp $HOME_NET any -> $HOME_NET any (... content:"crontab"; ... sid:1000060;)`. No `flow`, no buffer, no threshold on either.
- **Recommendation**: Delete both and document that T1548.003/T1053.003 are host-telemetry detections (syslog + the Sigma rules), not network detections. If kept for teaching, add `flow:established,to_server;` and a comment marking them reference-only, as was done for the `$EXTERNAL_NET` rules at lines 37-48.
---

**[MEDIUM] Pass-the-Hash rule matches SMB1 only**
- **MITRE ATT&CK**: T1550.002
- **Red Team**: Any SMB2/SMB3 client (i.e. everything modern, `|FE|SMB`) evades the rule entirely. The rule's own `depth:5` pins it to the SMB1 header.
- **Blue Team**: No SMB2/3 signature, and no `smb` entry in the `app-layer` protocol list in `suricata.yaml` (lines 135-185) — so Suricata isn't even decoding SMB for `smb.*` keywords.
- **Evidence**: `blue-team/detection/suricata/local.rules:30` — `alert tcp any any -> $HOME_NET 445 (... content:"|FF|SMB"; depth:5; ... sid:1000040;)`.
- **Recommendation**: Add a paired rule with `content:"|FE|SMB"; depth:5;` and enable `smb:` under `app-layer.protocols` in `suricata.yaml`, then key on `smb.ntlmssp_user`/session-setup patterns rather than the raw header.
---

**[MEDIUM] DNS version-scan rule is structurally dead**
- **MITRE ATT&CK**: T1046 / T1590
- **Red Team**: The rule requires a DNS transaction ID of `0x0000` to match, which effectively never occurs — DNS recon goes undetected.
- **Blue Team**: Same missing pcap-replay regression test as sid:1000050.
- **Evidence**: `blue-team/detection/suricata/local.rules:11` — `alert udp any any -> $HOME_NET 53 (... content:"|00 00 10 00 01|"; depth:5; ... sid:1000003;)`. The intended qtype=TXT/qclass=IN bytes sit at the *end* of the question section, not within the first 5 bytes; `depth:5` forces the match into the transaction-ID/flags region.
- **Recommendation**: Rewrite using app-layer keywords: `dns.query; content:"version.bind"; nocase;` combined with `dns.opcode` / qtype matching, and drop the raw-offset form.
---

**[MEDIUM] HTTP attack rules inspect only the URI, and HTTP is decoded on port 80 alone**
- **MITRE ATT&CK**: T1190, T1110
- **Red Team**: SQLi and XSS delivered in a POST body — which is exactly how the lab's own login form works (`DEMO_ALERTS` even describes *"SQL injection payload detected in login form"*) — never touch `http_uri` and are missed. `..%252f` survives because double-decoding is disabled. Any HTTP service on 8080/8000 isn't parsed as HTTP at all, so every `alert http` rule is inert against it.
- **Blue Team**: No `http.request_body` / `http.uri.raw` coverage; no negative-test corpus proving which encodings are caught.
- **Evidence**: `blue-team/detection/suricata/local.rules:17-20` — all four rules use `http_uri` (`content:"' OR"; http_uri;`, `content:"<script>"; http_uri;`, `content:"../"; http_uri;`, `content:"UNION SELECT"; http_uri;`). `blue-team/detection/suricata/suricata.yaml:17` — `HTTP_PORTS: "80"`; line 167 — `double-decode-path: no`.
- **Recommendation**: Duplicate each rule against `http.request_body` (with `http-body-inline` already enabled at line 161); broaden `HTTP_PORTS` to `"[80,8000,8080,8888]"`; enable `double-decode-path`/`double-decode-query` or add explicit `..%25` content matches. Note in the rule comments that `' OR` misses `'/**/OR` and `'||` — these are teaching rules, not comprehensive ones.
---

**[MEDIUM] Port-scan detection is evadable by timing and by non-SYN scan types**
- **MITRE ATT&CK**: T1046, T1595
- **Red Team**: `nmap -sF` / `-sN` / `-sX` / `-sA` set no SYN flag and bypass both Suricata rules. `flags:S` is an exact-match (SYN and nothing else), so even SYN+ECE/CWR evades. `nmap -T2 --scan-delay 3s` stays under both the 20-in-1s and 10-in-5s thresholds and under Zeek's 15-ports-in-30s.
- **Blue Team**: No slow-scan aggregation over a longer epoch, no FIN/NULL/XMAS signature, no `stream-event` rules.
- **Evidence**: `blue-team/detection/suricata/local.rules:9-10` — `flags:S; threshold:type threshold,track by_src,count 20,seconds 1` and `count 10,seconds 5`. `blue-team/detection/zeek/scripts/port_scan.zeek:16-18` — `distinct_ports_threshold: double = 15.0`, `scan_interval: interval = 30sec`.
- **Recommendation**: Change to `flags:S+;`; add rules for `flags:F`, `flags:0` (NULL) and `flags:FPU` (XMAS); add a second Zeek SumStats reducer with a 10-minute epoch and a lower threshold for slow scans.
  Also note the comment/code mismatch at `port_scan.zeek:48-56`: *"Only track connections that look like scanning (no data transferred)"* — no such filter exists; every connection is observed.
---

**[MEDIUM] DNS-tunnel Zeek detection is label-length only, despite claiming entropy analysis**
- **MITRE ATT&CK**: T1048.003, T1071.004
- **Red Team**: Chunk exfil into labels of ≤30 characters and detection is zero. There is no entropy calculation, no NXDOMAIN-rate heuristic, no qtype filter (TXT/NULL are the tunnelling record types), and DoH/DoT (443/853) is not considered at all.
- **Blue Team**: The file header advertises *"Detects high-entropy DNS subdomains"* but the implementation only measures length.
- **Evidence**: `blue-team/detection/zeek/scripts/dns_exfil.zeek:10` — `const long_subdomain_threshold: count = 30 &redef;`; lines 22-31 test only `|labels[label]| > long_subdomain_threshold`.
- **Recommendation**: Lower the threshold to ~20 and add a Shannon-entropy check (>3.5 bits/char) plus a per-source unique-subdomain-count SumStats reducer; alert on TXT/NULL qtype volume and on NXDOMAIN rate. This layers on top of fixing the Zeek visibility problem — without that fix none of it fires.
---

**[MEDIUM] `privesc_sudo.yml` fires HIGH on any log line containing "NOPASSWD"**
- **Red Team**: An attacker who can write to syslog (see the syslog-injection finding) can trivially generate false positives that subtract from the blue-team score via the scorer's FP penalty, or flood the queue to bury a real alert.
- **Blue Team**: The `or` condition means a bare substring match with no context is enough for a HIGH-severity detection.
- **Evidence**: `blue-team/detection/sigma/privesc_sudo.yml:27-30` —
  ```yaml
  sudo_nopasswd:
      - 'sudo -l'
      - 'NOPASSWD'
  condition: keywords or sudo_nopasswd
  ```
  Evaluated as unanchored case-insensitive substring at `forensics/scoreboard/sigma_eval.py:55`.
- **Recommendation**: Require co-occurrence (`condition: keywords and sudo_nopasswd`) or scope `sudo_nopasswd` to the `sudo` program field now that `syslog.conf:35` populates `[program]`; drop `level: high` for the bare-enumeration case.
---

## LOW

- **[LOW] `block_ip.sh` IP validation accepts impossible addresses.** `blue-team/response/actions/block_ip.sh:28` — `^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$` accepts `999.999.999.999`. The script is a documented no-op (lines 4-15), so impact is confined to teaching a weak validation pattern. Fix: octet-range regex or `python3 -c 'import ipaddress,sys;ipaddress.ip_address(sys.argv[1])'`.

- **[LOW] `isolation_log.json` is not valid JSON.** `isolate_host.sh:32-34` and `restore_host.sh:27-29` append bare objects with no array wrapper or delimiter, so `json.load()` fails on the second entry. Rename to `.jsonl` or write a proper array. Any tooling that parses it will silently see only the first record.

- **[LOW] `collect_evidence.py` crashes on same-second collections and mixes time bases.** `blue-team/response/actions/collect_evidence.py:38` — `session_dir.mkdir()` without `exist_ok=True` raises `FileExistsError` outside the try block if two collections land in the same second (the playbook runs both `collect_evidence` steps in quick succession). Line 36 uses naive local time for the directory name while line 41 uses UTC for the manifest — a chain-of-custody timestamp discrepancy in the artifact itself. Fix: `exist_ok=True` (or a uniquifying suffix) and `datetime.now(UTC)` for both.

- **[LOW] `EVIDENCE_DIR` is honoured unvalidated in all four collectors.** `block_ip.sh:38`, `isolate_host.sh:30`, `restore_host.sh:25`, `collect_evidence.py:14` all take the path from the environment and `mkdir -p` it. In-container code exec can redirect the evidence trail anywhere writable. Fix: resolve, and refuse anything outside `/evidence`.

- **[LOW] No `.dockerignore`; committed `__pycache__` bytecode is copied into the image.** `blue-team/Dockerfile:31` — `COPY . .` with no `.dockerignore` anywhere in the repo. `blue-team/response/__pycache__/playbook_engine.cpython-314.pyc` matches the image's interpreter (`FROM python:3.14-slim`, line 1), so tampered bytecode whose header matches the `.py` mtime/size would execute in preference to the source (T1554). Fix: add `.dockerignore` with `__pycache__/`, `*.pyc`, `.env`; set `ENV PYTHONDONTWRITEBYTECODE=1`.

- **[LOW] No HTTP security headers on the dashboard.** No CSP, `X-Frame-Options`, `X-Content-Type-Options` or `Referrer-Policy` anywhere in `blue-team/dashboard/app.py`. The pages are clickjackable and inline `<script>` blocks (`index.html:97-107`, `playbooks.html:41-65`) would require CSP nonces. Fix: an `@app.after_request` header block.

- **[LOW] Suricata eve-log records full packet payloads and HTTP bodies to disk.** `blue-team/detection/suricata/suricata.yaml:48-56` — `payload: yes`, `payload-printable: yes`, `packet: yes`, `http-body: yes`. Credentials from the lab's cleartext login traffic land in `/var/log/suricata/eve.json` (a host bind-mount, `docker-compose.yml:202`) and are then copied into `/evidence` by `collect_evidence.py:16-17`. Intentional for forensics teaching, but it should be documented in `evidence/README.md` as "this directory contains cleartext credentials — do not share".

- **[LOW] The C2 User-Agent pcre never excludes anything.** `local.rules:48` — `pcre:"/User-Agent:[^\r\n]*(?!Mozilla|Chrome|Safari|curl|python)/"`. The greedy `[^\r\n]*` backtracks until the negative lookahead trivially succeeds, so it matches every User-Agent including the ones it means to whitelist. The rule is correctly marked reference-only (lines 37-44) but is presented as a production template students will copy. Fix: `pcre:"/User-Agent:\s*(?!(Mozilla|Chrome|Safari|curl|python))[^\r\n]+/H"`.

- **[LOW] `Notice::policy` hook is a no-op — the "page on critical events" comment is not implemented.** `blue-team/detection/zeek/local.zeek:38-44` adds `Notice::ACTION_LOG` to the two most severe notice types, but `ACTION_LOG` is already the default. There is no escalation (`ACTION_ALARM`/`ACTION_EMAIL`), so lateral movement and DNS tunnelling are treated identically to everything else. Fix: add `ACTION_ALARM` and set `$suppress_for` explicitly.

- **[LOW] Notice suppression semantics are inverted between the two DNS detections.** `dns_exfil.zeek:29` — `$identifier=cat(src, query)` makes every unique query a new notice (no suppression → log flood during tunnelling), while line 39 — `$identifier=cat(src)` suppresses `High_DNS_Volume` for Zeek's default 1-hour window, so sustained exfiltration alerts exactly once. Fix: use `cat(src)` for both and set an explicit `$suppress_for=5min`.

- **[LOW] `EVIDENCE_DIR.mkdir(exist_ok=True)` lacks `parents=True`.** `blue-team/response/playbook_engine.py:65` — fails with `FileNotFoundError` if the parent path doesn't exist, aborting the write of the playbook execution log *after* containment has already been performed. Fix: `mkdir(parents=True, exist_ok=True)` as `collect_evidence.py:35` already does.

- **[LOW] Playbook context validation doesn't verify the keys the selected playbook actually needs.** `blue-team/dashboard/app.py:179-201` validates whatever keys are supplied but never checks that `ransomware_ir` received `affected_host`. A missing key surfaces as a `KeyError` inside `_run_script` (`playbook_engine.py:140` — `args = [a.format(**context) for a in args]`), which the required-step logic converts into a mid-playbook halt. Fix: parse the playbook's `{vars}` at request time and return 400 listing the missing ones.

- **[LOW] Zeek runtime `local.zeek` shares a name with the file it loads.** `blue-team/detection/zeek/entrypoint.sh:22-33` writes `/tmp/zeek-runtime/local.zeek` whose first directive is `@load local` (line 26), intended to resolve via ZEEKPATH to the site copy. If Zeek's search path resolves `local` to the generated file itself, the lab scripts never load and `LateralMovement::internal_net` (line 29) becomes an unknown identifier — a parse error and crash-loop rather than a silent blind spot, so severity is low, but it is fragile. Fix: name the generated file something unambiguous (`runtime-site.zeek`). *(verify: `docker logs <zeek>` for load errors and check `loaded_scripts.log`.)*

---

## INFO — checked and clean

- **No XSS found.** All three templates are `.html`, so Jinja autoescaping is on; `grep` for `|safe`, `Markup`, `render_template_string`, `autoescape` across `blue-team/` returned **no matches**. Alert fields interpolated into `class="badge-{{ alert.severity }}"` and `href=".../{{ ... }}"` are escaped, and the `href` scheme is fixed to `https://attack.mitre.org/`, so no `javascript:` injection is possible.
- **No injection in the dashboard's trust boundary.** `_validate_context` (`app.py:173-201`) is genuinely well-built: closed key allowlist, `ipaddress.ip_address()` parsing for IPs, hostname charset with an explicit leading-`-` guard against argument injection, and type checking. `playbook_id` is restricted to the `PLAYBOOKS` registry (`app.py:260`), closing the path traversal into `PLAYBOOK_DIR / f"{id}.yml"`. `subprocess.run` is always called with a list, never `shell=True`. `yaml.safe_load` is used in both `playbook_engine.py:35` and `sigma_eval.py:107`. No SQL anywhere in `blue-team/`. Secret handling (`_require_secret_key`, the `INSECURE_SECRET_KEYS` denylist, `hmac.compare_digest`) is correct and fails closed.
- **Dependencies are exactly pinned** (`blue-team/requirements.txt:1-15`) with documented resolution rationale. I cannot check these versions against advisory databases offline — recommend running `pip-audit`/`safety` against this file; do not treat "no CVEs listed here" as a clean bill of health.

---

## Summary

| Severity | Count | Top Finding |
|----------|-------|-------------|
| CRITICAL | 1 | Sigma compile pipeline invokes the wrong `sigma` binary; all 7 compiled detections are bioinformatics help text, exit code 0, Kibana import errors swallowed |
| HIGH | 8 | Zeek sniffs a bridge-attached `eth0` and sees no lab traffic — all three custom detection scripts inert while the sensor reports healthy |
| MEDIUM | 15 | Sigma rules key on literal markers the red team itself emits — any technique variant evades 100% while coverage reads green |
| LOW | 13 | No `.dockerignore`; committed `cpython-314` bytecode is copied into an image running the matching interpreter |
| INFO | 3 | XSS, injection and secret-handling paths reviewed and clean; dependency CVE status unverified offline |

**Recommended next steps, in order:** (1) fix `compile_sigma.sh` and re-verify the compiled artifacts; (2) move Zeek to host-netns bridge capture; (3) add the missing `restore_host.sh` steps and make both network scripts idempotent; (4) hand the eight detection-logic findings (sids 1000003, 1000030, 1000040, 1000041, 1000042, 1000050, 1000052, 1000060) to `tester-debugger` for pcap-replay validation — several are asserted dead on static reading and should be proven; (5) hand the Sigma marker-coupling finding to `purple-team` to produce the technique-vs-detection coverage truth table.
