# Scoreboard Security Audit — 2026-08-13

## Scope

In scope: `forensics/scoreboard/` — `app.py` (311 lines), `scorer.py` (377), `sigma_eval.py` (125), `Dockerfile`, `requirements.txt`, `templates/scoreboard.html`, `templates/report.html`.
Adjacent files read for deployment context (not audited in full): `docker-compose.yml`, `.env.example`, `siem/logstash/pipelines/syslog.conf`, `tests/test_dashboard_security.py`, `blue-team/dashboard/app.py` (auth helper only).

Complete route inventory (5 routes, all confirmed): `GET /` (113), `GET /api/scores` (124), `GET /report` (129), `POST /api/award` (156), plus Flask's implicit `/static/<path:filename>`. **`/api/award` is the only state-mutating route, and it is authenticated.** The narrow question "are ALL state-mutating endpoints authenticated?" is: yes — but see CRIT-1, that guarantee is meaningless in this deployment.

Assumption: the threat actor is a student with a shell in the red-team container (`172.20.0.10`) and/or browser access to the published host ports — the realistic adversary for this lab.

## Summary

**1 CRITICAL, 2 HIGH, 6 MEDIUM, 6 LOW, 1 INFO (verified negatives).**
The `#143` fix on `POST /api/award` is correct as written but **incomplete in effect**: it is the only *authenticated* write path, yet it controls the smallest share of the score. The entire automatic score is read from Elasticsearch indices that any lab-net peer can write to with zero authentication (`xpack.security.enabled=false`), so score tampering does not need `/api/award` at all.
Second most important: successful awards are logged at `INFO`, which Flask's default logger level (WARNING) silently discards — the tamper-evidence trail the fix added never actually reaches stdout, and no container logs are shipped to ELK regardless.

---

**[CRITICAL] Scoreboard score is fully forgeable without touching the authenticated endpoint — Scorer trusts unauthenticated Elasticsearch indices**
- **MITRE ATT&CK**: T1565.001 (Data Manipulation: Stored Data Manipulation)
- **Red Team**: The `#143` auth gate protects a path worth at most ±50 points. The *automatic* score — which is the whole scoreboard — is derived from four ES indices with no authentication anywhere in the chain. From the red-team container (or the host, port 9200 is published), a student runs a single `curl -XPOST http://elasticsearch:9200/red-team-events-1/_doc` with `{"event_type":"campaign_end","campaign_id":"x","@timestamp":...}` to mint 10 base points + 15 stealth bonus per fake campaign, or backdates `suricata-*` alert docs to hand blue team fake Gold MTTDs, or floods `ir-events-*` with `playbook_complete` docs. They can also *delete* indices to zero the other team. Nothing distinguishes a forged doc from a real one.
- **Blue Team**: No detection. ES has no auth, no audit logging enabled, and container/ES logs are not ingested anywhere. There is no integrity control (no signed events, no HMAC on campaign IDs, no append-only enforcement) and no anomaly check in `Scorer` (e.g. campaign_end without a matching campaign_start, or alerts with `@timestamp` older than the doc's ingest time).
- **Evidence**: `forensics/scoreboard/scorer.py:126-129`
  ```python
  starts = self._hits("red-team-events-*", {"match": {"event_type": "campaign_start"}})
  ends = self._hits("red-team-events-*", {"match": {"event_type": "campaign_end"}})
  alerts = self._hits("suricata-*", {"match": {"event_type": "alert"}})
  responses = self._hits("ir-events-*", {"match": {"event_type": "playbook_complete"}})
  ```
  `docker-compose.yml:282` `- xpack.security.enabled=false` and `:276` `- "${ELASTICSEARCH_PORT:-9200}:9200"`
- **Recommendation**: Either (a) enable ES security with a scorer-scoped read-only role and separate write credentials held only by the red-team/IR containers, or (b) accept ES as untrusted and add integrity at the scorer: require each `red-team-events-*` doc to carry an HMAC over `(campaign_id, event_type, @timestamp)` keyed by a secret the students do not have, and drop docs whose `@timestamp` precedes the index's `_ingest` time by more than a tolerance. At minimum, bind ES to `127.0.0.1:9200` on the host and document that scores from a compromised ES are advisory.

---

**[HIGH] The award audit trail added by the #143 fix is never emitted — INFO is below Flask's default logger level**
- **MITRE ATT&CK**: T1562.002 (Impair Defenses: Disable Windows Event Logging — analogous: logging not configured), detection gap for T1565
- **Red Team**: An attacker (or a student who obtains the instructor token) applies `lab_violation_penalty` to a rival team, or `extra_credit_red` to themselves, and the "who changed the score and by how much" record at `app.py:191` is discarded before it reaches stderr. Only the *denied* attempts (WARNING, line 168) are visible, so a successful single-shot abuse with a correct token is completely silent — the exact inverse of what you want.
- **Blue Team**: `flask.logging.create_logger` sets the app logger to DEBUG only when `app.debug` is true; with `debug=False` the logger level stays NOTSET and inherits the root logger's default of WARNING, so `app.logger.info(...)` is filtered at the logger before any handler runs. There is no `logging.basicConfig` anywhere in `app.py`/`scorer.py`, and the scoreboard's compose env block (`docker-compose.yml:458-467`) does not even pass `LOG_LEVEL`, unlike red-team (`:70`) and blue-team (`:120`). Separately, no container stdout is shipped to ELK — the Logstash pipelines are `suricata.conf`, `zeek.conf`, `syslog.conf` only, with no docker/filebeat input — so even a correctly-emitted log never reaches the SIEM.
- **Evidence**: `forensics/scoreboard/app.py:191-198`
  ```python
  app.logger.info(
      "award: %s %+d to %s from %s (detail=%r)",
  ```
  versus `app.py:168` `app.logger.warning("award denied: ...")`. No logging configuration exists in the module.
- **Recommendation**: Add `logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format=...)` at import time in `app.py` and pass `- LOG_LEVEL=${LOG_LEVEL:-INFO}` in the scoreboard's compose env block to match the other services. Then ship the container's stdout into ELK (gelf/syslog log-driver to `logstash:5514`, or a filebeat docker input) so score-change events are queryable alongside detections. **This inference is from reading Flask's documented logger behaviour, not from execution — hand it to the tester-debugger agent to confirm empirically that a successful `POST /api/award` produces no stdout line.**

---

**[HIGH] Blue-team detections are mintable by any lab-net peer via the unauthenticated Logstash syslog input**
- **MITRE ATT&CK**: T1565.001, T1036 (Masquerading — forged advisories)
- **Red Team**: `_sigma_detection_ts()` treats *any* `syslog-*` document whose text contains a deployed Sigma rule's keyword as a scored detection. The Logstash syslog input listens on port 5514 with no authentication and no source allowlist, reachable from every container on lab-net. `logger -n logstash -P 5514 "sudo: pam_unix ..."` (or any keyword lifted from the read-only-mounted rules at `/app/sigma`, which the student can also read straight out of the repo) fabricates detections at will — inflating blue's score, or, timed into inter-campaign dead air, manufacturing false positives that deduct 5 points each from blue via `_correlate()`.
- **Blue Team**: No control distinguishes a genuine `BaseCampaign.emit_syslog_advisory` from a hand-crafted UDP packet — the pipeline stamps `[observer][name] => "syslog"` on everything. There is no rule requiring the advisory to originate from the red-team container's IP, and `_sigma_detection_ts` discards the source entirely.
- **Evidence**: `forensics/scoreboard/scorer.py:151-156`
  ```python
  for doc in self._hits("syslog-*", {"match_all": {}}):
      text = f"{doc.get('message', '')} {doc.get('syslog_message', '')}"
      if sigma_eval.matched_rule(text, self._sigma_rules):
  ```
  `siem/logstash/pipelines/syslog.conf:11-16` (`syslog { port => 5514 }`, no source filter)
- **Recommendation**: Constrain the syslog query to advisories from known emitters — replace `{"match_all": {}}` with a filtered query on `[host][name]`/`[source][ip]` matching the red-team container address (already available as `ATTACKER_IP`, `docker-compose.yml:69`), and have `emit_syslog_advisory` include a per-run nonce the scorer validates against the corresponding `campaign_start` doc.

---

**[MEDIUM] Unauthenticated 500 via non-ASCII auth header — same bug class the #143 fix was meant to close**
- **MITRE ATT&CK**: T1499 (Endpoint Denial of Service), detection evasion for T1110
- **Red Team**: `hmac.compare_digest` raises `TypeError: comparing strings with non-ASCII characters is not supported` when either `str` argument contains a codepoint above U+007F. Werkzeug decodes request headers as latin-1, so `X-Auth-Token: café` (raw bytes `0xC3 0xA9`) produces a non-ASCII `str` and the comparison throws — an **unauthenticated** request yields a 500 instead of a 401. Worse for detection: the exception is raised inside `_award_auth_ok` *before* line 168, so the `"award denied"` warning never fires. An attacker brute-forcing or probing the endpoint can append a single high byte to every attempt and generate zero denial logs. The same defect exists if an operator sets a non-ASCII `SCOREBOARD_AUTH_TOKEN`, in which case every request 500s and the endpoint is permanently broken.
- **Blue Team**: `tests/test_dashboard_security.py:186-206` pins "no 500 on malformed body" but has no equivalent case for a malformed *header*, so CI would not catch this. Identical code exists at `blue-team/dashboard/app.py:66` for `PLAYBOOK_AUTH_TOKEN` — fix both.
- **Evidence**: `forensics/scoreboard/app.py:69`
  ```python
  return bool(provided) and hmac.compare_digest(provided, SCOREBOARD_AUTH_TOKEN)
  ```
- **Recommendation**: Compare bytes, not str: `hmac.compare_digest(provided.encode("utf-8", "surrogateescape"), SCOREBOARD_AUTH_TOKEN.encode("utf-8"))`. Add a regression test posting `X-Auth-Token` with a non-ASCII byte and asserting 401 plus the presence of the denial log.

---

**[MEDIUM] Unauthenticated request amplification: every page view rebuilds the Scorer, re-parses all Sigma YAML, and issues ~10 Elasticsearch searches**
- **MITRE ATT&CK**: T1499.003 (Application Exhaustion Flood)
- **Red Team**: `_compute_scores()` constructs a fresh `Scorer()` on every request, and `Scorer.__init__` re-reads and YAML-parses the entire `/app/sigma` directory from disk. `compute_final_scores()` then calls `_correlate()` twice (`scorer.py:255` and `:310`), and each `_correlate` runs four `_hits` queries at `size: 500` plus a full `syslog-*` `match_all` scan with per-document substring matching against every loaded rule — roughly ten ES searches and two full rule reloads per HTTP request. All three GET routes are unauthenticated, so a trivial `while true; do curl :5002/api/scores; done` from lab-net exhausts the ES 1 GB heap and the scoreboard container, which has **no `mem_limit`** unlike elasticsearch and kibana (`docker-compose.yml:418`). The scoreboard template also self-refreshes every 30 s per open browser tab (`templates/scoreboard.html:110`), so this load exists even without an attacker.
- **Blue Team**: No rate limiting, no caching, no request-duration metric, no alert on ES query volume. The compose healthcheck hits `/api/scores` every 15 s (`docker-compose.yml:453-454`), adding to the same load.
- **Evidence**: `forensics/scoreboard/scorer.py:90` (`self._sigma_rules = sigma_eval.load_rules(...)` in `__init__`), `scorer.py:255` and `scorer.py:310` (both call `self._correlate()`), `app.py:223` (`scores = Scorer().compute_final_scores()`).
- **Recommendation**: Load Sigma rules once at module import, and memoize `compute_final_scores()` behind a short TTL cache (5-10 s) so bursts collapse to one ES round-trip; compute `_correlate()` once and share the result between `get_red_team_score` and `get_blue_team_score`. Add `mem_limit: 256m` to the scoreboard service.

---

**[MEDIUM] Unauthenticated read endpoints leak live detection state and scoring thresholds to the red team**
- **MITRE ATT&CK**: T1592/T1590-analogue (adversary reconnaissance of defender capability); exercise-integrity issue
- **Red Team**: `GET /api/scores` requires no auth and returns, per campaign, whether blue detected it (`"detail": "no alert"`, `blue_team.misses`, `red_team.campaigns_undetected`) plus the exact tier thresholds (`MTTD_GOLD_S`, `MTTD_SILVER_S`, weights). A student polls it as a real-time detection oracle: run a technique, poll, see whether an alert landed and how fast, then tune. Knowing thresholds lets them deliberately pace attacks so detections land just past the Bronze cutoff, minimizing blue's score while maximizing their own stealth bonus.
- **Blue Team**: No access control, no logging of who reads the scoreboard, no separation between the instructor view and the participant view.
- **Evidence**: `forensics/scoreboard/app.py:124-126` (`@app.route("/api/scores")` with no auth decorator) and `forensics/scoreboard/scorer.py:337-341`:
  ```python
  "thresholds": {
      "detection": DETECTION_THRESHOLDS,
      "response": RESPONSE_THRESHOLDS,
  ```
- **Recommendation**: Split the surface — a public view that returns only the two totals and the winner, and an instructor view (gated on `SCOREBOARD_AUTH_TOKEN`, same helper as `/api/award`) that returns per-campaign history, misses, false positives and thresholds. Drop `thresholds` from the unauthenticated payload entirely.

---

**[MEDIUM] `detail` field has no type, length, or count validation — post-auth unbounded memory growth**
- **MITRE ATT&CK**: T1499.003
- **Red Team**: `team` and `event` are correctly allowlisted, but `detail` is taken verbatim with no `isinstance` check, no length cap, and no cap on how many history entries accumulate. Anyone holding the instructor token (or the CI token, or an over-shared `.env`) can POST a 100 MB `detail` string repeatedly; each is retained forever in the process-global `MANUAL_SCORES` list and re-rendered into every subsequent `/` and `/report` response, so one abusive POST permanently degrades the page for all viewers. There is also no `MAX_CONTENT_LENGTH` configured, so `request.get_json()` buffers an arbitrarily large body into memory before any validation runs. A non-string `detail` (dict/list) is also accepted and stored.
- **Blue Team**: No size or rate limits, no cap on history length, no container memory limit to contain the blast.
- **Evidence**: `forensics/scoreboard/app.py:177` `detail = data.get("detail", "")` and `app.py:200-207` (unbounded `MANUAL_SCORES[team]["history"].append(...)`).
- **Recommendation**: `detail = str(data.get("detail", ""))[:200]` with an explicit 400 if the raw value is not a string; set `app.config["MAX_CONTENT_LENGTH"] = 16 * 1024`; cap history with `collections.deque(maxlen=200)`.

---

**[MEDIUM] Container runs as root with read-write bind mounts of the evidence store and the repo's forensics tree**
- **MITRE ATT&CK**: T1611 (Escape to Host — precondition), T1565.001 (evidence tampering), T1222 (file permission modification)
- **Red Team**: The Dockerfile declares no `USER`, so the Flask process runs as uid 0, and compose grants it `./evidence:/evidence` and `./forensics:/app/forensics` read-write on the host filesystem. Any code-execution primitive in the app (today: none found — but this is the amplifier that turns a future bug into a real incident) yields root-owned writes into the host repo and, critically, into the chain-of-custody store that `_evidence_bonus()` itself scores. An attacker who reaches the container can both manufacture `manifest.json` directories to farm the evidence bonus and destroy the real forensic artifacts. No `cap_drop: [ALL]`, no `security_opt: no-new-privileges`, no `read_only: true`.
- **Blue Team**: No file-integrity monitoring on `./evidence`, no auditd, and the evidence bonus is awarded purely on the *existence* of a manifest filename — never on its cryptographic validity.
- **Evidence**: `forensics/scoreboard/Dockerfile:16-23` (no `USER` directive anywhere in the file); `docker-compose.yml:445-447`:
  ```yaml
  volumes:
      - ./evidence:/evidence
      - ./forensics:/app/forensics
  ```
- **Recommendation**: Add `RUN useradd -r -u 10001 scoreboard` + `USER scoreboard` to the Dockerfile; mount `./evidence:/evidence:ro` (the scoreboard only reads it — `os.scandir`/`os.path.exists` at `scorer.py:358-361`) and drop the `./forensics` mount entirely, since nothing in the app reads it. Add `cap_drop: [ALL]`, `security_opt: ["no-new-privileges:true"]`, `read_only: true`.

---

**[MEDIUM] Service published on all host interfaces despite the lab's `internal: true` air-gap posture**
- **MITRE ATT&CK**: T1190 (Exploit Public-Facing Application)
- **Red Team**: `lab-net` is `internal: true` (`docker-compose.yml:21`) to block container egress, but the port mapping is written without a bind address, so Docker publishes on `0.0.0.0:5002`. Anyone on the instructor's or student's physical LAN/Wi-Fi reaches the scoreboard, `/api/award`, Kibana (`:5601`) and the unauthenticated Elasticsearch (`:9200`). Combined with CRIT-1, a peer on the coffee-shop network can rewrite the exercise results. The air-gap control protects outbound traffic only; inbound is wide open.
- **Blue Team**: No host firewall rule is documented, and `.env.example:35-41` presents the ports as plain numbers with no bind-address option, so operators have no obvious lever.
- **Evidence**: `docker-compose.yml:440-441`
  ```yaml
  ports:
      - "${SCOREBOARD_PORT:-5002}:5002"
  ```
- **Recommendation**: Introduce `BIND_ADDR=127.0.0.1` in `.env.example` and rewrite every published port as `"${BIND_ADDR:-127.0.0.1}:${SCOREBOARD_PORT:-5002}:5002"`. Operators who genuinely need LAN access set `BIND_ADDR=0.0.0.0` deliberately.

---

**[LOW] No security response headers on any route**
- **MITRE ATT&CK**: T1189-adjacent (client-side attack surface)
- **Red Team**: No `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`/`frame-ancestors`, or `Referrer-Policy` is set on any response. The scoreboard is clickjackable (an iframe overlay could trick an instructor with an authenticated browser session into interacting), and there is no CSP defence-in-depth backstop if a future template change introduces `|safe` on the attacker-influenced `detail` field.
- **Blue Team**: No `@app.after_request` hook exists in either Flask app in this repo (grep for `after_request` across `blue-team/` returns nothing), so this is a consistent gap, not a scoreboard-only regression.
- **Evidence**: `forensics/scoreboard/app.py` — no `after_request` handler; `app.py:146-152` sets only `Content-Type` and `Content-Disposition` on the download path.
- **Recommendation**: Add an `@app.after_request` that sets `Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`.

---

**[LOW] Air-gapped lab template fetches a font from an external CDN**
- **MITRE ATT&CK**: T1071.001 (Application Layer Protocol: Web) as a potential channel
- **Red Team**: The scoreboard page instructs the *operator's browser* (which is not on the internal network) to fetch `fonts.googleapis.com`. That is an outbound request from the instructor's workstation every time the page renders — every 30 seconds, given the auto-refresh — contradicting the lab's stated air-gap posture and providing a ready-made beacon channel if anyone modifies the template. `report.html` deliberately avoids this (see its comment at line 7-8); `scoreboard.html` did not get the same treatment.
- **Blue Team**: Nothing blocks or alerts on it; the operator's browser is outside the lab's egress controls entirely.
- **Evidence**: `forensics/scoreboard/templates/scoreboard.html:7`
  ```
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&family=JetBrains+Mono&display=swap');
  ```
- **Recommendation**: Replace with the system font stack already used in `report.html:16` (`-apple-system, BlinkMacSystemFont, "Segoe UI", ...`), or vendor the font files into the image.

---

**[LOW] Session secret is mandatory but sessions are never used; no cookie hardening configured**
- **Red Team**: `app.secret_key` is set (and correctly refuses known-default values) but nothing in the app calls `session[...]` or `flash()`. If a later change adds session use, the cookie will default to `Secure=False`, `SameSite=None`, meaning it is transmitted over the lab's plaintext HTTP and attachable to cross-site requests — at which point the header-based CSRF immunity described in INFO-1 quietly disappears.
- **Blue Team**: No `SESSION_COOKIE_SECURE` / `SESSION_COOKIE_HTTPONLY` / `SESSION_COOKIE_SAMESITE` configuration and no test asserting it.
- **Evidence**: `forensics/scoreboard/app.py:73` `app.secret_key = _require_secret_key()` — no `app.config` cookie settings follow. Also dead config at `app.py:75-76`: `EVIDENCE_DIR` and `ELASTICSEARCH_URL` are assigned but never referenced (`scorer.py:25` and `:353` read the same env vars independently), which invites drift.
- **Recommendation**: Set `app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_SECURE=False)` with a comment that `SECURE` must flip to `True` behind the PKI proxy, and delete the two unused module globals.

---

**[LOW] No rate limiting or minimum-entropy requirement on the award token**
- **MITRE ATT&CK**: T1110.001 (Password Guessing)
- **Red Team**: `SCOREBOARD_AUTH_TOKEN` is validated against a five-entry denylist but has no length or entropy floor, so `SCOREBOARD_AUTH_TOKEN=abc` is accepted and enables the endpoint. There is no lockout, backoff, or per-IP throttle on `/api/award`, so a short token falls to a trivial loop. (`scripts/lab/student-env.sh:73` does generate a strong value, so the realistic exposure is a hand-edited `.env`.)
- **Blue Team**: Denials *are* logged at WARNING (`app.py:168`), which is the right level and will actually emit — but those logs go only to container stdout and are not ingested by ELK, so no alert can fire on N failures per minute.
- **Evidence**: `forensics/scoreboard/app.py:51-55` — only membership in `INSECURE_SECRET_KEYS` is checked, no length test.
- **Recommendation**: Reject tokens shorter than 32 characters at startup (log a warning and disable the endpoint, consistent with the existing fail-closed behaviour), and add a simple in-process counter that returns 429 after 5 failures from the same `remote_addr` in 60 seconds.

---

**[LOW] Audit-log source attribution is unreliable for host-published traffic**
- **Red Team**: `request.remote_addr` is logged as "who changed the score," but requests arriving through Docker's published port are source-NAT'd by the userland proxy, so every request originating from the host (i.e. the instructor's own browser, and anyone on the LAN per the `0.0.0.0` binding in the MEDIUM finding above) appears as the bridge gateway address. Attribution collapses to a single indistinguishable IP exactly where you most need it.
- **Blue Team**: There is no secondary identity in the log line — no token fingerprint, no user agent, no request ID.
- **Evidence**: `forensics/scoreboard/app.py:169` and `app.py:195` both log `request.remote_addr`.
- **Recommendation**: Log `X-Forwarded-For` when present, plus the first 8 hex chars of `sha256(provided_token)` so distinct instructor tokens are distinguishable in the trail without recording the secret, and issue per-instructor tokens rather than one shared value.

---

**[LOW] Werkzeug development server used as the production entrypoint; dependencies pinned without hashes**
- **Red Team**: `app.run(host="0.0.0.0", port=5002)` starts Werkzeug's development server, which is explicitly not intended for exposed deployment and lacks request-size, timeout, and connection limits — compounding the amplification finding above. Separately, `pip install -r requirements.txt` resolves from PyPI with pinned versions but no hash pinning, so a compromised or typosquatted artifact for a pinned version would be installed silently at image build.
- **Blue Team**: Versions *are* pinned (good) and `.github/dependabot.yml` references this directory, so update automation exists. No SBOM or image scanning step was found in scope.
- **Evidence**: `forensics/scoreboard/app.py:310` `app.run(host="0.0.0.0", port=5002, debug=False)`; `forensics/scoreboard/Dockerfile:14` `RUN pip install --no-cache-dir -r requirements.txt`; `forensics/scoreboard/requirements.txt:1-3`. I did not attempt to verify that the pinned versions (`flask==3.1.3`, `requests==2.34.2`, `pyyaml==6.0.3`) correspond to real published releases or carry known CVEs — no network access here, no guessed advisory IDs.
- **Recommendation**: Switch the CMD to `gunicorn -w 2 -b 0.0.0.0:5002 app:app` (add `gunicorn` to requirements), and generate `requirements.txt` with `pip-compile --generate-hashes`, installing with `pip install --require-hashes`.

---

**[INFO] Verified negatives — checked and found sound**
These were explicitly tested against the code and are *not* vulnerable; recording them so the next audit does not re-litigate them:
- **SQL / NoSQL / command injection**: no user input reaches any query. All four ES query bodies are literal dicts (`scorer.py:126-129`, `:151`), the index names are hardcoded, and there is no `subprocess`, `os.system`, `eval`, `exec`, or `pickle` anywhere in `forensics/**/*.py` (grep-confirmed).
- **SSTI**: no `render_template_string`; only fixed template names at `app.py:116` and `app.py:139`.
- **Unsafe deserialization**: `sigma_eval.py:107` uses `yaml.safe_load`, and the rules directory is mounted read-only (`docker-compose.yml:450`).
- **Debug mode**: `app.py:310` passes `debug=False` explicitly, which in Flask overrides the `FLASK_DEBUG` environment variable, so the Werkzeug debugger console (RCE) cannot be turned on by env alone.
- **Mass assignment**: `app.py:179` allowlists `team` against a literal tuple and `event` against `MANUAL_OVERRIDE_RULES`; the point value comes from the server-side dict at `app.py:188`, never from the request body. A client cannot set its own score delta.
- **CSRF**: not exploitable. Authentication is a custom request header (`X-Auth-Token` / `Authorization`), never a cookie, so there is no ambient authority — a cross-origin HTML form cannot set those headers, and an XHR/fetch attempt triggers a CORS preflight that the app does not answer. Note this property is load-bearing: it breaks the moment anyone adds cookie-based auth (see the session finding).
- **Stored XSS via `detail`**: mitigated by Jinja autoescape on `.html` templates; `report.html:200` renders `{{ row.detail }}` in a text node, and `report.html:154`'s attribute interpolation uses server-generated `tier` values, not user input. No `|safe` filter appears in either template.
- **Path traversal**: no route accepts a filename. `/report?download=1` (`app.py:145-152`) derives its `Content-Disposition` filename from a server-side date stamp only; `_evidence_bonus` (`scorer.py:352-365`) and `load_rules` (`sigma_eval.py:96-114`) build paths from environment variables, not requests; Flask's implicit `/static/` route uses Werkzeug's `safe_join`.
- **Non-JSON body handling (the #143 fix itself)**: correct. `app.py:174` `request.get_json(silent=True) or {}` handles both a wrong `Content-Type` and syntactically broken JSON, with regression tests at `tests/test_dashboard_security.py:186-206`. The auth check correctly precedes body parsing (`app.py:167`), so an unauthenticated caller cannot even reach the parser.

---

## Summary Table

| Severity | Count | Top Finding |
|----------|-------|-------------|
| CRITICAL | 1 | Score fully forgeable by writing directly to unauthenticated Elasticsearch — `/api/award` auth protects the least valuable path (`scorer.py:126-129`, `docker-compose.yml:282`) |
| HIGH | 2 | The award audit trail added by the #143 fix is emitted at INFO and silently dropped by Flask's default WARNING logger level (`app.py:191`) |
| MEDIUM | 6 | Unauthenticated 500 via non-ASCII `X-Auth-Token` — `hmac.compare_digest` TypeError, same bug class as the fix, and it suppresses the denial log (`app.py:69`) |
| LOW | 6 | No security response headers on any route; air-gapped lab template still pulls a Google Fonts CDN (`scoreboard.html:7`) |
| INFO | 1 | Verified negatives: injection, SSTI, deserialization, debug mode, mass assignment, CSRF, XSS, path traversal all checked and sound |

**Suggested follow-up:** hand HIGH-2 to the tester-debugger agent to empirically confirm the dropped INFO log, and run the purple-team agent against CRIT-1 and HIGH-3 — both are score-integrity attacks with currently zero detection coverage, which is the kind of gap that agent exists to quantify.
