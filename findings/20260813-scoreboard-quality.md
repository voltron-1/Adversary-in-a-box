# Code Review: forensics/scoreboard/ (Flask app) — logic, error handling, test coverage, maintainability

Reviewer: code-reviewer sub-agent
Date: 2026-08-13
Scope: forensics/scoreboard/app.py, scorer.py, sigma_eval.py, templates/, requirements.txt, Dockerfile
Out of scope: vulnerability hunting (covered separately by security-auditor)

Baseline reviewed: current `main` (HEAD), specifically commit bed44e2 "fix(scoreboard):
authenticate POST /api/award; stop 500 on non-JSON body" (closes #143) and how it sits
against the rest of the module. `forensics/scoreboard/` has no uncommitted changes at
review time.

---

## Must Fix
None. No correctness bug found that breaks functionality or reliability of the shipped
behavior under normal operation.

## Should Fix

1. **scorer.py:255, scorer.py:310, scorer.py:323-325 — `_correlate()` (and therefore the
   full 5-call ES fetch) runs twice per page render, doubling ES load and healthcheck
   latency risk.**
   `compute_final_scores()` calls `self.get_red_team_score()` (line 310:
   `pairs, completed, _fp = self._correlate()`) and then `self.get_blue_team_score()`
   (line 255: `pairs, _completed, fp_count = self._correlate()`). Each `_correlate()` call
   invokes `_fetch()` (scorer.py:126-138), which does 4 sequential blocking `requests.get`
   calls (`red-team-events-*` x2, `suricata-*`, `ir-events-*`, `timeout=5` each) plus a 5th
   sequential call for `syslog-*` inside `_sigma_detection_ts()` (scorer.py:151) — 5 HTTP
   round trips per `_correlate()`, 10 per `compute_final_scores()`. This runs on every hit
   to `/`, `/api/scores`, and `/report` (app.py:115, app.py:126, app.py:138 all call
   `_compute_scores()` → `Scorer().compute_final_scores()`), including the Docker
   healthcheck (`docker-compose.yml:453`, `curl ... /api/scores` every 15s, 5s timeout).
   The author was aware of the double-call (see the comment at scorer.py:87-89: "load the
   deployed Sigma rules once per scorer (not per `_correlate`, which runs twice per page
   render)") and mitigated the Sigma-rule-loading cost, but not the ES round trips
   themselves. Under a slow-but-responding ES, 10 sequential 5s-timeout calls can push a
   single request past 5-25s+, which exceeds the healthcheck's 5s timeout and can flap the
   container to unhealthy/restarted even though the app itself is fine.
   Fix: memoize `_correlate()`'s result per `Scorer` instance (e.g.
   `functools.cached_property` or a `self._pairs_cache` set on first call) since a `Scorer`
   is already constructed fresh per request in `_compute_scores()` — this halves ES load
   for free with no behavior change (already covered by test_scoring_contract.py's
   fixed-fixture assertions, which don't distinguish call count).

2. **scorer.py:99, scorer.py:453 (docker-compose.yml healthcheck) — 5 sequential
   `timeout=5` ES calls per `_fetch()` mean a single degraded-ES request can take up to
   ~25s (50s after item 1 is fixed... actually worse, unfixed), far exceeding the 5s
   healthcheck timeout.**
   Independent of the double-call in finding #1, `_fetch()` alone issues 4 sequential
   `requests.get(..., timeout=5)` calls, and `_sigma_detection_ts()` adds a 5th — none run
   concurrently, none share a session/connection pool. This is a genuine reliability gap:
   a partially-degraded (not down) Elasticsearch turns a normally-instant `/api/scores`
   into a multi-second serial chain that can trip the compose healthcheck
   (`interval: 15s, timeout: 5s, retries: 6`) and cause `restart: unless-stopped` churn.
   Fix: at minimum, reduce per-call timeout and/or run the 5 lookups concurrently
   (`concurrent.futures.ThreadPoolExecutor` or a shared `requests.Session` with a smaller
   per-call timeout budget so total worst case stays under the healthcheck timeout).

## Consider

3. **app.py:58 — `_award_auth_ok(req)` has no type hint on `req`, inconsistent with the
   rest of the file's typed signatures (`-> bool`, `-> str`, `-> dict`).** Low priority:
   `app.py` is outside the `[tool.mypy] files` strict scope in `pyproject.toml` (only
   `scorer.py` and `base_campaign.py` are strict), so this doesn't fail CI, but annotating
   as `req: Request` (or `flask.Request`) would match the file's own style and avoid it
   silently degrading further as the file grows.

4. **app.py:199-207 — `MANUAL_SCORES[team]["history"]` grows unbounded for the life of the
   container.** Every `/api/award` call appends and never trims. Given `restart:
   unless-stopped` and a semester-length lab, this is a slow, bounded-by-usage memory
   growth, not a leak per request — low real-world impact for an instructor-driven,
   low-frequency endpoint, but worth a comment or cap if the lab is expected to run for
   very long stretches.

5. **app.py:175-177 — `team`/`event` are not normalized (case/whitespace) before the
   membership check at line 179.** A caller sending `"Red_Team"` or `" red_team"` gets a
   clean 400 (not a 500 — correct per the #143 fix's intent), so this is not a bug, just a
   minor usability rough edge for an API with no client UI calling it (confirmed:
   `templates/scoreboard.html` has no `/api/award` fetch/form — this is a curl/instructor-
   tool-only endpoint, so the rough edge is low priority).

6. **scorer.py:105 — `_hits(..., size=500)` silently truncates any index with more than
   500 matching documents.** For a single-session lab exercise this is very unlikely to be
   reached, but if it is, the scorer would undercount without any warning (no logged
   truncation notice). Consider logging when `len(hits) == size` (likely truncated) so a
   large exercise doesn't silently under-score.

## Looks Good

- **The #143 fix (auth + non-JSON-body handling) was applied to the only endpoint that
  needed it.** `app.py` has exactly one state-mutating route (`POST /api/award`,
  app.py:156); `/`, `/api/scores`, and `/report` are all read-only `GET`s that don't parse
  a request body. There are no unauthenticated "sibling" mutating endpoints left behind —
  the fix's scope matches the actual attack surface.
- **Auth runs strictly before body parsing and before any mutation** (app.py:167-171
  gates on `_award_auth_ok(request)` before `request.get_json(silent=True)` at line 174),
  and the body is read with `silent=True` + `or {}` so a non-JSON or garbled-JSON body
  degrades to a clean `400`, never a `500` — matches the commit's stated intent and is
  directly exercised by `test_malformed_body_does_not_500` and
  `test_garbled_json_body_does_not_500` in `tests/test_dashboard_security.py:186-206`.
- **Test coverage for the fix is thorough and matches implementation behavior exactly**:
  `tests/test_dashboard_security.py` (`TestAwardAuth`, lines 107-206) covers missing
  header, env-var-absent-vs-empty-string (a real distinction in `_load()`'s
  `mock.patch.dict` helper), wrong token, correct token via both `X-Auth-Token` and
  `Authorization: Bearer`, the committed-placeholder-token-disables-endpoint case, invalid
  event when authed, and both malformed-body variants. `TestInsecureKeyDenylistSync`
  (lines 293-327) also guards the documented duplication between the scoreboard's and
  dashboard's `INSECURE_SECRET_KEYS` against drift and against missing `.env.example`
  placeholders — a good regression guard for a genuinely awkward cross-Docker-context
  constraint (each app builds from its own Docker context and can't share the import).
- **scorer.py's false-positive / dead-air correlation logic (lines 214-245) is well
  commented with the concrete production incident that motivated it** ("the live run
  charged ~7 such startup alerts as FPs, sinking 3 Gold detections") and is backed by a
  dedicated regression test (`test_false_positives_are_dead_air_only`,
  `tests/test_scoring_contract.py:173-203`) that encodes the exact scenario. This is a
  strong example of a fix with both a "why" comment and a test that would catch a
  regression to the old (wrong) behavior.
- **Fail-closed design is consistent and intentional across both the SECRET_KEY boot
  guard and the SCOREBOARD_AUTH_TOKEN gate**: an unset or known-placeholder value disables
  the feature rather than silently accepting it, and this is uniformly true for both apps
  (`TestInsecureKeyDenylistSync`) — a good, auditable security posture for a multi-tenant
  student lab.
- **`sigma_eval.py`'s scope-limiting is explicit and honest about what it does not
  support** (mixed `and`/`or` conditions log a warning and return `False` rather than
  mis-evaluate — sigma_eval.py:72-79), which is the right failure mode for a scoring
  engine (under-score is safer than a silently wrong match).

---

## Verdict

⚠️ **Approve with conditions** — no functional or correctness break was found, and the
#143 fix was applied consistently (no sibling endpoint was left unauthenticated or left
to 500 on bad input). The two "Should Fix" items (double `_correlate()`/ES-fetch per page
render, and the resulting exposure to the compose healthcheck's 5s timeout under a
degraded-but-responsive ES) are pre-existing performance/reliability issues, not
regressions introduced by the reviewed fix, but they are real and cheap to fix (memoize
`_correlate()` per `Scorer` instance). Recommend landing them as a small follow-up before
relying on the healthcheck in a live exercise with real ES load.
