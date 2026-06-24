# Wave 2 Hardening — Findings & Review Triage (2026-06-23)

Scope: P6 (IR dashboard lockdown), P7 (ES ILM/retention), P8 (red target
allowlist), P9 (ECS field normalization). Delegated to `security-auditor` +
`code-reviewer` in parallel on the working-tree diff per CLAUDE.md.

## Fixing now (real bug, in Wave 2 scope or in code Wave 2 introduced)

| ID | Source | Severity | Item | Action |
|----|--------|----------|------|--------|
| A | code-review #1 | High | `_require_secret_key` checks `key.strip()` but returns unstripped `key` — a trailing-space default (`"lab-secret-key "`) passes the denylist | Strip before check, return stripped. Both apps. |
| B | code-review #2 / sec #9 | Med | `run_playbook` derefs `request.get_json()` which is `None` for non-JSON bodies | `get_json(silent=True) or {}`, return 400 |
| C | sec #6 | **High** | `playbook_id` passed unvalidated to `PlaybookEngine` → path traversal → arbitrary YAML exec (container holds docker.sock + NET_ADMIN). Token gate is the only barrier. | Validate `playbook_id` against the `PLAYBOOKS` registry before constructing the engine |
| D | sec #7 | Med | `.env.example` ships `PLAYBOOK_AUTH_TOKEN` = the same string in the SECRET_KEY denylist; app accepts it as a valid token | Treat a denylisted token as "not configured" (endpoint disabled, fail closed) |
| E | sec #1 | Low | `_is_lab_target` is case-sensitive and dot-sensitive (`Victim-Web`, `victim-web.` rejected) — fails closed but surprises operators | Normalize host: lowercase + strip trailing dot |
| F | code-review #8 / sec #12 | Low | `es-init` health poll has no retry cap (gated by `service_healthy`, so low risk, but a hung ES would wedge the stack) | Add a bounded retry cap, exit non-zero on timeout |
| G | code-review #9 | Low | Secret values unquoted in the `student-env.sh` heredoc (safe for hex today, fragile) | Quote the values |
| H | code-review #3/#4 / sec #2/#4 | Doc | Allowlist validates a name→IP binding it doesn't pin (resolve-time TOCTOU); gate skipped when target falls back to the hardcoded default | Document the trust assumption at the fallback site and that `internal:true` egress isolation is the actual containment |

## Deferred (pre-existing, outside Wave 2 scope) — tracked, not fixed here

| Source | Item | Why deferred |
|--------|------|-------------|
| code-review #6 | suricata `severity_label: low` `else` fires on all non-alert events | Pre-existing (P9 only renamed the field, behaviour unchanged); not a regression. Detection-semantics change is out of P9 scope. |
| code-review #7 | `src_port` rename nested inside the `[dest_ip]` guard | Pre-existing; untouched by P9. |
| code-review #5 | `INSECURE_SECRET_KEYS`/`_require_secret_key` duplicated across the two apps | The two apps run in **separate containers** with disjoint filesystems — a shared import is infeasible without restructuring mounts. Duplication is the correct choice here. |
| sec #9 | `award_points` (scoreboard) has no auth + `get_json` null-deref | Different endpoint; P6 scoped only the IR `run-playbook` route. Worth a future wave. |
| sec #11 | `LAB_NET_PREFIX` interpolated unescaped into the suricata `awk` entrypoint | Pre-existing compose code; operator-supplied value is already a trusted input. Worth a future wave (validate prefix format in preflight). |
| sec #3 | Obfuscated IP encodings (`0x7f..`) reach `gethostbyname` | Already fail-closed for out-of-lab targets; residual risk is only obfuscated *in-lab* targeting, which is permitted anyway. |

No credentials, keys, or PII recorded in this file.
