# Code Review — Wave 2 Follow-up Issues (#144, #145, #146, #147)
**Reviewer:** code-reviewer agent
**Date:** 2026-06-24
**Scope:** blue-team/dashboard/app.py, red-team/runner.py, forensics/scoreboard/app.py,
docker-compose.yml, scripts/lab/student-env.sh, siem/elasticsearch/ilm/index-template.json,
tests/test_dashboard_security.py, tests/test_target_allowlist.py, tests/test_es_ilm.py
**Basis:** `git diff HEAD` (uncommitted working-tree changes)

---

## Must Fix

### 1. [red-team/runner.py:346] `_pin_host_in_target` produces an invalid URL for IPv6 URL targets

**Code (line 346):**
```python
netloc = f"{ip}:{parts.port}" if parts.port is not None else str(ip)
```

When `ip` is an IPv6 address string (e.g., `"::1"` or `"2001:db8::1"`), `urlsplit` strips the
RFC 3986 brackets from `parts.hostname`. The reconstruction above puts the bare IPv6 address
directly into the netloc without re-bracketing it. The result is a syntactically invalid URL:

```
Input:   "http://[::1]:8080/path"
Actual:  "http://::1:8080/path"   ← invalid; colon-separated fields are ambiguous
Correct: "http://[::1]:8080/path"
```

Verified with Python 3:
```python
>>> urlsplit("http://[::1]:8080/path").hostname
'::1'
>>> urlunsplit(("http", "::1:8080", "/path", "", ""))
'http://::1:8080/path'  # invalid
```

**Mitigating factor:** `_vet_and_pin_target` will reject any IPv6 target before
`_pin_host_in_target` is called, because `_lab_networks()` only builds IPv4 `/24` objects —
an IPv6 address literal is never `in` any of them. So the broken branch is currently
unreachable through the production code path.

**Risk it stays a latent bug:** if a future operator adds IPv6 lab segments, or if
`_pin_host_in_target` is called directly in a test, the URL emitted is malformed and
the campaign will silently connect to the wrong place (or fail with a confusing error).

**Fix:**
```python
import ipaddress
parsed_ip = ipaddress.ip_address(ip)
if parsed_ip.version == 6:
    netloc = f"[{ip}]:{parts.port}" if parts.port is not None else f"[{ip}]"
else:
    netloc = f"{ip}:{parts.port}" if parts.port is not None else str(ip)
```

The bracketed-IPv6 guard in the `else` branch (bare target form, line 351) is also
unreachable via `_vet_and_pin_target` for the same reason, and should be removed or
annotated as future scaffolding to avoid confusion.

### 2. [red-team/runner.py:360] `_reject_target` annotated `-> None` but never returns — mypy cannot prove `_vet_and_pin_target` always returns `str`

**Code:**
```python
def _reject_target(target: str, host: str) -> None:   # line 360
    ...
    sys.exit(2)

def _vet_and_pin_target(target: str) -> str:
    ...
    if ip is None or not any(ip in net for net in _lab_networks()):
        _reject_target(target, host)          # mypy thinks this returns None
    return _pin_host_in_target(target, str(ip))  # ip could be None per mypy
```

Because `_reject_target` is annotated `-> None` rather than `-> NoReturn`, mypy's
non-strict pass over `red-team/` cannot rule out that execution falls through to
`_pin_host_in_target(target, str(ip))` with `ip = None`, making `str(None)` a latent
type error. The strict pass does not cover `runner.py` (CI only runs strict on
`base_campaign.py` and `scorer.py`), so this slips through.

**Fix:** add `from typing import NoReturn` and annotate:
```python
def _reject_target(target: str, host: str) -> NoReturn:
```

---

## Should Fix

### 3. [red-team/runner.py:379] LAB_HOSTNAMES pass-by-name skips IP-pinning — TOCTOU gap remains for in-lab service names

**Code:**
```python
if host in LAB_HOSTNAMES:
    return target   # <-- no pin applied
```

The stated goal of #145 is to defeat DNS rebinding by pinning the resolved IP so
"the campaign connects to that exact IP rather than re-resolve." For the three known
service names (`victim-web`, `victim-db`, `victim-mail`), the code returns the original
hostname unchanged. The campaign then re-resolves at connect time, which is the TOCTOU
gap the fix was supposed to close.

The comment "in-lab DNS controls them" is accurate for the composed network (`internal: true`),
so the practical risk is low. But the fix is logically inconsistent: it defeats DNS
rebinding for arbitrary hostnames but not for the three most-used ones. If an operator
runs the runner outside the compose network (e.g., on a jump box with external DNS),
the service-name path has the same TOCTOU exposure that was fixed for everything else.

**Suggestion:** resolve-and-pin LAB_HOSTNAMES too (fall through to `_resolve_host_ip`),
OR add a comment explaining exactly why the in-lab DNS makes the shortcut safe so a
future reader doesn't fix it by accident.

### 4. [tests/test_target_allowlist.py:119] `test_ip_literal_returned_unchanged` doesn't assert the pinning no-op, it asserts the unchanged string

**Code:**
```python
def test_ip_literal_returned_unchanged(self):
    self.assertEqual(runner._vet_and_pin_target("http://172.20.0.30/x"), "http://172.20.0.30/x")
```

This test asserts the return value equals the input — which is correct for an IP
literal. But it also silently passes if `_vet_and_pin_target` took the LAB_HOSTNAMES
short-circuit (it doesn't for an IP, but if the logic were wrong it could). Adding a
`mock.patch.object(runner.socket, "gethostbyname")` assertion that it is NOT called
would make the test more specific and catch a regression where an IP literal is
accidentally routed through DNS lookup. The rebinding test (test 4) does this correctly
for the resolution case; the IP-literal case should match.

### 5. [tests/test_dashboard_security.py:50-56] `_load` leaves a partially-initialized module in `sys.modules` if `exec_module` raises

**Code (new version):**
```python
sys.modules[module_name] = mod   # line 50
spec.loader.exec_module(mod)     # line 51 -- if this raises...
```

The `finally` block only removes `extra_path` from `sys.path`; it does not pop
`sys.modules[module_name]`. If `exec_module` raises (e.g., a bad `SECRET_KEY` causes a
`SystemExit` that is not caught), the module name maps to a half-initialized object.
The next `_load` call pops it at the top (`sys.modules.pop(module_name, None)`), so
this self-heals within a single test session. However, if two test classes share a
module name string AND the first call's `exec_module` raises, the second call gets
a clean slate — this is fine — but any code in the `with mock.patch.dict` block that
runs after the exception and before the `finally` sees a dirty `sys.modules`. This is
pre-existing behavior, not introduced by this diff, but the refactor was an opportunity
to fix it.

**Suggestion:** add `sys.modules.pop(module_name, None)` to the `finally` clause.

---

## Consider

### 6. [docker-compose.yml:337] `rc=$$?` placement is correct but the control flow is non-obvious

The concern is whether `rc=$$?` captures curl's exit code after `curl ... && break`.
It does: when curl fails, `&&` short-circuits (break does not run), `$?` equals curl's
exit code, and then `rc=$$?` captures it correctly. On success, `break` exits the loop
before `rc=$$?` is reached, so `rc` is never set on the success path — which is
correct, since it's never read on that path.

This is logically sound and BusyBox ash-compatible (POSIX `&&` semantics).
**Suggestion:** add a one-line comment `# rc is only used on the failure path` to save
the next reader from having to re-derive this.

### 7. [blue-team/dashboard/app.py:172] `_SAFE_HOST_RE` permits a single-char campaign_id

```python
_SAFE_HOST_RE = re.compile(r"\A[A-Za-z0-9._-]{1,253}\Z")
```

A 1-character campaign_id (e.g., `{"campaign_id": "x"}`) passes validation. The engine
uses `campaign_id` only for SIEM correlation JOIN, so a short value is semantically
harmless, but if the intent is "a UUID or timestamp-like string" the lower bound of 1
is looser than necessary. Low priority; document the intent or tighten to `{8,253}`.

### 8. [siem/elasticsearch/ilm/index-template.json] `_meta.replicas_note` added — correct but adds ~200 bytes to every template PUT

The note is informational and valid. No functional issue. If ES template size is ever a
concern (it won't be at this scale), move it to a README instead.

---

## Looks Good

- **#144 `_validate_context` key coverage:** `_CONTEXT_IP_KEYS` and `_CONTEXT_HOST_KEYS`
  exactly match the union of all `{…}` placeholders in the four shipped playbooks
  (`{attacker_ip}`, `{c2_ip}`, `{pivot_host}`, `{affected_host}`, `{source_host}`) plus
  `campaign_id` used by `PlaybookEngine._emit_ir_event`. No known playbook key is missing
  and no phantom key is allowed.

- **#144 `_validate_context` IP validation:** `ipaddress.ip_address()` correctly rejects
  hostnames, CIDR ranges, and partial octets. Both IPv4 and IPv6 literals are accepted,
  which is appropriate.

- **#144 `_validate_context` host regex:** `\A[A-Za-z0-9._-]{1,253}\Z` blocks all
  shell metacharacters (`; | $ { } space ( ) < >`) and format-string metacharacters
  (`{ }` already blocked by the lack of braces in the class). The `{1,253}` upper
  bound matches the DNS label-set length limit. The UUID `hex` format
  (`a3f8e1b2c4d5e6f7…`, 32 hex chars) passes.

- **#145 `_vet_and_pin_target` resolves exactly once:** `_resolve_host_ip` calls
  `socket.gethostbyname` once and returns an `ipaddress` object. The result is
  immediately passed to `_pin_host_in_target`; no second lookup occurs. The
  `test_rebinding_uses_single_validated_resolution` test verifies this with a
  `side_effect` list and `call_count == 1`.

- **#145 `os.environ[var] = _vet_and_pin_target(val)` pin flows correctly:** The
  pinned value is written back to `os.environ` before `_run_single_campaign` reads
  `os.environ.get("TARGET_WEB", DEFAULT_WEB_TARGET)`, so campaigns that read env vars
  at runtime connect to the allowlist-approved IP, not a fresh resolution.

- **#146 denylist sync test:** Using distinct module name strings (`"blue_dash_app"`,
  `"score_app_sync"`) avoids `sys.modules` collision between the two `_load` calls.
  The placeholder-coverage test correctly parses `.env.example` without importing it.

- **`_load` env isolation refactor (test_dashboard_security.py):** Replacing the manual
  `save/clear/update` pattern with `mock.patch.dict` is strictly safer: the original
  code called `os.environ.clear()` in `finally`, which would have wiped the real process
  environment if an exception escaped the inner `try`. The new code cannot do that.

- **`test_es_ilm.py` PyYAML import hardening:** Promoting the `SkipTest` to a hard
  import failure is correct — PyYAML is a declared dep in all requirements files, so a
  missing import is a broken environment, not a missing optional dep.

---

## Verdict

**Approve with conditions.** The two Must Fix items must be addressed before the branch
is relied upon for IPv6 targets (Finding 1) and before mypy strict coverage is extended
to runner.py (Finding 2). All four issues under review (#144–#147) are logically correct
for the current IPv4-only lab scope. The IPv6 URL reconstruction bug in
`_pin_host_in_target` is the single highest-priority item because it is a silent data
corruption (malformed URL, wrong connection target) that will appear only when the lab is
extended to IPv6 — exactly the kind of latent bug that is hardest to diagnose later.
