# Wave-2 Follow-ups — Security Audit (#144 / #145)

Scope: uncommitted working-tree changes implementing #144 (`_validate_context`)
and #145 (vet-and-pin). Delegated to `security-auditor` per CLAUDE.md.
Read-only lens; full data-flow traced into the privileged IR sinks.

## Summary

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High     | 0 |
| Medium   | 1 |
| Low      | 2 |

## MEDIUM — leading-hyphen host values pass `_validate_context` → argv-flag injection

- **Where:** `blue-team/dashboard/app.py:174` — `_SAFE_HOST_RE = \A[A-Za-z0-9._-]{1,253}\Z`
- **Sink:** value is `str.format`'d into playbook args → `subprocess.run(["bash", script] + args)`;
  scripts do `docker network connect "$QUARANTINE_NET" "$TARGET"`
  (`blue-team/response/actions/isolate_host.sh:25`).
- **Issue:** the regex permits a leading `-`, so `pivot_host: "--help"` / `affected_host: "-D"`
  passes validation and reaches `docker`/`bash` argv as a flag (CWE-88 argument injection).
  Impact is bounded today (value lands in the *final* positional, where docker stops option
  parsing), but the validator is the trust boundary and should reject argv-flag-shaped values;
  any future playbook placing a context value in a non-terminal argv slot is directly exploitable.
- **MITRE:** T1059 (Command/Scripting Interpreter); downstream T1562.001.
- **Fix:** anchor the first char to alphanumeric: `\A[A-Za-z0-9][A-Za-z0-9._-]{0,252}\Z`.
  Defense-in-depth: `--` before positionals in the IR scripts.
- **Detection:** alert on `docker network connect|disconnect` (or `playbook_*.json` evidence)
  where the host arg matches `^-`.

## LOW — `_pin_host_in_target` mis-rewrites URL-form IPv6 targets

- `red-team/runner.py:344-352`. `http://[::1]:8080/x` → netloc rebuilt as `{ip}:{port}` with no
  brackets → invalid `http://::1:8080/x`. Not exploitable (lab nets are IPv4 /24s; IPv6 hosts
  fail the membership check and are rejected), but the pin path is internally inconsistent.
- **Fix:** bracket IPv6 results in the URL branch; add a test.

## LOW — IPv4-only resolution (fail-closed)

- `red-team/runner.py:333` uses `socket.gethostbyname` (A records only). An AAAA-only in-lab
  host named by hostname resolves to nothing → rejected. Fails **closed** (safe); flagged as a
  documented assumption, not a risk.

## Probed and NOT vulnerable (negative results)

1. **Format-string injection via context values** — not exploitable: values are `str.format`
   *arguments*, never re-interpolated; regex also blocks `{` `}` in host values.
2. **Shell metachar injection** (`; | $ \` & newline space`) — blocked by regex; sink is an argv
   list with no `shell=True`. Only gap was the leading-`-` flag case (above).
3. **TOCTOU / DNS-rebinding (#145 core claim)** — resolution is genuinely single; vetted IP is
   pinned before campaign import; `test_rebinding_uses_single_validated_resolution` asserts
   `call_count == 1`. `LAB_HOSTNAMES` pass by name unchanged by design (in-lab DNS, `internal:true`).
4. **userinfo@ scope escape** — `http://victim-web@evil.com/` vets as `evil.com` (urlparse
   hostname) → rejected. Non-URL `a@b` → `gethostbyname` fails → rejected.
5. **Out-of-scope slipping through / pin failing open** — no code path returns an un-vetted
   non-lab target; `_reject_target` exits non-zero on `ip is None or not in lab nets`.
6. **New SSRF / auth-bypass** — none; `/api/run-playbook` still token-gated (constant-time) +
   `playbook_id` registry allowlist; `_emit_ir_event` POSTs to a fixed URL/server-side-dated index.

No credentials, keys, or PII recorded in this file.
