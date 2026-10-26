# Code Review: pki-lab/ shell scripts
Date: 2026-08-13
Reviewer: code-reviewer sub-agent
Scope: `pki-lab/setup_ca.sh`, `pki-lab/issue_cert.sh`, `pki-lab/tls_hardening/entrypoint.sh`
Working tree: uncommitted changes present (mode-only diff, see Must Fix #1)

All findings below were reproduced empirically (not inferred) by running the
scripts against a scratch `PKI_DIR` with real `openssl`. Repro commands are
included so they can be re-verified.

---

## Must Fix

### 1. `pki-lab/setup_ca.sh` — not re-runnable at all; crashes with `Permission denied` on second run
- **Evidence (reproduced):**
  ```
  [+] Generating Root CA private key (RSA 4096)...
  genrsa: Can't open ".../root-ca/private/ca.key.pem" for writing, Permission denied
  EXIT=1
  ```
- **File:line:** `pki-lab/setup_ca.sh:36-37` (root key) and `:70-71` (intermediate key)
  ```
  36  openssl genrsa -out "$PKI_DIR/root-ca/private/ca.key.pem" 4096
  37  chmod 400 "$PKI_DIR/root-ca/private/ca.key.pem"
  ```
- **Why it matters:** The script `chmod 400`s the private keys it just wrote.
  On any subsequent run, `openssl genrsa -out <path>` opens that same path
  for writing and now fails immediately (mode 400 blocks write even for the
  owning non-root user) — this is the *first* command in the script, so the
  entire CA bootstrap aborts instantly. The task explicitly asks "can
  `setup_ca.sh` be re-run safely?" — answer: no, it cannot be re-run at all
  without a manual `rm -rf "$PKI_DIR"` or `chmod` first. This contradicts the
  `docker-compose.yml` comment at line 498 ("Idempotent: skips if certs
  already exist") — that idempotency is enforced *only* by the `pki-init`
  compose entrypoint's file-existence guard (lines 515-519), not by the
  script itself. Any user who follows the script's own fallback instructions
  in `tls_hardening/entrypoint.sh:28` (`docker compose exec pki-ca sh
  setup_ca.sh`) a second time, or any CI job that re-runs it idempotently by
  design, will get a hard crash.
- **Suggested fix:** Add an idempotency guard at the top of `setup_ca.sh`,
  e.g.:
  ```sh
  if [ -f "$PKI_DIR/intermediate-ca/certs/ca-chain.cert.pem" ]; then
      echo "[i] PKI already initialized at $PKI_DIR — skipping. Delete the directory to rebuild." >&2
      exit 0
  fi
  ```
  or explicitly document + enforce that re-running requires wiping
  `$PKI_DIR` first (`rm -rf` guarded behind a `--force` flag), rather than
  failing opaquely on an unrelated `openssl` permission error.

### 2. `pki-lab/issue_cert.sh` — re-issuing for an existing CN also crashes with `Permission denied`
- **Evidence (reproduced):**
  ```
  $ PKI_DIR=... bash pki-lab/issue_cert.sh testhost   # second time, same CN
  [+] Issuing server certificate for: testhost (IP: 172.20.0.30)
  genrsa: Can't open ".../intermediate-ca/private/testhost.key.pem" for writing, Permission denied
  EXIT=1
  ```
- **File:line:** `pki-lab/issue_cert.sh:16-17`
  ```
  16  openssl genrsa -out "$PKI_DIR/intermediate-ca/private/$CN.key.pem" 2048
  17  chmod 400 "$PKI_DIR/intermediate-ca/private/$CN.key.pem"
  ```
- **Why it matters:** Same root cause as #1 — the previous key's `chmod 400`
  blocks the next `genrsa -out` for the same CN. There is no existence check
  or `--force`/prompt before overwriting, so re-issuing a cert for a hostname
  that already has one (e.g., renewing `victim-web` after the default 365-day
  cert, or just re-running the exercise) fails with a confusing raw OpenSSL
  error instead of a clear "cert already exists, use --force to reissue"
  message.
- **Suggested fix:**
  ```sh
  KEY_PATH="$PKI_DIR/intermediate-ca/private/$CN.key.pem"
  if [ -e "$KEY_PATH" ] && [ "${FORCE:-0}" != "1" ]; then
      echo "[!] $KEY_PATH already exists. Set FORCE=1 to reissue and overwrite." >&2
      exit 1
  fi
  ```

### 3. `pki-lab/issue_cert.sh` — no CN sanitization; a CN containing `/` or `..` escapes the intended output directory
- **Evidence (reproduced):**
  ```
  $ PKI_DIR=.../ca bash pki-lab/issue_cert.sh "../../evil"
  [+] Issuing server certificate for: ../../evil (IP: 172.20.0.30)
  req: Missing '=' after RDN type string '../evil' in subject name string
  EXIT=1
  $ find .../ca -iname '*evil*'
  .../ca/evil.key.pem      <-- written OUTSIDE intermediate-ca/private/
  ```
- **File:line:** `pki-lab/issue_cert.sh:7, 16`
  ```
  7   CN="${1:-victim-web}"
  16  openssl genrsa -out "$PKI_DIR/intermediate-ca/private/$CN.key.pem" 2048
  ```
- **Why it matters:** `$CN` is user-supplied (`$1`) and interpolated directly
  into a filesystem path with no validation. `genrsa -out` runs and
  `chmod 400`s the key at the traversed location *before* the later `openssl
  req -subj` step fails on the same string (the CSR step is what actually
  rejects `../../evil`, but only because `/` is also the RDN separator in
  `-subj` syntax — that's incidental, not intentional input validation). A
  CN like `sub-ca` (no leading `..` but still containing `/`, e.g.
  `foo/bar`) would silently create `intermediate-ca/private/foo/` — failing
  with "No such file or directory" only because the subdirectory doesn't
  exist, not because the input was rejected. This is a correctness/hygiene
  gap regardless of intent — a typo with a stray `/` in `$CN` silently writes
  key material to an unexpected path. Flagging for `security-auditor` to
  assess exploitability/blast-radius further; from a code-quality lens this
  is simply missing input validation on an untrusted positional argument
  used to build a file path.
- **Suggested fix:** Validate `CN` against an allowlist pattern before using
  it in any path, e.g.:
  ```sh
  case "$CN" in
      *[!A-Za-z0-9._-]*|*/*|.*|*..*) echo "[!] Invalid CN: '$CN' (allowed: alnum, dot, dash, underscore)" >&2; exit 1 ;;
  esac
  ```

### 4. Execute bit stripped on all three reviewed scripts (uncommitted working-tree change)
- **Evidence:**
  ```
  $ git diff HEAD --stat -- pki-lab/
   pki-lab/issue_cert.sh               | 0
   pki-lab/setup_ca.sh                 | 0
   pki-lab/tls_hardening/entrypoint.sh | 0
  $ git diff HEAD -- pki-lab/setup_ca.sh
  diff --git a/pki-lab/setup_ca.sh b/pki-lab/setup_ca.sh
  old mode 100755
  new mode 100644
  ```
  `git ls-files -s` confirms the committed mode is `100755` for all three
  files — the working tree has silently dropped the exec bit on all of them.
- **Why it matters:** This is the exact regression the last five commits on
  `main` (`e66f784`, `7bacb08`, `e71fad3`, `298175e`, `a1be7e7`) were written
  to fight ("chore: preserve execute bits" / "chore: actually preserve
  execute bits" / "chore: restore execute bits (final)"). It has recurred a
  third time in the current working tree. It does not currently break the
  Docker path (the `Dockerfile` re-`chmod +x`s `entrypoint.sh`, and
  `pki-init` invokes both other scripts via explicit `sh setup_ca.sh`/`sh
  issue_cert.sh ...`), but it breaks any direct invocation
  (`./pki-lab/setup_ca.sh`, `./pki-lab/tls_hardening/entrypoint.sh` if ever
  run standalone/tested outside Docker) and will keep re-triggering the same
  "chore: restore execute bits" commit churn seen in `git log`. Given
  `MEMORY.md` already notes CRLF/mode churn as a recurring WSL2 issue on this
  repo, this is worth fixing at the root cause (likely `git config
  core.fileMode` or an editor/tool flipping bits on save) rather than
  re-committing the fix a fourth time.
- **Suggested fix:** `chmod +x pki-lab/setup_ca.sh pki-lab/issue_cert.sh
  pki-lab/tls_hardening/entrypoint.sh` before committing this changeset, and
  separately track down what's flipping the bit (check `core.fileMode`,
  editor/IDE settings, or any tooling that does a plain `cp`/extraction
  without preserving modes) so the next `git status` doesn't show the same
  mode-only diff again.

---

## Should Fix

### 5. `pki-lab/issue_cert.sh` — `CERT_TYPE` (4th positional arg) undocumented in usage comment
- **File:line:** `pki-lab/issue_cert.sh:3, 11`
  ```
  3   # Usage: bash issue_cert.sh <common_name> [san_ip] [san_dns]
  ...
  11  CERT_TYPE="${4:-server}"  # server or client
  ```
- **Why it matters:** A fourth positional argument exists and materially
  changes behavior (`extendedKeyUsage`), but the usage banner doesn't mention
  it — a maintainer reading only the header comment won't discover
  client-cert issuance is supported.
- **Suggested fix:** Update the usage comment to `Usage: bash issue_cert.sh
  <common_name> [san_ip] [san_dns] [cert_type: server|client]`.

### 6. Neither script guards against missing prerequisites before doing partial work
- **File:line:** `pki-lab/issue_cert.sh:16` (assumes `setup_ca.sh` has already
  run and `intermediate-ca/private/intermediate.key.pem` exists)
- **Why it matters:** If `issue_cert.sh` is run before `setup_ca.sh`, it
  generates a leaf key/CSR (real filesystem side effects) before failing
  deep in the signing step (`-CAkey ".../intermediate.key.pem"` not found),
  leaving orphaned key/CSR files and a raw OpenSSL error rather than the
  friendly guidance already established as the house style in
  `tls_hardening/entrypoint.sh:16-38`.
- **Suggested fix:** Add an early check —
  `[ -f "$PKI_DIR/intermediate-ca/private/intermediate.key.pem" ] || { echo
  "[!] No intermediate CA found at $PKI_DIR. Run setup_ca.sh first." >&2;
  exit 1; }` — before generating any key material.

### 7. No `trap` cleanup for temp files on error exit
- **File:line:** `pki-lab/setup_ca.sh:41,64` and `:82,99`; `pki-lab/issue_cert.sh:26,48`
  ```
  41  ROOT_CONF=$(mktemp)
  ...
  64  rm -f "$ROOT_CONF"
  ```
- **Why it matters:** Under `set -e`, if the `openssl` command between the
  `mktemp` and the `rm -f` fails, the script exits immediately and the `rm
  -f`/`rm` cleanup line is never reached, leaking a temp file per failed run.
  Low severity (temp file contents are non-sensitive DN/extension config,
  not key material), but it's a real gap in an otherwise `set -euo pipefail`
  disciplined pair of scripts, and multiplies across CI/exercise re-runs.
- **Suggested fix:** `trap 'rm -f "$ROOT_CONF"' EXIT` immediately after each
  `mktemp` call, instead of a manual `rm -f` at the end of the happy path.

---

## Consider

### 8. `pki-lab/setup_ca.sh:27-30` — `serial`/`crlnumber` files are dead scaffolding
  ```
  27  echo 1000 > "$PKI_DIR"/root-ca/serial
  28  echo 1000 > "$PKI_DIR"/intermediate-ca/serial
  29  echo 1000 > "$PKI_DIR"/root-ca/crlnumber
  30  echo 1000 > "$PKI_DIR"/intermediate-ca/crlnumber
  ```
  These `serial`/`crlnumber`/`index.txt` files are the state files consumed
  by the `openssl ca` subcommand and its config-driven CRL generation. Both
  scripts actually sign certs with `openssl x509 -req -CAcreateserial` (its
  own independent `<CAfile>.srl` sidecar), and neither script ever calls
  `openssl ca -gencrl`. So these four files (plus the `crl/` directories
  created at line 21) are never read or written again — they imply a
  revocation/CRL workflow that doesn't actually exist, which could mislead a
  future maintainer (or a student in the SY0-701 exercise) into thinking CRL
  generation is wired up. Either remove the unused scaffolding, or note in a
  comment that CRL generation is intentionally out of scope for this lab.

### 9. `pki-lab/setup_ca.sh:118-121` / `pki-lab/issue_cert.sh:54-57` — verification failure produces no custom message
  ```
  119  openssl verify -CAfile "$PKI_DIR/root-ca/certs/ca.cert.pem" \
  120      "$PKI_DIR/intermediate-ca/certs/intermediate.cert.pem" && \
  121      echo "[✓] Certificate chain verified successfully"
  ```
  This relies on `set -e` to abort the script if `openssl verify` fails
  (confirmed correct — a bare `cmd1 && cmd2` at top level does propagate
  `cmd1`'s failure through `set -e`), so it isn't broken, but the failure
  path prints only OpenSSL's own stderr with no `[✗]`-style message matching
  the rest of the script's UX. Consider `|| { echo "[✗] Chain verification
  failed" >&2; exit 1; }` for consistency.

### 10. `pki-lab/issue_cert.sh:34` — no format validation on `SAN_IP`
  A non-IP value passed as `$2` (e.g., a hostname by mistake) fails deep
  inside the `openssl x509 -req -extfile` step with a raw "unable to parse IP
  address" error rather than a clear pre-check. Low priority since `set -e`
  still stops the script safely, but worth a one-line `case` check for a
  friendlier failure message given the CN input-handling gap in #3 above.

---

## Looks Good

- All three scripts use `set -euo pipefail` (bash) / `set -eu` (POSIX sh)
  consistently, and `shellcheck` reports zero warnings on all three files
  (`shellcheck pki-lab/setup_ca.sh pki-lab/issue_cert.sh` and `shellcheck -s
  sh pki-lab/tls_hardening/entrypoint.sh` all exit 0).
- Quoting is consistently correct throughout — every path expansion involving
  `$PKI_DIR`, `$CN`, etc. is double-quoted; no unquoted-variable word-splitting
  bugs found.
- `pki-lab/tls_hardening/entrypoint.sh` is a good example of defensive
  scripting for a Docker entrypoint: it checks both required files exist
  before starting nginx, prints a single actionable, copy-pasteable remediation
  block instead of letting the container crash-loop through nginx's own
  cryptic SSL errors, and correctly `exec`s nginx as PID 1 (line 44) so
  signals propagate for clean container shutdown.
- Private key files are `chmod 400`'d immediately after generation in both
  `setup_ca.sh` and `issue_cert.sh` (before any other step touches them) —
  good default-permissions hygiene, and directories are `mkdir -p` before
  `chmod 700` in the correct order.
- The `docker-compose.yml` `pki-init` service already recognizes this problem
  space and has a file-existence idempotency guard *at the orchestration
  layer* (lines 515-519) — that pattern should simply be pushed down into
  `setup_ca.sh`/`issue_cert.sh` themselves per Must-Fix #1/#2, since the
  guard doesn't help anyone who runs the scripts directly (as the scripts'
  own error messages tell people to do).

---

## Verdict

**Approve with conditions** — the scripts are clean, well-quoted, and
`shellcheck`-clean, but they fail the core "can this be safely re-run"
requirement (Must Fix #1, #2 — reproduced, not theoretical: both crash with
`Permission denied` on a second run) and have no input validation on the
user-controlled `CN` argument that is used to build filesystem paths (Must
Fix #3 — reproduced path escape to `evil.key.pem` outside the intended
directory). Fix #1–#4 before merging; #5–#7 should be addressed in the same
pass since they're small; #8–#10 are polish.
