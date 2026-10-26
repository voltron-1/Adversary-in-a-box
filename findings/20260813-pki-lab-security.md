# PKI-Lab Security Audit — 2026-08-13

## Scope

In scope, all under ``:
`pki-lab/setup_ca.sh`, `pki-lab/issue_cert.sh`, `pki-lab/tls_hardening/{entrypoint.sh,Dockerfile,nginx-tls.conf,cipher_audit.py}`, `pki-lab/certs/README.md`, `pki-lab/exercises/*.md`.
Pulled in as directly-coupled context: `docker-compose.yml:472-541` (pki profile), `.gitignore:223-234`, `scripts/lab/reset.sh`, `.github/workflows/integration.yml:76-102`, `blue-team/detection/zeek/local.zeek`, `siem/logstash/pipelines/zeek.conf`, `tests/test_pki.py`.

Stack: bash/POSIX-sh + OpenSSL 3.x two-tier RSA PKI, nginx-alpine TLS terminator, Docker Compose `pki` profile on an internal `lab-net`.

Verified negative (good): **no key material is committed.** Glob for `**/*.{pem,key,crt,csr,p12,pfx}` returned nothing, and a repo-wide grep for `BEGIN ... PRIVATE KEY` returned nothing. `.gitignore:223-234` correctly excludes `pki-lab/ca/`, `pki-lab/certs/*`, and all key/cert extensions. Also good: `setup_ca.sh:25` chmods the `private/` dirs to `700` *before* any key is written, and both CA keys are RSA-4096 with `chmod 400`.

Assumption stated: this is a deliberately-vulnerable training lab on an air-gapped `internal: true` network. I calibrated severity to "does this break the lesson, destroy the lab, or teach a wrong control" rather than to production data loss — that is why nothing is rated CRITICAL.

**Summary: 3 HIGH, 7 MEDIUM, 9 LOW, 4 INFO. No CRITICAL.**
Most important: `pki-lab/issue_cert.sh` interpolates unvalidated positional args (`CN`, `SAN_IP`, `SAN_DNS`) into both an OpenSSL extension file and five filesystem paths — yielding arbitrary SAN injection (mint a lab-CA-signed cert for any name) and a one-word CA-key destruction primitive (`sh issue_cert.sh intermediate` overwrites the Intermediate CA private key inside the root-running `pki-init`/`pki-ca` containers).
Second-order theme: the lab's only TLS verification control, `cipher_audit.py`, fabricates PASS results when it cannot connect and can never detect a weak protocol — the audit tool provides false assurance.

---

## HIGH

---
**[HIGH] OpenSSL extension-file injection via unvalidated CN/SAN arguments**
- **MITRE ATT&CK**: T1587.003 (Develop Capabilities: Digital Certificates), T1649 (Steal or Forge Authentication Certificates), enabling T1557 (Adversary-in-the-Middle)
- **Red Team**: Every positional arg is pasted raw into an OpenSSL config. No newline or shell metachar is even required — a comma suffices. `sh issue_cert.sh victim-web 172.20.0.30 'x, DNS:*.lab.local, IP:172.20.0.30'` produces a cert the lab Intermediate CA signs as valid for **every** lab hostname and the victim-web IP. Since `nginx-tls.conf:11` trusts `ca-chain.cert.pem` and Exercise 03 teaches pinning against this chain, the attacker gets a chain-valid impersonation cert and silently defeats the pinning/stapling lesson. With an embedded newline the injection escalates: `basicConstraints = critical,CA:TRUE` and `keyUsage = keyCertSign` appended after line 34 turn a leaf into a subordinate CA (OpenSSL's `NCONF` stores section values in a hash where a later duplicate name replaces the earlier, so the injected directive should win over the `CA:FALSE` on line 29 — I could not execute openssl to confirm last-wins empirically; recommend the tester-debugger agent validate this specific variant. The SAN-injection half needs no such assumption and is unconditional).
- **Blue Team**: No control exists. There is no allow-list on CN/SAN, no post-issuance assertion that the emitted cert's SAN set equals the requested set, and — critically — **no issuance audit trail anywhere in the SIEM**. A grep of `blue-team/` for `T1649`, `T1552.004`, `key.pem`, or `private key` returns nothing.
- **Evidence**: `pki-lab/issue_cert.sh:7-9` and `:26-35`:
  ```
  CN="${1:-victim-web}"
  SAN_IP="${2:-172.20.0.30}"
  SAN_DNS="${3:-$CN.lab.local}"
  ...
  subjectAltName = IP:$SAN_IP, DNS:$SAN_DNS, DNS:$CN
  ```
- **Recommendation**: Validate before use — `printf '%s' "$CN" | grep -Eq '^[A-Za-z0-9]([A-Za-z0-9.-]{0,62})$' || { echo "invalid CN"; exit 2; }` and an equivalent IPv4 regex for `SAN_IP`, plus a DNS-label regex for `SAN_DNS`; reject anything containing `,`, `:`, newline, or `/`. Then re-read the issued cert and assert the SAN list matches: `openssl x509 -noout -ext subjectAltName` diffed against the expected string. Move `basicConstraints = critical, CA:FALSE` to the *last* line of the ext file as defence in depth.
---

---
**[HIGH] Path traversal in `$CN` destroys the CA private keys (`issue_cert.sh intermediate`)**
- **MITRE ATT&CK**: T1485 (Data Destruction), T1499 (Endpoint Denial of Service)
- **Red Team**: `$CN` is concatenated into five filesystem paths with no sanitisation, and the leaf key is written into the *CA's own* `private/` directory. `sh issue_cert.sh intermediate` resolves `-out "$PKI_DIR/intermediate-ca/private/$CN.key.pem"` to `intermediate.key.pem` — the exact filename of the Intermediate CA private key — and `openssl genrsa` truncates it with a fresh 2048-bit key. Line 38's signing step then fails on a key/cert mismatch, leaving the CA permanently unusable. `CN='../../root-ca/private/ca'` reaches the **Root CA key** (`private/` → `intermediate-ca/` → `ca/` → `root-ca/private/ca.key.pem`). The `chmod 400` on those files does not protect them: `pki-init` and `pki-ca` run as root (`docker-compose.yml:502-541`), and root ignores the write bit. Recovery is not automatic — `scripts/lab/reset.sh` never deletes `pki-lab/ca/`, and `docker-compose.yml:515-519` skips re-bootstrap whenever `certs/` is populated. One typo by a student bricks the PKI profile for the whole class.
- **Blue Team**: Nothing detects or prevents it. No integrity check on the CA key (no stored fingerprint), no write-protection of the CA tree, and `pki-init`'s idempotence check inspects `certs/` rather than validating that the CA keypair still matches its certificate.
- **Evidence**: `pki-lab/issue_cert.sh:16-17`:
  ```
  openssl genrsa -out "$PKI_DIR/intermediate-ca/private/$CN.key.pem" 2048
  ```
  and `:22`, `:39`, `:43`, `:62` reuse `$CN` in paths identically.
- **Recommendation**: Apply the CN regex from the previous finding (it forbids `/` and `..` by construction), and additionally refuse reserved basenames: `case "$CN" in ca|intermediate|root) echo "reserved name"; exit 2;; esac`. Separately, add a guard before `genrsa`: `[ -e "$KEYPATH" ] && { echo "refusing to overwrite existing key $KEYPATH"; exit 3; }`.
---

---
**[HIGH] `cipher_audit.py` fabricates PASS results and can never detect a weak protocol**
- **MITRE ATT&CK**: Defensive control failure against T1040 / T1557 preconditions (weak TLS)
- **Red Team**: The lab's only TLS verification tool reports a clean bill of health for a host that does not exist. Against an unreachable or non-TLS target, `get_certificate_info` returns `{"error": ...}`, the tool announces `"[i] Running in simulation mode..."` and then *invents* results: TLS1.3 accepted=True→PASS, TLS1.2→PASS, and TLS1.0/1.1 return PASS from the bare `except Exception` handler. Output: `Results: 4 PASS / 0 FAIL`. An attacker who downgrades or misconfigures a service gets a green audit. Worse, the TLS1.0/1.1 probes are structurally incapable of failing: modern Python/OpenSSL 3.x refuses to *offer* TLS < 1.2 at the default security level, so `ctx.wrap_socket` raises `SSLError` **client-side** and line 38 returns PASS no matter what the server accepts. And because only the *negotiated* version is recorded (lines 102-104), a server that still permits TLS 1.0–1.2 but happens to negotiate 1.3 is reported as rejecting them.
- **Blue Team**: `WEAK_CIPHERS` and `WEAK_PROTOCOLS` are declared (lines 15-17) and **never referenced** — the tool advertises cipher auditing it does not perform. `WEAK_PROTOCOLS = {ssl.PROTOCOL_TLS_CLIENT}` is semantically wrong; that constant is the modern client protocol, not a weak one. Cert inspection is also dead: with `verify_mode = ssl.CERT_NONE` (line 48), CPython's `getpeercert()` returns an empty dict, so `subject`/`issuer`/`not_after` are permanently `Unknown` and expiry is never evaluated. `tests/test_pki.py:34-40` asserts only that a dict comes back, codifying the false-PASS behaviour as expected.
- **Evidence**: `pki-lab/tls_hardening/cipher_audit.py:39-40`, `:83`, `:105-106`:
  ```
  except Exception as e:
      return {"version": version_name, "accepted": False, "status": "PASS", "note": str(e)}
  ...
  print("[i] Running in simulation mode...")
  ...
  accepted = version_name == "TLSv1.3"  # Simulate good config
  ```
- **Recommendation**: Delete simulation mode — on connection failure exit non-zero with `status: ERROR`, never `PASS`. Distinguish `ssl.SSLError` (server rejected → genuine PASS) from `OSError`/`socket.timeout` (unreachable → ERROR). Force the client to actually offer legacy protocols with `ctx.set_ciphers("ALL:@SECLEVEL=0")` alongside `minimum_version`/`maximum_version`, and skip-with-ERROR if the local OpenSSL refuses to build the context. Probe TLS1.2 and TLS1.3 explicitly with pinned min==max rather than inferring from the negotiated version. Use `ssl.CERT_REQUIRED` with `cafile=ca-chain.cert.pem` in a second pass so `getpeercert()` populates, then assert `notAfter` is > 30 days out. Wire `WEAK_CIPHERS` into a real check against `ssock.cipher()[0]` or delete the constants.
---

## MEDIUM

---
**[MEDIUM] Root CA private key is unencrypted and permanently online in a read-write bind mount**
- **MITRE ATT&CK**: T1552.004 (Unsecured Credentials: Private Keys), T1649
- **Red Team**: `setup_ca.sh:36` generates the Root CA key with no `-aes256` passphrase, and `docker-compose.yml:538` mounts the entire `./pki-lab` tree — Root CA key included — **read-write** into `pki-ca`, a long-running container (`entrypoint: tail -f /dev/null`, `restart: unless-stopped`) sitting on `lab-net` at a fixed `172.20.0.71`, alongside the intentionally vulnerable victim containers. Any code execution in `pki-ca`, or any `docker exec`/socket access, yields the trust anchor for the whole lab — mint anything, for any name, with no `pathlen` ceiling. This directly contradicts the lesson the lab teaches: `pki-lab/exercises/01-build-your-ca.md:12` states "Root CA: The trust anchor. Kept offline in real deployments."
- **Blue Team**: No separation between the offline root and the online issuing CA, no passphrase, no HSM/softhsm simulation, and no file-access auditing on the key. Nothing logs a read of `ca.key.pem`.
- **Evidence**: `pki-lab/setup_ca.sh:36` `openssl genrsa -out "$PKI_DIR/root-ca/private/ca.key.pem" 4096` (no `-aes256`); `docker-compose.yml:530-541` (`pki-ca`, `- ./pki-lab:/workspace`, no `:ro`).
- **Recommendation**: Have `pki-init` `cp` only `intermediate-ca/` + `certs/` into the long-lived container, or mount `./pki-lab/ca/root-ca` `:ro` and drop it from `pki-ca` entirely. Teach the real control by encrypting the root key (`openssl genrsa -aes256 -passout env:ROOT_CA_PASS`) and having the exercise prompt for it — the intermediate can stay unencrypted for automation. Add a `README` note that the root key directory would be an offline HSM in production.
---

---
**[MEDIUM] The CA has no working revocation path — `openssl ca` database bypassed, no CRL DP, no AIA**
- **MITRE ATT&CK**: T1649 (a stolen leaf key cannot be invalidated)
- **Red Team**: `setup_ca.sh:26-30` builds `index.txt`, `serial`, and `crlnumber` for both CAs, but neither script ever calls `openssl ca` — issuance uses `openssl x509 -req -CAcreateserial` (`issue_cert.sh:38-46`), which writes to a separate `.srl` file and **never records the certificate in `index.txt`**. Consequently the lab has no issuance ledger: a rogue cert minted via the SAN-injection finding above leaves no trace in the CA database. Additionally, the leaf extension block (`issue_cert.sh:27-35`) contains no `crlDistributionPoints` and no `authorityInfoAccess`, so no relying party can discover revocation status at all. Exercise 02 step 4 instructs students to revoke via `openssl ca -revoke` against an index that has no matching row, so the exercise does not exercise the mechanism it claims to.
- **Blue Team**: `nginx-tls.conf:30-31` sets `ssl_stapling on; ssl_stapling_verify on;` against certificates that carry no OCSP responder URI — nginx will log `"ssl_stapling" ignored, no OCSP responder URL in the certificate` and serve no staple, while Exercise 03 tells the student to look for `OCSP Response Status: successful`. The student is trained to accept a control that is silently inert. Exercise 03:19 further recommends `resolver 8.8.8.8 valid=300s;` — an external DNS resolver on a network declared `internal: true`, which both cannot work and contradicts the lab's air-gap safety model.
- **Evidence**: `pki-lab/setup_ca.sh:26-30` (`index.txt`/`serial`/`crlnumber` created); `pki-lab/issue_cert.sh:38-46` (`openssl x509 -req ... -CAcreateserial`, bypassing the DB); `pki-lab/tls_hardening/nginx-tls.conf:30-31`; `pki-lab/exercises/03-pinning-and-stapling.md:19`.
- **Recommendation**: Switch `issue_cert.sh` to `openssl ca -config <openssl.cnf> -extensions ext -notext -in ... -out ...` so `index.txt` becomes the real ledger and `-revoke`/`-gencrl` work as the exercises describe. Add to the leaf ext block: `crlDistributionPoints = URI:http://pki-ca.lab.local/crl/intermediate.crl.pem` and `authorityInfoAccess = OCSP;URI:http://pki-ca.lab.local:2560`. Either stand up `openssl ocsp -port 2560 -index ... -CA ...` in the `pki-ca` container so stapling genuinely works, or set `ssl_stapling off` with an inline comment explaining why, and delete the `resolver 8.8.8.8` line from Exercise 03.
---

---
**[MEDIUM] CA and leaf keys survive `reset.sh` and are reused by every cohort indefinitely**
- **MITRE ATT&CK**: T1552.004
- **Red Team**: `scripts/lab/reset.sh` is documented as the instructor's "start a new class run" action and wipes `evidence/*` (step 3) and all named volumes (step 2, line 89), but it never touches `pki-lab/ca/` or `pki-lab/certs/`. Meanwhile `docker-compose.yml:515-519` short-circuits the bootstrap whenever the three staged files exist. Net effect: the Root CA key generated on day one is still the trust anchor for every subsequent class. A student in cohort 1 who exfiltrates `victim-web.key.pem` (which Exercise 02 step 3 deliberately deploys into the vulnerable `victim-web` container) retains a working impersonation key against cohort 5 — and there is no revocation path (previous finding) to stop them. The files are also root-owned via the container write, so an unprivileged instructor cannot clean them up without `sudo`.
- **Blue Team**: No key rotation, no expiry-driven regeneration, no fingerprint pinning that would reveal reuse across runs.
- **Evidence**: `docker-compose.yml:515-519`:
  ```
  if [ -f certs/victim-web.cert.pem ] && [ -f certs/victim-web.key.pem ] \
     && [ -f certs/ca-chain.cert.pem ]; then
    echo "[pki-init] certs already present -- skipping CA bootstrap"
    exit 0
  ```
  and `scripts/lab/reset.sh:88-90` (only `docker compose down -v`; no `pki-lab/ca` removal).
- **Recommendation**: Add a step to `reset.sh` — `docker run --rm -v "$PWD/pki-lab:/w" alpine sh -c 'rm -rf /w/ca /w/certs/*.pem'` (root-owned files need a root context to remove) — gated behind the existing confirmation prompt, so every class run gets a fresh trust anchor. Document in `pki-lab/certs/README.md` that the CA is ephemeral per class.
---

---
**[MEDIUM] Server private keys are stored inside the Intermediate CA's `private/` directory**
- **MITRE ATT&CK**: T1552.004
- **Red Team**: Every issued leaf key is written to `$PKI_DIR/intermediate-ca/private/`, the same directory holding `intermediate.key.pem`. One directory read — via a container escape, a misconfigured bind mount, or the `pki-ca` shell — yields the signing key *and* every subscriber key simultaneously. It also creates the filename collision exploited in the HIGH path-traversal finding above.
- **Blue Team**: No separation of duties between CA key storage and subscriber key storage; a single ACL protects assets with radically different blast radii.
- **Evidence**: `pki-lab/issue_cert.sh:16-17` and `:51` (`Private key: $PKI_DIR/intermediate-ca/private/$CN.key.pem`).
- **Recommendation**: Emit subscriber keys to a sibling tree, e.g. `mkdir -p "$PKI_DIR/issued/$CN" && KEY="$PKI_DIR/issued/$CN/key.pem"`, leaving `intermediate-ca/private/` containing exactly one file. Update `docker-compose.yml:525` and `pki-lab/certs/README.md` to the new path.
---

---
**[MEDIUM] Zeek `validate-certs` will alarm on every legitimate lab TLS connection; `x509.log` is not shipped**
- **MITRE ATT&CK**: Detection coverage gap for T1557 / T1649
- **Red Team**: `blue-team/detection/zeek/local.zeek:14` loads `policy/protocols/ssl/validate-certs`, which validates against Zeek's bundled Mozilla root store. The lab Root CA is not in that store and there is **no `redef SSL::root_certs`** anywhere in the repo (grep confirms zero hits). Every single connection to `pki-nginx` therefore raises `SSL::Invalid_Server_Cert`, and `siem/logstash/pipelines/zeek.conf:10` ships `notice.log` straight into Elasticsearch. An attacker presenting a forged or self-signed cert produces an alert that is indistinguishable from the constant baseline noise — textbook alert-fatigue evasion.
- **Blue Team**: Only `conn/dns/http/ssh/ssl/notice` logs are shipped (`zeek.conf:10`); `x509.log` is absent, so analysts cannot pivot on certificate subject, issuer, validity window, or SHA-1 fingerprint — exactly the fields needed to spot a rogue cert. There is no detection anywhere in `blue-team/` for certificate theft or forgery (grep for `T1649`, `T1552.004`, `key.pem`, `id_rsa` across `blue-team/` returns nothing), and no logging of certificate issuance events from the PKI itself.
- **Evidence**: `blue-team/detection/zeek/local.zeek:14` `@load policy/protocols/ssl/validate-certs`; `siem/logstash/pipelines/zeek.conf:10` (log list omits `x509.log`).
- **Recommendation**: Add `redef SSL::root_certs += { ["Lab Root CA"] = <DER blob> };` to `local.zeek` — or, simpler for a lab, suppress `SSL::Invalid_Server_Cert` for `172.20.0.70` via a `Notice::policy` hook — so the notice retains signal. Add `/zeek-logs/x509.log` to the Logstash input list. Then write the missing detection: alert on any `x509.log` entry whose issuer is not the lab Intermediate CA, and have `issue_cert.sh` emit a structured issuance event (CN, SAN set, serial, requester) to `/evidence/` or syslog so forged certs can be diffed against the issuance ledger.
---

---
**[MEDIUM] CI "TLS works" gate passes on a redirect loop or a 502, and validates nothing about the chain**
- **MITRE ATT&CK**: N/A (test-integrity failure)
- **Red Team**: The G3a gate accepts *any* HTTP status other than the connection-failure sentinel `000`, and uses `curl -sk` — `-k` disables verification of the very chain the job just bootstrapped. A broken TLS config, an expired cert, a wrong-CN cert, a 502, or the redirect loop described in the next finding all report "pki-nginx served a TLS response (G3a verified)". The regression net is therefore blind to the failure modes it exists to catch.
- **Blue Team**: No assertion on negotiated protocol version, cipher, chain validity, or response body — so none of the hardening in `nginx-tls.conf` is actually regression-tested. `tests/test_pki.py:162-167` only greps the config file text for the string `TLSv1.3`, which cannot detect a runtime override.
- **Evidence**: `.github/workflows/integration.yml:93-95`:
  ```
  code=$(docker exec "$NGINX" curl -sk -o /dev/null -w '%{http_code}' https://localhost:443/ 2>/dev/null || true)
  ...
  if [ -n "$code" ] && [ "$code" != "000" ]; then ok=1; break; fi
  ```
- **Recommendation**: Replace `-k` with `--cacert /etc/nginx/ssl/ca-chain.cert.pem --resolve victim-web.lab.local:443:127.0.0.1` and require `[ "$code" = "200" ]`. Add a protocol assertion: `docker exec "$NGINX" openssl s_client -connect localhost:443 -tls1_2 </dev/null` must **fail**, and `-tls1_3` must succeed.
---

---
**[MEDIUM] `proxy_pass http://127.0.0.1:80` loops back into the HTTP→HTTPS redirect block**
- **MITRE ATT&CK**: N/A (availability / config correctness)
- **Red Team**: The TLS vhost proxies to `127.0.0.1:80` inside its own container, where the only listener is the port-80 server block that `return 301 https://$server_name$request_uri`. A client hitting `https://host:8443/` gets that 301 relayed back, pointing at `https://victim-web.lab.local/` — `$server_name` omits the published port `8443`, so the browser retries a port that is not mapped. The hardened endpoint serves no content at all, and combined with the CI gate above (which accepts the 301) the breakage ships silently. Students conclude their hardened config "works".
- **Blue Team**: No healthcheck in the Dockerfile and no body/status assertion anywhere would surface this.
- **Evidence**: `pki-lab/tls_hardening/nginx-tls.conf:42` `proxy_pass http://127.0.0.1:80;` against `:51-55` (`listen 80; server_name victim-web.lab.local; return 301 ...`).
- **Recommendation**: Point the upstream at the actual application container — `proxy_pass http://victim-web:80;` (both are on `lab-net`) — or serve a static `root /usr/share/nginx/html;` from the TLS block. In the redirect block use `return 301 https://$host$request_uri;` so a non-default port survives, and restrict that block with `if ($http_host = "")` hardening or a `default_server` catch-all.
---

## LOW

---
**[LOW] Keys are written with default umask before `chmod 400` (TOCTOU window)**
- **Red Team**: `openssl genrsa -out` creates the file at `0644 & ~umask` and the file exists in that state for the entire duration of 4096-bit key generation; `chmod 400` only runs afterward. On a shared host another local user could read the key mid-generation. **Largely mitigated** — `setup_ca.sh:25` sets the `private/` directories to `0700` before any key is written, so the file is unreachable in practice. The residual gap is `issue_cert.sh`, which is often run standalone and assumes those dirs already exist.
- **Blue Team**: No `umask` hardening at script scope.
- **Evidence**: `pki-lab/setup_ca.sh:36-37` and `pki-lab/issue_cert.sh:16-17` (`genrsa` then `chmod 400`).
- **Recommendation**: Add `umask 077` immediately after `set -euo pipefail` in both scripts, and have `issue_cert.sh` assert the private dir exists with mode 700 before writing.
---

---
**[LOW] `server_tokens` not disabled — nginx version disclosed**
- **MITRE ATT&CK**: T1592.002 (Gather Victim Host Information: Software)
- **Red Team**: The stock nginx defaults to `server_tokens on`, so the `Server:` header and error pages leak the exact version, feeding version-specific exploit selection. The config is presented as the hardening reference for Exercise 3.2 and omits it.
- **Blue Team**: N/A — prevention only.
- **Evidence**: `pki-lab/tls_hardening/nginx-tls.conf` — no `server_tokens` directive anywhere in the file.
- **Recommendation**: Add `server_tokens off;` to both server blocks (or better, hoist to an `http`-level snippet).
---

---
**[LOW] Entrypoint does not validate `ca-chain.cert.pem`, and `restart: unless-stopped` defeats its fail-fast intent**
- **Red Team**: N/A (availability/UX).
- **Blue Team**: `entrypoint.sh:14` checks only `$CERT` and `$KEY`, but `nginx-tls.conf:11` requires `ssl_trusted_certificate .../ca-chain.cert.pem` and `ssl_stapling_verify on` depends on it — a partial staging yields the wall-of-errors the entrypoint was written to prevent. Separately, `docker-compose.yml:494` sets `restart: unless-stopped` on `pki-nginx`, which restarts the container on *any* exit code, so the "print once and exit" design still produces a loop — just of the nicer message.
- **Evidence**: `pki-lab/tls_hardening/entrypoint.sh:11-14` (only `CERT`/`KEY` defined and tested); `docker-compose.yml:494`.
- **Recommendation**: Add `CHAIN=/etc/nginx/ssl/ca-chain.cert.pem` to the existing `-f` test. Change `pki-nginx` to `restart: on-failure:3`, or keep `unless-stopped` and have the entrypoint `sleep 30` before exiting so logs stay readable.
---

---
**[LOW] Dockerfile: base image pinned by tag not digest; `curl` added to a TLS-terminating image**
- **MITRE ATT&CK**: T1195.002 (Supply Chain Compromise: Software Supply Chain); T1105 (Ingress Tool Transfer) for the `curl` half
- **Red Team**: A mutable tag can be re-pushed; without a digest the build is not reproducible and a poisoned rebuild is undetectable. `apk add curl` puts a fully-featured HTTP client in the container that holds the server private key — a ready-made exfil/download primitive post-compromise. Dependabot is configured for this directory (`.github/dependabot.yml:88`), which covers version currency but not integrity.
- **Blue Team**: No image digest pinning, no SBOM, no `--no-install-recommends`-equivalent minimisation review.
- **Evidence**: `pki-lab/tls_hardening/Dockerfile:1` `FROM nginx:1.31.3-alpine` and `:7` `RUN apk add --no-cache curl`.
- **Recommendation**: Pin as `FROM nginx:1.31.3-alpine@sha256:<digest>` (Dependabot updates digests too). Move `curl` behind a build arg — `ARG WITH_DEBUG_TOOLS=0` — so the default image ships without it and CI opts in explicitly; note the CI TLS gate at `integration.yml:93` currently depends on `curl` being present, so update that step in the same change.
---

---
**[LOW] Weak security-header details: deprecated XSS header, incomplete CSP, `preload` on a `.lab.local` name**
- **Red Team**: `X-XSS-Protection: 1; mode=block` is deprecated and its filter has been a source of information-disclosure bugs; modern guidance is `0`. The CSP omits `frame-ancestors 'none'`, `object-src 'none'`, `base-uri 'self'`, and `form-action 'self'`, leaving base-tag hijacking and plugin/embed vectors open despite `X-Frame-Options` covering only framing. `preload` on a non-public `.lab.local` name is inert here, but students copy hardening snippets verbatim — submitting a shared production domain to the preload list is effectively irreversible.
- **Blue Team**: No CSP `report-uri`/`report-to`, so violations produce no telemetry for the SIEM.
- **Evidence**: `pki-lab/tls_hardening/nginx-tls.conf:34-39`.
- **Recommendation**: Set `X-XSS-Protection "0"`; extend CSP to `default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'`; add a comment on line 34 warning that `preload` must not be copied to a shared production domain.
---

---
**[LOW] `pki-lab/certs/README.md` documents non-existent paths for hand-copying a private key**
- **Red Team**: N/A directly; the failure mode is a student copy-pasting private-key handling commands that silently target the wrong path.
- **Blue Team**: The README is labelled "the canonical instructions" by `entrypoint.sh:37`, yet `entrypoint.sh:25` explicitly contradicts it ("note: intermediate-ca, not intermediate"). Two authoritative sources disagree about where the CA private key lives.
- **Evidence**: `pki-lab/certs/README.md:17-19` uses `pki-lab/ca/intermediate/...`; the actual tree created at `setup_ca.sh:20` is `intermediate-ca`. Line 13-14 of the README also omits `--profile pki` from the `docker compose exec` calls.
- **Recommendation**: Correct lines 17-19 to `intermediate-ca`, and replace the manual block with a pointer to the `pki-init` one-shot so there is exactly one documented procedure.
---

---
**[LOW] Temporary OpenSSL config files are not cleaned up on failure**
- **Red Team**: Low value — the files contain DN and extension text, not key material — but under `set -e` a failed `openssl` call aborts before `rm`, leaving predictable `/tmp` residue that reveals the requested SAN set on a shared host.
- **Blue Team**: No `trap` handler in either script.
- **Evidence**: `pki-lab/setup_ca.sh:41`/`:64` and `:82`/`:99`; `pki-lab/issue_cert.sh:26`/`:48`.
- **Recommendation**: `trap 'rm -f "$ROOT_CONF" "$INT_EXT"' EXIT INT TERM` after the first `mktemp` in each script (BusyBox ash supports `trap ... EXIT`).
---

---
**[LOW] Intermediate CA has no `nameConstraints`**
- **MITRE ATT&CK**: T1553.004 (Subvert Trust Controls: Install Root Certificate)
- **Red Team**: The intermediate is constrained only by `pathlen:0` and can sign a cert for *any* name on earth. Today the blast radius is contained because nothing installs the lab root into a system trust store (grep for `update-ca-certificates` / `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` finds no such step). But the pinning exercise nudges students toward trusting the chain, and a student who imports `ca.cert.pem` into their host or browser store hands the lab CA authority over `*.google.com` on their own machine.
- **Blue Team**: No constraint enforcement, and no warning in the exercises about the consequences of importing the root.
- **Evidence**: `pki-lab/setup_ca.sh:83-89` — the `[v3_ca]` block for the intermediate contains `basicConstraints`, `subjectKeyIdentifier`, `authorityKeyIdentifier`, `keyUsage` and no `nameConstraints`.
- **Recommendation**: Add `nameConstraints = critical, permitted;DNS:.lab.local, permitted;IP:172.20.0.0/255.255.0.0` to the intermediate's extension block — it is also a directly examinable Security+ 3.9 concept the lab currently skips. Add a bold warning in Exercise 01 against importing the root into a real trust store.
---

---
**[LOW] Leaf keys are RSA-2048 only; the ECDSA cipher suite listed first can never be selected**
- **Red Team**: RSA-2048 remains acceptable, so this is not an exploitable weakness. The issue is coherence: `nginx-tls.conf:18` lists `ECDHE-ECDSA-AES256-GCM-SHA384` ahead of the RSA suite, but `issue_cert.sh:16` can only ever produce RSA keys, so the ECDSA suite is unreachable. The lab teaches a cipher preference it cannot demonstrate.
- **Blue Team**: N/A.
- **Evidence**: `pki-lab/issue_cert.sh:16` (`genrsa ... 2048`) vs `pki-lab/tls_hardening/nginx-tls.conf:18`.
- **Recommendation**: Add a `KEY_ALG` variable supporting `openssl ecparam -genkey -name prime256v1` so students can issue an ECDSA leaf and observe the negotiated suite change — a concrete, self-verifying exercise.
---

## INFO

- **Validity periods are sound.** Root 3650d (`setup_ca.sh:62`), Intermediate 1825d (`:96`), leaf 365d (`issue_cert.sh:44`) — the leaf sits under the 398-day CA/Browser Forum ceiling. Worth a note in Exercise 01 that the industry is trending toward much shorter leaf lifetimes, since `01-build-your-ca.md:16` presents 1yr/5yr/10yr as the norm.
- **`ssl_ciphers` and `ssl_prefer_server_ciphers` are no-ops** given `ssl_protocols TLSv1.3` on `nginx-tls.conf:14`. TLS 1.3 suites are configured via `ssl_conf_command Ciphersuites ...`, not `ssl_ciphers`. The comment on line 16-17 half-acknowledges this; make it explicit so students do not believe line 18 is doing the work.
- **The mTLS half of the lab is unused.** `issue_cert.sh:33` supports `CERT_TYPE=client` → `extendedKeyUsage = clientAuth` (4th positional arg, undocumented in the usage comment on line 3), but no config anywhere sets `ssl_verify_client` / `ssl_client_certificate`. Either wire client-cert auth into `nginx-tls.conf` as a fourth exercise or remove the dead branch.
- **`listen 443 ssl http2;`** (`nginx-tls.conf:5`) uses the legacy `http2` listen parameter, deprecated in favour of a separate `http2 on;` directive in nginx 1.25.1+. I could not verify the behaviour of the exact pinned base image tag; if it emits a deprecation warning, switch to `listen 443 ssl;` + `http2 on;`.

---

## Summary

| Severity | Count | Top Finding |
|----------|-------|-------------|
| CRITICAL | 0 | — |
| HIGH | 3 | `issue_cert.sh:26-35` — unvalidated CN/SAN args injected into the OpenSSL extension file; mint a lab-CA-signed cert for any name (and `:16` path traversal destroys the CA key) |
| MEDIUM | 7 | `setup_ca.sh:36` + `docker-compose.yml:538` — unencrypted Root CA key permanently online in a read-write mount shared with a long-running container |
| LOW | 9 | `setup_ca.sh:36-37` / `issue_cert.sh:16-17` — keys written at default umask before `chmod 400` |
| INFO | 4 | `ssl_ciphers` on `nginx-tls.conf:18` is inert under TLS 1.3-only |

Two items need runtime confirmation and are good candidates for the **tester-debugger** agent: (1) whether OpenSSL's `NCONF` last-wins duplicate-key behaviour actually lets an injected `basicConstraints = critical,CA:TRUE` override line 29 — the SAN-injection impact does not depend on this, but the CA-escalation variant does; (2) the `proxy_pass` redirect loop, which should be reproduced with `curl -v` against a live `pki-nginx`.
