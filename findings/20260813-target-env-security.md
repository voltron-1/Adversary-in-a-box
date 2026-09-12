# Target-Env Security Audit — 2026-08-13

## Scope

In scope: `target-env/` (victim-web, victim-db, victim-mail) and the compose/runtime wiring that governs their containment. Reviewed as supporting evidence: `docker-compose.yml`, `.env.example`, `scripts/lab/{start,reset,student-env}.sh`, `scripts/safety/egress_test.sh`, `blue-team/detection/suricata/local.rules`, `blue-team/detection/zeek/local.zeek`, `tests/`, `.github/workflows/{validate,integration}.yml`, `docs/THREAT_MODEL.md`.

Out of scope by instruction: the intentional vuln set (SQLi, XSS, path traversal, weak seeded creds, plaintext password storage, open `svc_backup'@'%'`).

**Summary: HIGH 2 · MEDIUM 5 · LOW 4 · INFO 2.** No intentional lab vulns counted as findings.
**Most important:** the lab's containment claim (`lab-net: internal: true`) is documented in `docs/THREAT_MODEL.md` and `docs/EXECUTIVE_SUMMARY.md` but is **enforced by nothing testable** — no test parses `docker-compose.yml` for containment invariants, and the only egress verification (`scripts/safety/egress_test.sh`) probes *the host*, never runs from inside a victim container. A one-line `ports:` or `network_mode: host` edit silently publishes an SQLi + arbitrary-file-read app on `0.0.0.0` and CI would stay green.
**Credentials check: clean.** All target-env secrets are lab-synthetic (`@lab.local`, `FLAG{...}` markers, SSN explicitly "FAKE LAB DATA"); `.env` is gitignored; no valid-looking API keys.
**Structural containment is currently good** (no `ports:`, no host bind-mounts, no `privileged`, no docker.sock on any victim) — that is exactly why it needs a regression test.

---

**[HIGH] Containment invariants for target-env are undocumented-as-code and untested**
- **MITRE ATT&CK**: T1190 (exposure of the vulnerable service), T1200-adjacent
- **Red Team**: `victim-web` exposes SQLi and an *unbounded absolute-path file read* (`app.py:137`). Today it has no host port. A single edit — `ports: - "8080:80"` under `victim-web`, or `network_mode: host` on `victim-mail` — publishes it on `0.0.0.0`. On WSL2/Docker Desktop that is forwarded to the Windows host and reachable from the campus LAN. `docs/tutorials/instructor.md:175` already anticipates this failure ("Student broke air-gap, removed `internal: true`") and scores a `-25` penalty, i.e. the project expects the regression but has no automated guard for it.
- **Blue Team**: No CI gate — `.github/workflows/validate.yml:103` only runs `docker compose build` for the victims, never inspects the resolved config. `grep` across `tests/` finds no test that parses `docker-compose.yml`; `tests/test_dashboard_security.py`, `test_start_script.py`, `test_target_allowlist.py` all cover other surfaces. No runtime alert either: `blue-team/detection/suricata/local.rules` has zero rules keyed on `$HOME_NET -> !$HOME_NET` (the `$EXTERNAL_NET` rules at lines 48/60/61 are explicitly annotated "cannot fire on air-gapped lab-net").
- **Evidence**: `docker-compose.yml:132-171` — the three victim services carry no `ports`, no `volumes`, no `cap_add`, only `lab-net`; nothing pins that shape. Contrast `docker-compose.yml:21` `internal: true  # OQ-1: block external egress` — a comment, not an assertion.
- **Recommendation**: Add `tests/test_compose_containment.py` that loads `docker-compose.yml` (or better, `docker compose config` output so `.env` interpolation is included) and asserts, for `victim-web`/`victim-db`/`victim-mail`: `"ports" not in svc`, `"volumes" not in svc`, `"network_mode" not in svc`, `"privileged" not in svc`, `"cap_add" not in svc`, `"pid" not in svc`, networks ⊆ `{lab-net, quarantine-net}`; plus `networks["lab-net"]["internal"] is True` and same for `quarantine-net`. Wire it into `validate.yml` on every PR. Add the Suricata tripwire in the next finding.

---

**[HIGH] The air-gap is never validated from inside a container; the one documented check is a manual curl that cannot distinguish "blocked" from "curl failed"**
- **MITRE ATT&CK**: T1048 (exfil over alternative protocol), T1071.004 (DNS), T1070 (indicator removal, via the SIEM path below)
- **Red Team**: The enforcement story has a hole at both ends. (1) `scripts/safety/egress_test.sh` runs entirely on the **host** — it resolves `SAFE_MODE_DOMAINS` and probes AD ports from the host's namespace. It proves nothing about what `victim-web` can reach. (2) Docker's `internal` flag installs DROP rules on the **FORWARD** path; traffic from a container to the bridge gateway (`${LAB_NET_PREFIX}.1`, i.e. the host itself) traverses **INPUT** and is not covered by those rules on many Docker versions. If that holds on the operator's Docker build, a compromised victim reaches `172.20.0.1:9200` — Elasticsearch, published to the host at `0.0.0.0:9200` with `xpack.security.enabled=false` — and can delete or forge the very indices that record the attack, from a container the docs describe as air-gapped. Same path reaches Kibana `:5601`, blue-team `:5000`, scoreboard `:5002`. **I cannot determine from the files whether gateway reach and Docker embedded-DNS (`127.0.0.11`) external forwarding are open on your Docker version — this is version-dependent and needs empirical verification. Recommend the tester-debugger agent.**
- **Blue Team**: The only check is manual and structurally unable to fail loudly: `docs/master_command_list.md:134` — `docker compose exec red-team curl -m 3 https://example.com || echo "isolated, as expected"`. That prints the reassuring message if DNS fails, if TCP is dropped, if curl is missing, or if the container isn't running. It is also run from `red-team`, not from the victims, and never in CI — `.github/workflows/integration.yml:65-68` explicitly sets `AIB_SKIP_PREFLIGHT=1` and asserts nothing about egress. No Suricata/Zeek rule alerts on a lab host talking to a non-lab address.
- **Evidence**: `scripts/safety/egress_test.sh:100-150` (host-only resolution and probing); `docs/master_command_list.md:134`; `docker-compose.yml:275-282` (ES published on the host with security disabled); `docs/THREAT_MODEL.md:122-124` claims "Egress is impossible without creating a separate network and attaching the container."
- **Recommendation**: Add `scripts/safety/containment_test.sh` that asserts *from inside each victim*, with distinct exit codes per failure mode:
  1. external TCP blocked — `docker compose exec -T victim-web python3 -c "import socket;socket.create_connection(('1.1.1.1',443),3)"` must raise;
  2. external DNS does not resolve — `docker compose exec -T victim-web python3 -c "import socket;print(socket.gethostbyname('example.com'))"` must fail (this is the DNS-tunnel channel the lab itself teaches);
  3. host gateway unreachable — `docker compose exec -T victim-web python3 -c "import socket;socket.create_connection(('${LAB_NET_PREFIX}.1',9200),3)"` must fail.
  Call it from `scripts/lab/start.sh` after the health poll and as a step in `integration.yml`. Separately, add a containment tripwire to `local.rules`: `alert ip $HOME_NET any -> !$HOME_NET any (msg:"AIB CONTAINMENT lab host reached non-lab address"; classtype:policy-violation; sid:1000200; rev:1;)` — Suricata is on `network_mode: host` sniffing the lab bridge, so it is positioned to see this.

---

**[MEDIUM] Victims share a flat L3 network with the container that holds the Docker socket**
- **MITRE ATT&CK**: T1610 / T1611 (container escape via Docker API), T1021
- **Red Team**: `blue-team` mounts `/var/run/docker.sock` and holds `NET_ADMIN`, and sits at `${LAB_NET_PREFIX}.20` on the same flat `lab-net` as the three intentionally-vulnerable hosts. There is no network segmentation between "the boxes we invite students to exploit" and "the box that is root on the host." The only barrier is application-layer: the `ir` profile must be enabled and `PLAYBOOK_AUTH_TOKEN` must be presented. Today no victim has an RCE primitive (the web app's traversal is read-only; `render_template_string` is called with the payload as a *variable*, not as template source, so there is no SSTI), so this is a topology risk rather than a live chain — but `victim-mail` runs Postfix as root, and the lab's whole purpose is students bolting new exploits onto these targets.
- **Blue Team**: The compose file's own comment (`docker-compose.yml:83-84`) states "A flask RCE here would be a single-step host takeover," and the risk is accepted in `docs/THREAT_MODEL.md:107-110`. The mitigations are real and correctly fail-closed (`blue-team/dashboard/app.py:51-66` rejects the committed placeholder token and uses `hmac.compare_digest`), and IR is opt-in (`.env.example:33` ships `COMPOSE_PROFILES=` empty). What is missing is the network-layer control.
- **Evidence**: `docker-compose.yml:99-112` (blue-team on `lab-net` + `/var/run/docker.sock` + `cap_add: NET_ADMIN`) vs `:135-137, :151-152, :163-165` (victims on the same `lab-net`).
- **Recommendation**: Add a third internal network (e.g. `ir-net`) carrying `blue-team` ↔ `elasticsearch`, and remove `blue-team` from `lab-net` — it reaches victims for quarantine via the Docker API and via `quarantine-net`, not via lab-net routing. If lab-net membership is required for a demo, at minimum bind the dashboard to the quarantine-net address rather than `0.0.0.0` (`blue-team/dashboard/app.py:301`).

---

**[MEDIUM] `LAB_NET_PREFIX` is unvalidated inside victim-mail's entrypoint → Postfix config injection / open relay**
- **MITRE ATT&CK**: T1584.006-adjacent (relay abuse); config-injection class
- **Red Team**: The entrypoint interpolates an unvalidated env var straight into `postconf -e`. `LAB_NET_PREFIX='0.0.0.0/0 172.20.0'` yields `mynetworks = 0.0.0.0/0 172.20.0.0/24 127.0.0.0/8` — a fully open relay, since `mynetworks` is what `permit_mynetworks` in both `smtpd_recipient_restrictions` and `smtpd_relay_restrictions` (lines 16-17) trusts. A newline in the value injects arbitrary additional `main.cf` parameters. `scripts/lab/start.sh:27` validates the prefix with a proper regex, but that guard is bypassed by the plain `docker compose up -d` path that the project itself documents (`docs/master_command_list.md:33`, `docs/setup-guide.md:66`) and by CI. To be precise: **this is config injection, not command injection** — `set -eu` is set and every expansion is double-quoted, so no shell metacharacter escape exists here.
- **Blue Team**: Nothing logs or alerts on the resulting `mynetworks`. The entrypoint echoes it at line 19, but container stdout for victim-mail is not shipped into the SIEM (no syslog/log-driver wiring for the victims anywhere in compose).
- **Evidence**: `target-env/victim-mail/entrypoint.sh:10` `LAB_SUBNET="${LAB_NET_PREFIX:-172.20.0}.0/24"` and `:14` `postconf -e "mynetworks = ${LAB_SUBNET} 127.0.0.0/8"`.
- **Recommendation**: Move the guard into the entrypoint so it holds regardless of launch path — after line 8:
  ```sh
  case "${LAB_NET_PREFIX:-172.20.0}" in
    *[!0-9.]*|*..*) echo "[victim-mail] invalid LAB_NET_PREFIX" >&2; exit 2 ;;
  esac
  printf '%s' "${LAB_NET_PREFIX:-172.20.0}" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){2}$' || { echo "[victim-mail] LAB_NET_PREFIX must be a 3-octet IPv4 prefix" >&2; exit 2; }
  ```
  Apply the same pattern to `blue-team/detection/zeek/entrypoint.sh`, which templates the same variable.

---

**[MEDIUM] victim-web ships an attacker toolchain and is handed database credentials it never uses**
- **MITRE ATT&CK**: T1552.001 (credentials in files/env), T1005
- **Red Team**: Two separate problems compounding. (1) The final image retains `gcc` and `libmariadb-dev` plus `curl` — a compiler and a network client inside the box students are told to exploit, i.e. ready-made tooling for compiling a local privesc/escape attempt and for staging data out. (2) `DB_USER`/`DB_PASS`/`DB_HOST` are injected into `victim-web`, but `app.py` imports only `sqlite3` and talks to `/tmp/lab.db` — it never connects to MySQL at all. The app's own file-read primitive (`app.py:137`, which opens an unbounded absolute path once the `/var/www/files/` open fails) reads `/proc/self/environ` and hands over those credentials without the student ever touching the database. Today those creds are lab-synthetic, so the impact is scope-creep rather than loss; the risk is an operator who puts a real password into `.env` (`.env.example:53-57` invites `DB_PASS=` edits and `scripts/lab/student-env.sh` does not generate DB values).
- **Blue Team**: No detection for process execution inside containers — the lab has network sensors (Suricata, Zeek) and syslog advisories only. A `gcc` invocation or a `curl` inside `victim-web` produces zero telemetry.
- **Evidence**: `target-env/victim-web/Dockerfile:4-5` `gcc libmariadb-dev curl`, `:9` `pip install ... pymysql requests`; `target-env/victim-web/app/app.py:7` `import sqlite3` (no pymysql import anywhere); `docker-compose.yml:138-142`.
- **Recommendation**: Drop `gcc`, `libmariadb-dev`, `pymysql` and `requests` from the victim-web image (nothing imports them); if `curl` is needed for a healthcheck, keep it but note it in the threat model. Remove the `DB_*` environment block from `victim-web` in `docker-compose.yml` until the app actually uses MySQL. Add a note in `.env.example` near line 53: "never paste a password you use anywhere else — these are readable from inside the victim by design."

---

**[MEDIUM] No resource limits, `no-new-privileges`, or capability drops on any victim**
- **MITRE ATT&CK**: T1499 (endpoint DoS), T1611 (escape, harder with caps dropped)
- **Red Team**: A fork bomb, a runaway crypto/ransomware simulation, or a memory balloon inside `victim-web` consumes the shared instructor host's memory and CPU — taking down every other student's stack *and* the Elasticsearch instance that would have recorded it. All three victims also run as root with the full default capability set and a writable root filesystem, which is the most favourable possible starting position for any container-escape primitive a student introduces.
- **Blue Team**: The SIEM services are protected (`mem_limit: 2g` at `docker-compose.yml:287`, `1g` at `:383` and `:418`, with the explicit Phase C6 rationale "so a single OOMing student stack can't take down a shared lab host") — the reasoning was applied to the containers that *aren't* being attacked and skipped on the ones that are.
- **Evidence**: `docker-compose.yml:132-171` — no `mem_limit`, `pids_limit`, `cpus`, `security_opt`, `cap_drop`, `read_only`, or `user` on any of the three victims. `target-env/victim-web/app/app.py:147` `app.run(host="0.0.0.0", port=80, ...)` forces root to bind :80.
- **Recommendation**: Add to each victim: `mem_limit: 512m`, `pids_limit: 200`, `cpus: "1.0"`, `security_opt: ["no-new-privileges:true"]`, `cap_drop: [ALL]` with the minimum re-added (`CHOWN, SETUID, SETGID, DAC_OVERRIDE` for the Postfix and MySQL images). For victim-web, move the app to port 8080 and add `user: "1000:1000"` — the intentional vulns are all app-layer and survive dropping root.

---

**[MEDIUM] Victim base images and Python packages are unpinned, while the sensor image is digest-pinned**
- **MITRE ATT&CK**: T1195.001 / T1195.002 (supply chain compromise of dependencies/tools)
- **Red Team**: `docker build` runs as root on the student's host with unrestricted internet — entirely outside every network control the lab has. A compromised `python:3.11-slim` tag, a hijacked PyPI name, or a poisoned Debian mirror executes arbitrary code on the host at build time, before any container isolation applies. `validate.yml:103` runs `docker compose build --pull` for exactly these images, and `scripts/lab/start.sh:45` builds on every start.
- **Blue Team**: No lockfile, no hash pinning, no SBOM, no image-digest assertion in CI. The project clearly knows the technique — `docker-compose.yml:182-188` pins Suricata to a manifest-list digest with a documented bump procedure — but the victims were left on floating tags.
- **Evidence**: `target-env/victim-web/Dockerfile:1` `FROM python:3.11-slim`, `:9` `pip install --no-cache-dir flask flask-sqlalchemy pymysql requests` (no versions, no hashes); `target-env/victim-db/Dockerfile:1` `FROM mysql:8.0`; `target-env/victim-mail/Dockerfile:1` `FROM debian:bullseye-slim` (Debian 11, now oldstable).
- **Recommendation**: Pin all three bases by digest with the same comment convention used for Suricata. Replace the inline `pip install` with `target-env/victim-web/requirements.txt` carrying exact versions and `pip install --require-hashes -r requirements.txt`. Bump `victim-mail` to `debian:bookworm-slim`.

---

**[LOW] `/var/www/files/` is never created, so the intended path-traversal lesson never executes and every read is unbounded**
- **Red Team**: The Dockerfile never creates `/var/www/files/`, so `open(base_dir + filename)` always raises `FileNotFoundError` and control always falls into the fallback branch, which opens an attacker-controlled absolute path. The "escape a base directory" lesson is never actually demonstrated; the primitive is unrestricted file read by construction, which is broader than the annotated intent ("Path Traversal (A01:2021)").
- **Blue Team**: Suricata sid:1000022 alerts on literal `../` in the URI — but the fallback path is reachable with a plain absolute path (`/file?name=/etc/passwd`) containing no `../` at all, so the detection misses the easier variant. That is a genuine false-negative in an in-scope rule.
- **Evidence**: `target-env/victim-web/app/app.py:127-140`, especially `:137` `open(filename.replace("../", "/").replace("..%2F", "/"))`; `target-env/victim-web/Dockerfile` has no `RUN mkdir -p /var/www/files`.
- **Recommendation**: Add `RUN mkdir -p /var/www/files && echo "lab notes" > /var/www/files/notes.txt` to the Dockerfile so the intended traversal lesson works, and keep the vuln. Separately, add a Suricata rule for absolute-path reads (`content:"/file?name=/"; http_uri;`) so the detection covers both variants.

---

**[LOW] Nothing prevents or tests `debug=True` in victim-web**
- **MITRE ATT&CK**: T1059.006 (Python execution via the Werkzeug console)
- **Red Team**: `debug=False` today, which is correct. If a student or contributor flips it while troubleshooting, the Werkzeug debugger adds unauthenticated RCE inside a container sitting on the same flat network as the docker.sock-mounted `blue-team` container (see the MEDIUM above). That converts a read-only lab target into a genuine host-adjacent takeover primitive and exceeds the intended vuln set.
- **Blue Team**: No test asserts it; nothing in CI would catch the diff.
- **Evidence**: `target-env/victim-web/app/app.py:147` `app.run(host="0.0.0.0", port=80, debug=False)`.
- **Recommendation**: Add to the containment test file: assert `"debug=True" not in app.py source` (and the same for the blue-team and scoreboard Flask entrypoints).

---

**[LOW] Any `docker compose up -d` silently reverts an IR quarantine**
- **MITRE ATT&CK**: T1562.001 (impair defenses / undo containment)
- **Red Team**: `isolate_host.sh` moves a victim to `quarantine-net` via the Docker API. Compose reconciles container network membership on `up`, so the next `scripts/lab/start.sh` (or `reset.sh` step 5, which `exec`s start.sh) re-attaches the isolated victim to `lab-net` — restoring reachability to every other lab host with no operator signal.
- **Blue Team**: `isolate_host.sh:32-34` appends to `/evidence/isolation_log.json`, but nothing re-verifies the container is still quarantined, and nothing logs the re-attachment. Scoring reads the isolation event and never learns it was undone.
- **Evidence**: `blue-team/response/actions/isolate_host.sh:24-28`; `scripts/lab/start.sh:45` `docker compose up -d --build "$@"`; `scripts/lab/reset.sh:109`.
- **Recommendation**: Have the blue-team dashboard re-read `docker inspect` network membership for any host listed in `isolation_log.json` and surface a "quarantine broken" alert, or have `start.sh` warn when `evidence/isolation_log.json` contains an un-restored host.

---

**[LOW] The red-team build context is bind-mounted read-write into a container on the victims' network**
- **MITRE ATT&CK**: T1610-adjacent (host code execution via build context poisoning)
- **Red Team**: `./red-team` is both the Docker **build context** and a read-write bind mount at `/app`. Any write primitive obtained inside the red-team container becomes host code execution at the next `docker compose up -d --build` (which `start.sh` always runs, as root-equivalent in the build step). The red-team container shares `lab-net` with the victims, so this sits one hop from the intentionally-vulnerable hosts. Speculative — red-team runs no listening services — but it is the shortest victim→host path in the topology after the docker.sock container.
- **Evidence**: `docker-compose.yml:52` `build: ./red-team` and `:58` `- ./red-team:/app` (no `:ro`); `scripts/lab/start.sh:45`.
- **Recommendation**: Mount the source read-only (`./red-team:/app:ro`) and use a separate writable path for runtime artifacts, or drop `--build` from the default `start.sh` invocation and build explicitly.

---

**[INFO] Credentials verified lab-synthetic and distinct from anything real — no action needed**
- **Evidence checked**: `target-env/victim-db/seed.sql:33-38` (`password123`, `letmein`, `qwerty`, `123456`, `Service!1`, all `@lab.local`), `:41` `LAB-API-KEY-FLAG{database_exfil_demo}` (a flag string, not a valid key format for any provider), `:43` `SSN: 000-00-0000 (FAKE LAB DATA)`, `:46` `backup123`; `target-env/victim-web/app/app.py:12` `super-insecure-secret-123` — used only by victim-web and **not** equal to the `FLASK_SECRET_KEY` placeholder in `.env.example:71`, so no cross-service reuse; `.gitignore:151` ignores `.env`. Root password `root` is baked at `target-env/victim-db/Dockerfile:4-7` as an image default and overridden by compose — acceptable for a never-published lab image; if you ever push these to a registry, strip the `ENV` block, since it is visible in image metadata to anyone who pulls.

---

**[INFO] The strongest current containment property — worth naming as an explicit invariant**
- No victim service has a host bind-mount, a published port, `privileged`, `network_mode`, `cap_add`, or access to the Docker socket, and `victim-db` uses only the base image's anonymous volume (cleared by `reset.sh:89-90`, which correctly uses `down -v`). This is the property that makes the whole lab safe today, and it is currently held together by convention. Lock it with the test in the first HIGH finding.

---

## Summary Table

| Severity | Count | Top Finding |
|----------|-------|-------------|
| CRITICAL | 0 | — |
| HIGH | 2 | Containment invariants for target-env are undocumented-as-code and untested; air-gap never validated from inside a container |
| MEDIUM | 5 | Victims share a flat L3 network with the docker.sock-mounted blue-team container |
| LOW | 4 | `/var/www/files/` never created — every `/file` read is unbounded and evades Suricata sid:1000022 |
| INFO | 2 | Credentials verified lab-synthetic; no host mounts or published ports on any victim |

**Recommended next step:** the two HIGH findings are both "the control exists but nothing proves it holds." The single highest-leverage fix is one new test file (`tests/test_compose_containment.py`) plus one new script (`scripts/safety/containment_test.sh`), both wired into `validate.yml`/`integration.yml`. Use the tester-debugger agent to empirically settle the version-dependent questions in the second HIGH finding — host-gateway reachability from `victim-web` and whether Docker's embedded DNS forwards external names off an `internal` network — before deciding how much of that finding is live versus theoretical.
