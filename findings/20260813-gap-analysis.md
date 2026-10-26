# Purple-Team Gap Analysis — Adversary-in-a-Box
**Date:** 2026-08-13
**Inputs:** 7 security-auditor findings files + 5 code-quality findings files (`findings/20260813-*.md`)
**Method:** Every coverage claim below was verified against the artifact on disk. Where a tool
was available locally (`sigma-cli`, `zeek 8.0.5`, `python3`) the behaviour was **executed**, not
inferred. Claims that could not be executed (Suricata pcap replay — no `suricata` binary on this
host; Logstash pipeline evaluation — no Logstash) are marked **(static)** and carry the reasoning.

---

## 0. Executive summary

**39 technique/finding rows evaluated: 1 Covered (2.6%) · 14 Partial (35.9%) · 24 Blind (61.5%).**

The single most important structural fact this analysis surfaced — and which none of the seven
audits state — is that **the Sigma ruleset has two independent consumers with opposite fates**:

| Consumer | Path | Status |
|---|---|---|
| **Scoreboard** | `forensics/scoreboard/sigma_eval.py` reads `blue-team/detection/sigma/*.yml` **directly** (bind-mount `docker-compose.yml:450`) | **WORKS** — verified: all 7 rules match their paired campaign advisory |
| **Kibana SIEM** | `scripts/setup/compile_sigma.sh` → `compiled/*.eql.json` → `/api/detection_engine/rules` | **DEAD** — four independent, stacked blockers (§3.1) |

Consequence: **the scoreboard is the only functioning Sigma detection layer in the lab**, and it is
also the layer with zero authentication on its input. Every "detection" it scores is mintable by
any container on `lab-net` with one UDP datagram — verified below.

Second structural fact: **the network sensor tier is effectively one sensor, not two.** Zeek is
attached to a bridge as a normal endpoint (`ZEEK_IFACE=eth0`, `docker-compose.yml:252-264`) while
Suricata deliberately captures the bridge master in the host netns (`network_mode: host`,
`docker-compose.yml:190`). Every Zeek-only detection is therefore inert, and — verified separately —
even with visibility restored, `port_scan.zeek` **still could not fire** on the lab's own recon
campaign (§3.3, row R1).

---

## 1. Coverage truth table

Legend — **Covered**: a rule exists, its logic matches the attacker's actual method, and it is on a
live ingest path. **Partial**: a rule exists but a trivial evasion, a logic bug, a missing log
source, or a broken deploy path degrades it. **Blind**: no rule, or a rule that cannot fire.

### Tier 1 — SIEM & scoreboard trustworthiness (ranked highest: these make every row below advisory-only)

| # | Finding / attacker capability | ATT&CK | Detection artifact | Status | Evidence |
|---|---|---|---|---|---|
| T1 | **Score forgery by direct ES write** — `curl -XPOST elasticsearch:9200/red-team-events-1/_doc` mints campaign points; `ir-events-*` mints response points | T1565.001 | *none* — `scorer.py:126-129` trusts four indices unconditionally | **BLIND** | `20260813-scoreboard-security.md` CRITICAL; verified `docker-compose.yml:282` `xpack.security.enabled=false`, `:276` `9200:9200` on `0.0.0.0` |
| T2 | **Detection minting via unauthenticated syslog** — any lab-net peer emits a keyword and the scorer counts a blue-team detection | T1565.001, T1036 | `sigma_eval.matched_rule` (no source check); `syslog.conf:11-16` has no host filter | **BLIND** | **Executed** (§2.1): the literal string `NOPASSWD` alone matches `privesc_sudo.yml` (`level: high`). All 7 advisories are replayable verbatim by any peer |
| T3 | **Evidence/index destruction** — `DELETE /suricata-*,zeek-*,syslog-*` in one unauthenticated request | T1485, T1070.001 | *none* — ES audit logging unavailable while `xpack.security.enabled: false` | **BLIND** | `20260813-siem-security.md` CRITICAL; `siem/elasticsearch/elasticsearch.yml:4,9` |
| T4 | **Pre-attack detection-rule deletion via unauthenticated Kibana** `/api/detection_engine/rules` | T1562.001 | *none* — `logging.root.level: warn` drops saved-object mutations | **BLIND** | `siem/kibana/kibana.yml:2,10-12`; `compile_sigma.sh:71-75` proves no auth header is needed |
| T5 | **Kibana Sigma deployment is dead** — 7/7 compiled artifacts are the wrong program's help text | T1562.001 (self-inflicted) | `scripts/setup/compile_sigma.sh:31` guard is `command -v sigma` | **BLIND** | **Verified on disk**: all 7 files in `blue-team/detection/sigma/compiled/` are 1619 bytes beginning `Sigma, version 1.1.3: simple greedy multiple alignment`. See §3.1 — three *further* blockers behind this one |
| T6 | **Operator dashboard is structurally empty** — 3/3 Lens panels filter `event.dataset:suricata`; no pipeline sets the field | n/a | `siem/kibana/dashboards/operator-view.ndjson:2-4` | **BLIND** | **Verified**: repo-wide grep for `[event][dataset]` across `siem/logstash/` returns **zero** matches |
| T7 | **Zeek notices never become alerts** — `if [_path] == "notice"` cannot match | n/a | `siem/logstash/pipelines/zeek.conf:49-54` | **BLIND** | **Executed** (§2.2): Zeek 8.0.5 base ASCII writer with `LogAscii::use_json = T` emits `{"ts":…,"note":…,"msg":…,"actions":…}` — **no `_path` key**. Settles the SIEM audit's "needs runtime confirmation" item |
| T8 | **syslog.conf ATT&CK tagging is dead for every lab campaign** — grok fails, so `[program]`/`[syslog_message]` are never set | T1548.003/T1053.003/T1110 tagging | `siem/logstash/pipelines/syslog.conf:21,35,45,54` | **BLIND** | **Executed** (§2.3) — **new, not in any audit**. Python's `SysLogHandler` emits `<12>aib-sudo: {json}` with no RFC3164 timestamp/hostname; the grok at `:21` requires both |
| T9 | **Timestomp → index routing / ILM-timed evidence destruction** | T1070.006 | *none* — no `event.ingested`, no skew tag | **BLIND** | `syslog.conf:24-27` + `:78` + `ilm-policy.json:14-17`. Note: T8 accidentally neuters this for *campaign* advisories (no parseable timestamp ⇒ ingest time wins) but **not** for a hand-crafted RFC3164 datagram, which is the actual attack |
| T10 | **Containment actions are invisible to the SIEM** — no per-action `ir-events-*` doc, `operator` always `"unknown"` | T1489 / admin-tool abuse | `isolate_host.sh:33`, `restore_host.sh:28` write only a local file | **BLIND** | **Verified on disk**: `${USER:-unknown}` unset in container processes; only `playbook_engine.py:83-100` emits, at aggregate granularity |
| T11 | **Successful score awards produce no audit line** — `app.logger.info` below Flask's default WARNING | T1562.002-analogue | `forensics/scoreboard/app.py:191` | **BLIND** | `20260813-scoreboard-security.md` HIGH; no `logging.basicConfig` in the module, no `LOG_LEVEL` in the scoreboard compose env block |
| T12 | **Attacker container can rewrite the evidence store** — `./evidence` mounted rw into `red-team` | T1070.004, T1565.001 | `forensics/chain_of_custody.py` (manual, post-hoc); `manifest.json` lives inside the tree it attests | **PARTIAL** | `docker-compose.yml:57-59` (no `:ro`); `collect_evidence.py:56-57` hashes the *copy*, not the source |

**Tier 1: 0 Covered · 1 Partial · 11 Blind.**

### Tier 2 — Containment / air-gap escape

| # | Finding / attacker capability | ATT&CK | Detection artifact | Status | Evidence |
|---|---|---|---|---|---|
| C1 | **Air-gap never validated from inside a container**; `internal: true` does not cover the container→gateway INPUT path on some Docker versions | T1048, T1071.004 | `internal: true` (prevention, real); `egress_test.sh` probes **the host only** | **PARTIAL** | `20260813-target-env-security.md` HIGH; `scripts/safety/egress_test.sh:100-150`. The proposed containment tripwire `sid:1000200` **does not exist** — verified absent from `local.rules` |
| C2 | **Egress preflight fails open on every resolver error**; no control probe | T1562.001 | `scripts/safety/egress_test.sh:100-114,136-149` | **PARTIAL** | `20260813-scripts-ci-security.md` CRITICAL F1. A PASS carries no evidence |
| C3 | **Preflight `source`s `.env`** — `exit 0` in `.env` silently bypasses the guardrail; metacharacters are RCE as the operator | T1059.004 | *none* — output is identical on a bypassed and a clean run | **BLIND** | `egress_test.sh:58-63` |
| C4 | **`AIB_SKIP_PREFLIGHT=1` leaves no durable artifact** — one stderr line in an ephemeral terminal | T1562.001, T1070 | *none* | **BLIND** | `scripts/lab/start.sh:40-42`; instructor penalty exists but is triggered by human observation (`docs/tutorials/instructor.md:188`) |
| C5 | **`C2_URL` / `C2_DNS_DOMAIN` bypass the target allowlist** and drive real egress with `verify=False` | T1041, T1048.003, T1071.001 | *none* — `tests/test_target_allowlist.py` covers other variables; passing status is false assurance | **BLIND** | `red-team/campaigns/exfiltration/https_exfil.py:21,68,85-91`; `runner.py:263-268` |
| C6 | **`LAB_NET_PREFIX` never reaches the red-team container** — allowlist authorizes another student's /24 and rejects the operator's own victims | n/a (control failure) | *none* — no startup consistency check against `ATTACKER_IP` | **BLIND** | `docker-compose.yml:60-70` vs `runner.py:289` |
| C7 | **`TARGET_DB`/`TARGET_MAIL` vs `TARGET_DB_HOST`/`TARGET_MAIL_HOST` mismatch** — hardcoded `.31`/`.32` win and skip the gate ("defaults are trusted") | T1566.001, T1550.002 | *none* | **BLIND** | `spear_phish.py:40`, `pass_the_hash.py:18`, `docker-compose.yml:62-63`; confirmed by committed run log `red-team/logs/campaign_20260525.json:6,9` |
| C8 | **Compose containment invariants are convention, not code** — one `ports:` edit publishes an SQLi + arbitrary-file-read app on `0.0.0.0` | T1190 | Structural (no ports/mounts/caps on victims today); **no test parses `docker-compose.yml`** | **PARTIAL** | `20260813-target-env-security.md` HIGH; `validate.yml:103` only builds |
| C9 | **PKI: SAN injection + CA-key destruction via unvalidated `issue_cert.sh` args**; no issuance ledger | T1649, T1587.003, T1485 | `validate-certs` loaded (`local.zeek:14`) but alarms on **every** lab TLS connection — the real signal is buried; `x509.log` is **not shipped** | **PARTIAL** | `pki-lab/issue_cert.sh:7-9,16-17,26-35`; `zeek.conf:9-10` log list omits `x509.log`; grep of `blue-team/` for `T1649`/`key.pem` returns nothing |

**Tier 2: 0 Covered · 4 Partial · 5 Blind.**

### Tier 3 — Per-technique detection-rule logic

| # | Technique | ATT&CK | Rule(s) | Status | Why |
|---|---|---|---|---|---|
| R1 | Recon port scan | T1595 / T1589 | `local.rules` sid:1000001, sid:1000002; `port_scan.zeek` | **PARTIAL** | **New finding**: `vuln_scan.py:32` scans exactly **10** ports. sid:1000001 needs **20** in 1 s → cannot fire. `port_scan.zeek:16` needs **>15** distinct ports → **cannot fire even if Zeek visibility is fixed**. Only sid:1000002 (10-in-5 s) can fire, and only marginally (`TIMEOUT=1.0` per connect). Evasion: `flags:S` is exact-match, so `-sF/-sN/-sX/-sA` and SYN+ECE evade both sids |
| R2 | DNS version scan | T1046 / T1590 | sid:1000003 | **BLIND** | `content:"\|00 00 10 00 01\|"; depth:5` forces the qtype/qclass bytes into the transaction-ID/flags region. Structurally unmatchable (static) |
| R3 | Spearphishing attachment | T1566.001 | sid:1000010 | **BLIND** | **New finding**: the rule's `pcre:"/filename=\"[^\"]*\.(exe\|bat\|ps1\|vbs\|js\|hta)\"/i"` does not include `pdf` — and `spear_phish.py:115` attaches `filename="Benefits_Form_2024.pdf"`. **The lab's own phishing campaign cannot trip the lab's own phishing rule.** Real SMTP is on the wire, so the ingest path exists; only the signature is wrong |
| R4 | SQL injection | T1190 | sid:1000020 `' OR`; sid:1000023 `UNION SELECT` — both `http_uri` | **BLIND** | **New finding**: `exploit_web.py:70-73` delivers SQLi as a **POST body** (`requests.post(.../login, data={"username": payload})`). `http_uri` never sees it. Confirms the audit's generic warning as a live false negative against the shipped campaign |
| R5 | Reflected XSS | T1190 | sid:1000021 `<script>`; `http_uri` | **PARTIAL** | `exploit_web.py:93` puts the payload in `/search?q=` — the URI — so the content match is correct. Degraded by `suricata.yaml:118 checksum-validation: yes` on offloaded veth capture (stream reassembly discarded) and `HTTP_PORTS: "80"` only. Evasion: `<ScRiPt`/`<svg onload=` |
| R6 | Path traversal | T1190 | sid:1000022 `content:"../"; http_uri` | **PARTIAL** | Matches `../../../etc/passwd`. **But** `/var/www/files/` is never created (`victim-web/Dockerfile`), so the code always falls into the unbounded-absolute-path branch (`app.py:137`) — `/file?name=/etc/passwd` contains no `../` and has **no rule at all** |
| R7 | Malware drop (EICAR) | T1204 | `malware_drop_eicar.yml` (scoreboard path); sid:1000100 marked reference-only | **PARTIAL** | **Executed**: advisory matches. Single-literal evasion confirmed — changing `write_target` to `/tmp/x.eicar` ⇒ **no match**. Kibana path dead (T5) |
| R8 | Brute force (HTTP) | T1110 | sid:1000090 (`POST` + `/login`, 5-in-60 s); `credential_access_brute_force.yml` | **COVERED** | The one genuinely layered technique. `brute_force.py:35-47`: 10 real POSTs at `RATE_LIMIT_SECONDS = 1.0` ⇒ ~10 s ⇒ well inside 5-in-60 s. Independent Sigma confirmation. **Caveat**: shares R5's checksum/HTTP_PORTS risk (static — needs pcap replay) |
| R9 | Adversary-in-the-Middle | T1557 | `mitm_arp_spoof.yml` (scoreboard); sid:1000080 reference-only | **PARTIAL** | **Executed**: matches; `signal_path` → `/tmp/a.log` ⇒ **evaded**. No duplicate-MAC behavioural fallback anywhere |
| R10 | Sudo abuse | T1548.003 | `privesc_sudo.yml`; `syslog.conf:35`; sid:1000030 | **PARTIAL** | Sigma path works but `condition: keywords **or** sudo_nopasswd` fires HIGH on the bare string `NOPASSWD` (**executed**). `syslog.conf:35` is dead (T8). sid:1000030 (`content:"sudo"` + `content:"-l"`, no flow/threshold) is a two-byte FP machine that cannot see the technique (it happens locally/over SSH) |
| R11 | SUID hunting | T1548.001 | *none* | **BLIND** | No wire traffic, **no syslog advisory**, no Sigma rule. Zero ingest path |
| R12 | Pass-the-Hash | T1550.002 | sid:1000040 (`\|FF\|SMB`, `depth:5`); `lateral_movement.zeek` | **BLIND** | Campaign is fully simulated — no traffic, no advisory. Rule is SMB1-only (`\|FE\|SMB` = SMB2/3 evades) and `smb:` is absent from `suricata.yaml` `app-layer.protocols`. Zeek half is blind (§3.2) |
| R13 | SSH session hijack | T1563.001 | `lateral_movement.zeek`; sid:1000042 | **BLIND** | Campaign runs local `find`/`who` — nothing on the wire, no advisory. sid:1000042 has no `flow`, no `content`, no `threshold` ⇒ alerts per-packet on all internal SSH (a burial primitive, not a detection). Zeek half blind |
| R14 | DNS tunnelling | T1048.003 | sid:1000050; `dns_exfil.zeek` | **BLIND** | Two independent logic errors in sid:1000050: the 10-byte `content` spans offsets 2-12 but `depth:10` caps at 10 (unsatisfiable), and the `^`-anchored pcre runs against the binary DNS header, not the QNAME. `dns_exfil.zeek:10` is **length-only** despite the header claiming entropy analysis, threshold 30 chars, no qtype filter. Zeek blind anyway. Campaign emits **no** traffic and **no** advisory |
| R15 | HTTPS exfiltration / C2 | T1041 | `exfil_https.yml` (scoreboard); sid:1000052 reference-only | **PARTIAL** | **Executed**: matches; `user_agent` → `Mozilla/5.0` ⇒ **evaded**. sid:1000052's pcre `User-Agent:[^\r\n]*(?!Mozilla\|…)` backtracks until the lookahead trivially succeeds — it matches every UA including the ones it whitelists |
| R16 | Ransomware | T1486 | `impact_ransomware.yml` (scoreboard); sid:1000110 reference-only | **PARTIAL** | **Executed**: matches; `decoy_path` → `/home/u/docs` ⇒ **evaded**. No extension-change-burst behavioural rule exists |
| R17 | Cron persistence | T1053.003 | `persistence_cron.yml`; `syslog.conf:45`; sid:1000060 | **PARTIAL** | Sigma path works (**executed**); mutating `entry` to `/usr/local/bin/beacon` ⇒ **evaded**. `syslog.conf:45 [program] =~ /cron/` is dead (T8) *and* unanchored (a process named `not-cron-really` forges the tag). sid:1000060 is bare `content:"crontab"`, no flow/threshold |
| R18 | SSH key persistence | T1098.004 | *none* | **BLIND** | File write only, no advisory, no rule. Zero ingest path |

**Tier 3: 1 Covered · 9 Partial · 8 Blind.**

### Totals

| Status | Count | % |
|---|---|---|
| Covered | 1 | 2.6% |
| Partial | 14 | 35.9% |
| Blind | 24 | 61.5% |
| **Total rows** | **39** | |

**Mean severity of the Blind set: HIGH.** Of the 24 Blind rows, 4 trace to a CRITICAL audit finding
and 11 to a HIGH.

---

## 2. Validation evidence (what was executed, not assumed)

### 2.1 Sigma matcher — run against the real advisory payloads
Harness: `sigma_eval.load_rules('blue-team/detection/sigma')` + advisory dicts reconstructed
verbatim from each campaign's `emit_syslog_advisory` call site.

```
BASELINE (does the shipped advisory match its paired rule?)
  T1204 malware_drop  -> malware_drop_eicar.yml            T1041 https_exfil -> exfil_https.yml
  T1486 ransomware    -> impact_ransomware.yml             T1053.003 cron    -> persistence_cron.yml
  T1110 brute_force   -> credential_access_brute_force.yml T1557 mitm        -> mitm_arp_spoof.yml
  T1548.003 sudo      -> privesc_sudo.yml
  => 7/7 match. The scoreboard Sigma layer genuinely works.

EVASION — change exactly ONE literal the red team chose:
  T1204 stage path -> /tmp/x.eicar        EVADED      T1557 signal_path -> /tmp/a.log     EVADED
  T1486 decoy path -> /home/u/docs        EVADED      T1053 entry -> /usr/local/bin/…     EVADED
  T1041 UA -> Mozilla/5.0                 EVADED      T1110 drop the `params` field       EVADED
  => 6/6 evaded. Coverage is 100% dependent on the attacker not changing a string.

FORGERY — unauthenticated syslog injection:
  bare "NOPASSWD"                                    -> privesc_sudo.yml  (level: high)
  bare "sudo -l"                                     -> privesc_sudo.yml
  "…user reviewed NOPASSWD policy doc"               -> privesc_sudo.yml
  all 7 advisories replayed verbatim by any peer     -> MINTABLE (7/7)
```
This is the empirical proof behind T2 and R10: `privesc_sudo.yml:29-30`'s
`condition: keywords **or** sudo_nopasswd` makes a 8-character UDP datagram a HIGH-severity
"detection" that adds to the blue score — or, timed into inter-campaign dead air, a false positive
that subtracts 5 points via `scorer._correlate()`.

### 2.2 Zeek `_path` — settled empirically
```
$ zeek -b t.zeek            # redef LogAscii::use_json = T; NOTICE(...) at zeek_init
$ head -1 notice.log
{"ts":1786635969.698105,"note":"PurpleProbe::Test_Notice","msg":"purple-team _path probe",
 "actions":["Notice::ACTION_LOG"],"email_dest":[],"suppress_for":3600.0}
=> no "_path" key.
```
`zeek.conf:49` `if [_path] == "notice"` can never match. **100%** of Zeek notices (port scan,
lateral movement, DNS exfil) land in `zeek-*` with no `event.kind`, no `event.category`.
*Caveat:* tested on Zeek 8.0.5; compose pins `zeek/zeek:7.0`. `_path` is injected by the
`json-streaming-logs` package (not loaded anywhere in this repo), not by the base writer, in
both versions — but a one-line confirmation inside the pinned image is cheap and worth doing.

### 2.3 syslog advisory wire format — **new finding, not in any audit**
```
$ # emit_syslog_advisory reproduced verbatim against a local UDP listener
RAW DATAGRAM: b'<12>aib-sudo: {"signature": "sudo_abuse_simulation", "audit": "sudo:   labuser :
               COMMAND=/usr/bin/find ; NOPASSWD", "check": "sudo -l"}\x00'
after <PRI> strip: 'aib-sudo: {"signature": …'
syslog.conf:21 grok = %{SYSLOGTIMESTAMP} %{HOSTNAME} %{DATA:program}(\[%{POSINT}\])?: %{GREEDYDATA}
=> NO MATCH — no RFC3164 timestamp, no hostname.
```
Python's `logging.handlers.SysLogHandler` prepends only `<PRI>`. Consequences:
1. `[program]` and `[syslog_message]` are **never populated** for any campaign advisory, so the
   T1548.003 / T1053.003 / T1110 tagging blocks at `syslog.conf:35/45/54` are **dead for the lab's
   own traffic** (T8). Every syslog-sourced ATT&CK enrichment in the SIEM is inert.
2. The `date` filter at `:24-27` has no `syslog_timestamp` to parse, so `@timestamp` falls back to
   ingest time — accidentally neutering T9 *for advisories only*, not for a crafted datagram.
3. The scoreboard survives because `_sigma_detection_ts` reads `doc['message']`, which retains the
   JSON. *(Static: I could not run Logstash. The `logstash-input-syslog` plugin sets `message` to
   the received payload and tags `_grokparsefailure_sysloginput` on internal parse failure; the
   custom grok at `:21` then adds `_grokparsefailure`. Verify by checking for those two tags on any
   `syslog-*` doc after a campaign run.)*
4. There is a trailing `\x00` on the datagram — worth confirming Logstash strips it.

### 2.4 Sigma compile pipeline — the fix is not what the audit recommended
```
$ ls -l blue-team/detection/sigma/compiled/     # 7 files, all 1619 bytes
$ head -1 …/exfil_https.eql.json
Sigma, version 1.1.3: simple greedy multiple alignment        # bioinformatics tool — CONFIRMED

$ sigma --version                                # the CORRECT sigma-cli, installed on this host
Error: No such option: --version      exit=2
$ sigma list targets                             # works: lucene, eql, esql, elastalert
$ python3 -c "import sigma.cli"                  # ModuleNotFoundError

$ for r in blue-team/detection/sigma/*.yml; do sigma convert -t eql --without-pipeline \
    -f siem_rule "$r"; done
=> 7/7 exit 0, 7/7 VALID JSON (1516–2212 bytes)
```
**Correction to `20260813-blue-team-security.md`:** its recommended guard
`sigma --version 2>&1 | grep -q '^sigma-cli'` **would reject the correct binary** — sigma-cli has no
`--version` option and exits 2. Its alternative, `python -m sigma.cli`, is also unavailable (the CLI
ships as a console script, not an importable `sigma` module in the system interpreter). Use
`sigma list targets >/dev/null 2>&1 || exit 1` instead — verified to pass on sigma-cli and fail on
the bioinformatics tool (which has no `list` subcommand).

### 2.5 Compiled artifacts don't reach the lab even when the compile is fixed — **new finding**
Inspecting a *correctly* compiled artifact reveals **three further blockers** stacked behind T5:

```json
"index": ["apm-*-transaction*","auditbeat-*","endgame-*","filebeat-*","logs-*",
          "packetbeat-*","traces-apm*","winlogbeat-*","-*elastic-cloud-logs-*"],
"query": "any where (\".locked\" or \"ransom_note.txt\") and \"/tmp/ransom-decoys\"",
"rule_type_id": "siem.queryRule", "consumer": "siem", "params": { … }
```
- **B2 — wrong index set.** `--without-pipeline` leaves Elastic's *default* SIEM index list. The lab
  writes to `suricata-*`, `zeek-*`, `syslog-*`, `red-team-events-*`, `ir-events-*` — **none** of which
  appear. Even a perfectly deployed rule queries indices that will always be empty.
- **B3 — degenerate EQL.** Keyword-only Sigma rules compile to bare string literals as boolean
  operands (`any where ".locked" …`). That is not a field-scoped search; it is not a well-formed
  EQL boolean expression.
- **B4 — wrong API shape.** `-f siem_rule` emits the Kibana **Alerting** framework body
  (`rule_type_id` / `consumer` / `params`), but `compile_sigma.sh:71` POSTs it to
  `/api/detection_engine/rules`, which expects a flat Detection-Engine body (`name`, `type`,
  `query`, `index`, `severity`, `risk_score`, `rule_id`, …). The resulting 400 is swallowed by
  `|| echo "[warn] … (may already exist)"` at `:75`. `sigma list formats eql` shows
  `siem_rule_ndjson` is the format intended for saved-object import.

**Implication for the backlog:** "fix the `compile_sigma.sh` identity check" does **not** unblock the
Kibana Sigma layer. It unblocks *step 1 of 4*.

### 2.6 IR containment scripts — read and confirmed on disk
- `ransomware_ir.yml` and `data_exfil_ir.yml` call `isolate_host.sh` and contain **no**
  `restore_host.sh` step; only `lateral_movement_ir.yml:69` restores. Confirmed by grep of all four
  playbooks. This violates the invariant written in `lateral_movement_ir.yml:64-66` (OQ-3, ADR 0001).
- `restore_host.sh:20` `docker network connect "$LAB_NET" "$TARGET"` under `set -euo pipefail` (`:8`)
  aborts on "endpoint already exists", **before** line 23's disconnect — the `|| true` is on the
  wrong line. A half-isolated host can never be restored by the shipped tool.
- `isolate_host.sh:25,28` is connect-then-disconnect with no rollback; a failure at `:28` strands the
  target on both networks and exits.
- Neither script validates `$TARGET` against a charset or a denylist — `isolate_host.sh elasticsearch`
  destroys the SIEM mid-incident, and a leading `-` reaches Docker's flag parser (CWE-88). The
  dashboard guards this at `app.py:176`; the scripts' own documented CLI usage does not.

---

## 3. Gap analysis, prioritised

### 3.1 P0 — the scoreboard cannot be trusted, and the SIEM reports green while deploying nothing

These four are ranked above everything else because they invalidate the *measurement*. Every other
row in the truth table is an assertion about a system whose output cannot currently be believed.

**Gap A — The score is forgeable and the detections are mintable (T1, T2, T11).**
- *What the attacker does*: one `curl -XPOST elasticsearch:9200/red-team-events-1/_doc` (10 base +
  15 stealth points per fake campaign), or one `logger -n logstash -P 5514 "NOPASSWD"` (one blue
  detection, verified §2.1), or `DELETE /suricata-*` (zero the opponent).
- *Why nothing catches it*: `xpack.security.enabled: false` + `9200:9200` on `0.0.0.0` means no
  authentication and — by construction — no ES audit log. `scorer._sigma_detection_ts` runs
  `{"match_all": {}}` over `syslog-*` and discards the source entirely.
- *Proposed detection / control* (pseudocode; field names verified against the pipelines):
  1. Bind `127.0.0.1:${PORT}` for **every** published service (`BIND_ADDR` in `.env.example`), and
     set `action.auto_create_index: "suricata-*,zeek-*,syslog-*,red-team-events-*,ir-events-*,-*"`.
  2. In `syslog.conf`, before the grok: copy the input's own sender address to
     `[observer][ingress][ip]` and stamp `[log][provenance] = "untrusted-syslog"` on every document.
  3. In `scorer._sigma_detection_ts`, replace `{"match_all": {}}` with a filter on
     `[observer][ingress][ip] == ATTACKER_IP` **and** a per-run nonce that
     `emit_syslog_advisory` writes and the matching `campaign_start` doc records.
  4. Anomaly rule: `campaign_end` with no preceding `campaign_start` for the same `campaign_id`;
     any `red-team-events-*` doc whose `@timestamp` precedes its `_ingest` time by > 60 s.
- *Required telemetry*: already present (`syslog-*`, `red-team-events-*`); item 2 needs a Logstash
  edit, not a new log source.
- *Evasion resistance*: 3 closes anonymous minting from other containers; a red-team-container shell
  can still forge (accepted — that is the threat model). 4 closes replay/backdating.
- *Effort*: **Medium** (1 compose edit, 1 pipeline edit, ~20 lines in `scorer.py`).

**Gap B — The Kibana Sigma layer deploys nothing, with a green build (T5, B2, B3, B4).**
- *What the attacker does*: nothing. No evasion is required.
- *Why nothing catches it*: four stacked blockers (§2.4, §2.5), each independently masked — wrong
  binary satisfies `command -v`, convert exits 0 into `> "$out"`, wrong index set, degenerate EQL,
  wrong API shape, and `|| echo warn` on the import. CI commit `7bacb08` added a retry loop that
  makes a deterministic failure look intermittent.
- *Proposed fix*:
  ```bash
  sigma list targets >/dev/null 2>&1 || { echo "[ERROR] sigma-cli not installed" >&2; exit 1; }
  # …per rule:
  sigma convert -t eql -p <lab-pipeline> -f siem_rule_ndjson "$rule" > "$out"
  jq -e 'type=="object" and has("query")' "$out" >/dev/null || { echo "[ERROR] $rule"; exit 1; }
  ```
  plus a lab processing pipeline that sets `index: ["syslog-*","suricata-*","zeek-*"]` and maps the
  keyword selections onto a real field (`message`), and an import that captures `%{http_code}`,
  treats 409 as OK and anything else as fatal. Post-import, `GET /api/detection_engine/rules/_find`
  and assert `total == <source rule count>`.
- *Effort*: **High** — B2/B3 need a Sigma processing pipeline authored for this lab's index/field
  layout; that is real work, not a one-liner.
- *Interim*: **document that the scoreboard's `sigma_eval` path is the authoritative Sigma layer**
  and that `compiled/` is currently decorative. Delete the stale artifacts so nobody mistakes them
  for coverage.

**Gap C — The operator dashboard and every Zeek detection are invisible (T6, T7, T8).**
- Three one-line pipeline defects that together mean: the headline dashboard renders zero data, no
  Zeek notice is ever an alert, and no syslog ATT&CK tag is ever applied to lab traffic.
- *Proposed fix*:
  - `suricata.conf` / `zeek.conf` / `syslog.conf`: add
    `add_field => { "[event][dataset]" => "suricata"|"zeek"|"syslog" }` at filter top level (outside
    the alert guard, matching `zeek.conf:56-59`'s structure).
  - `zeek.conf:49`: `if [path] =~ /notice\.log$/ or [_path] == "notice"` — `path` is populated by the
    file input unconditionally (`zeek.conf:9-10` enumerates `notice.log`).
  - `base_campaign.emit_syslog_advisory`: emit RFC3164-shaped lines
    (`SysLogHandler(..., ident=...)` does not add a timestamp — set the formatter to
    `f"%(asctime)s {socket.gethostname()} {program}: %(message)s"` with
    `datefmt="%b %e %H:%M:%S"`), **or** relax `syslog.conf:21` to make the timestamp/host prefix
    optional. Prefer the latter: it also fixes hand-rolled `logger(1)` advisories.
- *CI assertion that stops recurrence*: every field referenced by a dashboard NDJSON query must be
  emitted by at least one pipeline (`tests/test_detection_ingest.py`).
- *Effort*: **Low** (three pipeline edits + one emitter/grok change). Highest ratio of coverage
  restored to lines changed in the entire backlog.

**Gap D — Sigma coverage is tautological: the red team controls the blue team's score (R7, R9, R10, R15, R16, R17).**
- *Verified*: 6/6 techniques evaded by mutating one string (§2.1).
- *Proposed detection*: keep the marker rules for scoreboard wiring, and ship a **second,
  path-independent rule per technique**, scored separately:

  | Technique | Behavioural rule | Log source needed |
  |---|---|---|
  | T1486 | ≥ N file renames to a single new extension in < 60 s in one directory | file-event telemetry — **not currently collected** |
  | T1110 | auth-failure **rate** per source | present (`syslog-*`) once Gap C is fixed |
  | T1557 | duplicate MAC↔IP binding | Zeek — needs Gap E first |
  | T1048.003 | Shannon entropy > 3.5 bits/char on a DNS label + NXDOMAIN rate + TXT/NULL qtype volume | Zeek `dns.log` — needs Gap E |
  | T1041 | bytes-out per flow z-score | Zeek `conn.log` — needs Gap E |
  | T1053.003 | new crontab entry referencing `/tmp`, `/dev/shm`, or a network client | file/process telemetry — **not currently collected** |
- **Prerequisite-log gap (separate remediation path):** T1486 and T1053.003 have **no host
  process/file-event collector anywhere in the lab** (no auditd, no Falco, no osquery). Also flagged
  independently by the target-env audit: "a `gcc` invocation or a `curl` inside `victim-web` produces
  zero telemetry." This is **infrastructure**, not a rule — it should be tracked as such.
- *Effort*: **Low** for the two that only need Gap C; **High** for the four that need a new collector.

### 3.2 P1 — containment gaps that could let the lab escape its air-gap

**Gap E — Zeek has no visibility, and the one thing that would prove it doesn't exist.**
`ZEEK_IFACE=eth0` on a bridge-attached container sees broadcast/multicast and its own traffic only;
unicast attacker→victim is forwarded by the Linux bridge solely to the destination veth. Suricata
gets this right (`network_mode: host` + `br-*` auto-detect, `docker-compose.yml:190,230`) and the
contrast is the proof. *Fix*: move Zeek to `network_mode: host` with `NET_RAW`/`NET_ADMIN` and reuse
Suricata's bridge auto-detect. *Add the missing alarm*: fail the healthcheck if `conn.log` has zero
entries N seconds after known lab traffic — today "no attacks" and "no visibility" are
indistinguishable. **Then** fix `port_scan.zeek:16` (`>15` ports vs a 10-port campaign — row R1) and
`dns_exfil.zeek:10` (length-only, threshold 30). *Effort*: **Medium**.

**Gap F — The air-gap is asserted, never proven (C1, C2, C3, C4, C8).**
Five findings, one root cause: **prevention exists; verification does not.** `internal: true` is
real, and the victims' structural containment (no ports, no mounts, no caps, no docker.sock) is
genuinely good — but nothing tests it, the preflight fails open on every resolver error, `.env` can
`exit 0` past it, and the bypass leaves no artifact. *Fix as one workstream*:
`tests/test_compose_containment.py` (parse `docker compose config`; assert no `ports`/`volumes`/
`network_mode`/`privileged`/`cap_add` on the three victims and `internal: true` on both networks) +
`scripts/safety/containment_test.sh` (assert **from inside each victim**, with distinct exit codes:
external TCP blocked, external DNS unresolvable, host gateway `:9200` unreachable) + a resolver
control probe in `egress_test.sh` + stop `source`-ing `.env` + write the `AIB_SKIP_PREFLIGHT` bypass
to a path `reset.sh` does not wipe. Add the containment tripwire that the target-env audit proposed
and which **does not exist**: `alert ip $HOME_NET any -> !$HOME_NET any (msg:"AIB CONTAINMENT lab
host reached non-lab address"; sid:1000200;)` — Suricata is correctly positioned to see it.
*Effort*: **Medium** (one test file, one script, three small edits). *Note*: whether Docker's
`internal` flag covers the container→gateway INPUT path is version-dependent — settle it empirically
before deciding how much of C1 is live.

**Gap G — The red team's scope gate does not cover the campaigns that move data (C5, C6, C7).**
`C2_URL`/`C2_DNS_DOMAIN` are outside `TARGET_ENV_VARS`; `LAB_NET_PREFIX` never reaches the container
so the allowlist evaluates against the wrong /24; `TARGET_DB`/`TARGET_MAIL` name mismatches mean
hardcoded IPs win and the "defaults are trusted" branch never vets them. *Fix as one change*: vet the
**effective** value after default resolution rather than skipping unset variables, add all four
variables to the sweep, pass `LAB_NET_PREFIX` into the red-team service, and assert
`ipaddress.ip_network(f"{prefix}.0/24").is_private`. Add one allowlist test **per variable** rather
than per campaign. *Effort*: **Low**. *This is the only Blind row where the consequence is traffic
leaving the lab*, which is why it sits in P1 despite being cheap.

**Gap H — IR containment is unsafe and unobservable (T10, §2.6).**
Two playbooks strand a host on `quarantine-net` permanently; `restore_host.sh` cannot recover it;
`isolate_host.sh <any-name>` will quarantine `elasticsearch` mid-incident; and no containment action
reaches the SIEM. *Fix*: append the `restore_host.sh` step to `ransomware_ir.yml` and
`data_exfil_ir.yml`; make both scripts idempotent and post-condition-checked
(`docker inspect --format '{{json .NetworkSettings.Networks}}'` before declaring success); apply the
dashboard's `_SAFE_HOST_RE` inside the scripts, insert `--` before positionals, and deny
infrastructure services by `com.docker.compose.service` label; POST one `ir-events-*` doc **per
action** with `action`/`target`/`operator`/`source_ip`/`campaign_id`. Add the CI test that asserts
every playbook containing `isolate_host.sh` also contains `restore_host.sh` for the same `{var}`.
*Effort*: **Low-Medium**.

### 3.3 P2 — individual detection-rule logic bugs

Grouped by root cause, not one line per bug.

**Gap I — Rules that cannot match their own campaign (R1, R3, R4, R6).** Four rules whose signature
does not describe what the lab's own red team actually does: sid:1000010 lists six extensions and
the campaign attaches a `.pdf`; sids 1000020/1000023 inspect `http_uri` and the SQLi is a POST body;
`port_scan.zeek` needs >15 ports and the scan uses 10; sid:1000022 needs `../` and the working
traversal is a bare absolute path. *Fix*: add `pdf|doc|docm|zip|iso` to sid:1000010's pcre; duplicate
each `http_uri` rule against `http.request_body` (`http-body-inline` is already enabled at
`suricata.yaml:161`); lower `port_scan.zeek:16` to 8 with a second 10-minute-epoch reducer for slow
scans; add `content:"/file?name=/"; http_uri;` for the absolute-path read.
**Then add the regression net that would have caught all four: a pcap-replay test per sid in CI.**
*Effort*: **Low** per rule; **Medium** for the pcap harness — but the harness is what makes the rest
durable.

**Gap J — Rules that are structurally dead (R2, R14, plus sid:1000052).** sid:1000003 (`depth:5`
excludes the qtype/qclass bytes), sid:1000050 (two independent errors), sid:1000052 (greedy pcre
defeats its own negative lookahead), sid:1000040 (SMB1-only, and `smb:` is absent from
`suricata.yaml` `app-layer.protocols`). *Fix*: rewrite against sticky buffers — `dns.query;
content:"version.bind"; nocase;` for 1000003; `dns.query; bsize:>50;` + a QNAME-scoped pcre for
1000050; `pcre:"/User-Agent:\s*(?!(Mozilla|Chrome|Safari|curl|python))[^\r\n]+/H"` for 1000052; a
paired `|FE|SMB` rule + enable `smb:` for 1000040. *Effort*: **Low**.

**Gap K — Rules that are alert-storm / false-positive machines (R10, R13, R17).** sid:1000042 (no
flow, no content, no threshold ⇒ per-packet on all internal SSH), sid:1000041 (thresholds *packets*,
not auth failures — a single legitimate login exceeds 5), sid:1000030 (`content:"-l"` is a two-byte
match), sid:1000060 (bare `content:"crontab"`). These are an *offensive* capability: an attacker
floods `eve.json` to bury real alerts and fill a bind-mounted log directory. *Fix*: delete
sid:1000030 and sid:1000060 and document T1548.003/T1053.003 as host-telemetry detections (as was
correctly done for the `$EXTERNAL_NET` rules at `local.rules:37-48`); add
`flow:established,to_server;` + `threshold:type limit,track by_src,count 1,seconds 300` to
sid:1000042; delete or rekey sid:1000041. Ship a `threshold.config` and monitor `eve.json` size.
*Effort*: **Low**.

**Gap L — Sensor configuration that silently disables app-layer detection.**
`suricata.yaml:118 checksum-validation: yes` on offloaded veth/bridge capture discards packets before
stream reassembly, which would silently kill **every** `http`/`smtp` rule — including R5, R6 and the
lab's one Covered row, R8. *(Static — this is the single highest-value item to hand to
tester-debugger, because it determines whether the Covered row is actually covered.)* Also
`HTTP_PORTS: "80"` only, and `double-decode-path: no`. *Fix*: `checksum-validation: no`, broaden
`HTTP_PORTS` to `[80,8000,8080,8888]`, enable double-decode, and monitor `stats.log`
`tcp.invalid_checksum`. *Effort*: **Low**.

**Gap M — PKI issuance has no ledger and no detection (C9).** `issue_cert.sh` bypasses `openssl ca`
so `index.txt` records nothing; a cert minted via SAN injection leaves no trace. `validate-certs`
alarms on every legitimate lab TLS connection (lab root is not in Zeek's Mozilla store, and no
`redef SSL::root_certs` exists anywhere), so a forged cert is indistinguishable from baseline noise.
`x509.log` is not in `zeek.conf`'s input list, so analysts cannot pivot on subject/issuer/fingerprint.
*Fix*: validate CN/SAN args and refuse reserved basenames (`ca`, `intermediate`, `root`) — this also
closes the CA-key-destruction primitive; switch issuance to `openssl ca` so the ledger is real; ship
`/zeek-logs/x509.log`; suppress `SSL::Invalid_Server_Cert` for the lab PKI host so the notice retains
signal; emit a structured issuance event per cert and alert on any `x509` issuer that is not the lab
Intermediate. *Effort*: **Medium**.

---

## 4. Prioritised remediation backlog (grouped by root cause)

Ordered so that each group unblocks the ones below it.

**P0-1 — Make the measurement trustworthy.** *(Gap A + Gap C — do these together; C is the
cheapest high-yield change in the repo.)*
1. `BIND_ADDR=127.0.0.1` for every published port; `action.auto_create_index` restricted to the five
   known patterns.
2. Add `[event][dataset]` to all three pipelines; change `zeek.conf:49` to key on `[path]`; fix the
   advisory/grok mismatch so `[program]` populates.
3. Add `[observer][ingress][ip]` + `[log][provenance]` provenance stamping to `syslog.conf`; filter
   `scorer._sigma_detection_ts` on it; add the campaign_start/campaign_end and timestamp-skew
   anomaly checks.
4. `logging.basicConfig` + `LOG_LEVEL` in the scoreboard so successful awards actually log.
> **Unblocks:** T2, T6, T7, T8, T11 and the *scoring validity* of every Tier-3 row. Restores the
> operator dashboard and all three Zeek detections' alert semantics in ~10 edited lines.

**P0-2 — Stop reporting a green build for a dead detection layer.** *(Gap B)*
1. Replace the `command -v sigma` guard with `sigma list targets >/dev/null 2>&1` — **not** the
   `--version` check the blue-team audit recommended (§2.4 proves it rejects the correct binary).
2. `jq -e` assert each converted artifact; fail the loop otherwise.
3. Capture `%{http_code}` on the Kibana POST; 409 = OK, anything else = fatal. Drop `|| echo warn`.
4. Revert CI commit `7bacb08` (the retry loop) so this fails loudly.
5. Author a lab Sigma processing pipeline setting `index: [syslog-*, suricata-*, zeek-*]` and mapping
   keyword selections to `message`; switch to `-f siem_rule_ndjson`; assert rule count post-import.
6. Delete the stale `compiled/*.eql.json` and document that `sigma_eval` is the authoritative path
   until 5 lands.
> Items 1-4 and 6 are **Low** effort and should ship this week. Item 5 is **High** and is the real
> fix; do not let 1-4 create the impression the Kibana layer is live.

**P1-1 — Prove the air-gap instead of asserting it.** *(Gap F + Gap G)*
`tests/test_compose_containment.py`; `scripts/safety/containment_test.sh` run from **inside** each
victim; resolver control probe in `egress_test.sh`; stop `source`-ing `.env`; durable
`AIB_SKIP_PREFLIGHT` artifact outside the `reset.sh` wipe path; Suricata `sid:1000200` containment
tripwire; vet **effective** target values and add `C2_URL`/`C2_DNS_DOMAIN`/`SIEM_*` to
`TARGET_ENV_VARS`; pass `LAB_NET_PREFIX` into the red-team service; require the prefix to be private.
> **Unblocks:** C1-C8. This is the only group where the failure mode is packets leaving the lab.

**P1-2 — Give the network sensor tier a second sensor.** *(Gap E)*
Zeek to `network_mode: host` + bridge auto-detect; zero-`conn.log` healthcheck assertion; then
`port_scan.zeek` threshold 8 + slow-scan reducer, and `dns_exfil.zeek` entropy/qtype/NXDOMAIN checks.
> **Unblocks:** R1, R12, R13, R14 partially, and is a prerequisite for three of the six behavioural
> rules in Gap D.

**P1-3 — Make IR containment safe and observable.** *(Gap H)*
Restore steps in both playbooks; idempotent + post-condition-checked scripts; `--` and charset guard
and infrastructure denylist on `$TARGET`; per-action `ir-events-*` emission with real operator
attribution; CI test for isolate/restore symmetry.

**P2-1 — Build the regression net, then fix the rules.** *(Gap I + Gap J + Gap K + Gap L)*
Build the pcap-replay harness **first** (one pcap per sid, assert fires/doesn't-fire) — every rule
bug in Tier 3 is a bug that shipped because a rule that has never fired is indistinguishable from a
rule with nothing to catch. Then, in one pass: `checksum-validation: no` + `HTTP_PORTS` +
double-decode (Gap L — verify first, it may silently gate the one Covered row); the four
can't-match-own-campaign signatures (Gap I); the four structurally-dead rules (Gap J); delete/rekey
the four FP machines (Gap K).

**P2-2 — Behavioural fallbacks so the red team stops controlling the blue score.** *(Gap D)*
Ship the T1110 auth-rate and (post-P1-2) T1557 duplicate-MAC, T1048.003 entropy and T1041 volume
rules; score them separately from the marker rules; label every rule explicitly as
*lab-instrumentation* or *real detection*.

**P2-3 — PKI issuance ledger + certificate detection.** *(Gap M)*

**INFRA — prerequisite log gaps (not rule work; track separately).**
- **No host process/file-event telemetry anywhere in the lab.** Blocks the behavioural rules for
  T1486 and T1053.003, and means T1548.001 (R11) and T1098.004 (R18) have **no possible ingest path**
  regardless of what rule is written. Options: auditd in the victims, Falco, or extend
  `emit_syslog_advisory` to the five campaigns that currently emit nothing (cheap, but keeps the
  tautology of Gap D).
- **No ES audit log** — unavailable by construction while `xpack.security.enabled: false`. T3 and T4
  cannot be *detected* until authentication is enabled; until then they can only be *prevented*
  (loopback binding).
- **No container stdout shipped to ELK** — no docker/filebeat input in any pipeline, so the
  scoreboard's award log and the victims' `mynetworks` echo can never be alerted on.

---

## 5. Validated detections — what the blue team can actually trust

Short list, and that is the point.

1. **T1110 HTTP brute force — `local.rules` sid:1000090.** The only genuinely layered technique:
   a real network signature on a real wire path (10 POSTs at 1 s ⇒ inside the 5-in-60 s threshold,
   verified against `brute_force.py:35-47`) **plus** independent Sigma confirmation. *Trust with one
   caveat*: Gap L (`checksum-validation: yes`) is unverified and could silently disable it — settle
   that first.
2. **`forensics/scoreboard/sigma_eval.py` as an evaluator.** The matcher itself is sound: it fails
   closed on mixed `and`/`or` conditions, fails closed on unknown selection names, uses
   `yaml.safe_load`, and correctly evaluates all 7 rules (7/7 verified). **The evaluator is
   trustworthy; its input is not.**
3. **Suricata's sensor placement.** `network_mode: host` + `br-*` auto-detect + digest-pinned image
   is correct and is the pattern Zeek should copy.
4. **The dashboard's trust boundary — `blue-team/dashboard/app.py:173-201`.** Closed key allowlist,
   `ipaddress.ip_address()` parsing, hostname charset with an explicit leading-`-` guard,
   `playbook_id` restricted to the registry, `subprocess.run` always list-form, `hmac.compare_digest`,
   fail-closed secret handling. This is the model the IR shell scripts should be held to.
5. **`block_ip.sh` being explicitly simulated.** Correctly and deliberately prevents forged syslog
   alerts from chaining into automated enforcement. A real control decision, documented as such.
6. **Structural containment of the victims.** No published ports, no host bind-mounts, no
   `privileged`, no `cap_add`, no docker.sock on any of the three. This is the property that makes
   the lab safe today — which is precisely why Gap F (lock it with a test) is P1.

---

## 6. Items requiring runtime confirmation (hand to tester-debugger)

Ordered by how much of the truth table depends on the answer.

1. **`suricata.yaml:118 checksum-validation: yes` on veth capture** — gates R5, R6 **and the one
   Covered row R8**. `suricata --dump-config | grep checksum` plus `stats.log`
   `tcp.invalid_checksum` during a campaign.
2. **pcap replay per sid** — 1000001/2/3, 1000010, 1000020-23, 1000030, 1000040, 1000041, 1000042,
   1000050, 1000052, 1000060, 1000090. Nine are asserted dead or mis-signatured on static reading.
3. **`conn.log` after a campaign run** — confirms Gap E quantitatively (expect near-zero).
4. **`_grokparsefailure` / `_grokparsefailure_sysloginput` tags on `syslog-*` docs** after a campaign
   — confirms §2.3 end-to-end through Logstash, and that `message` retains the JSON.
5. **`_path` inside the pinned `zeek/zeek:7.0` image** — one `head -1 /var/log/zeek/notice.log`.
   §2.2 settles it for 8.0.5.
6. **Docker `internal` and the container→gateway INPUT path** — determines how much of C1 is live
   versus theoretical, and whether a victim can reach `172.20.0.1:9200`.
7. **`find … -exec bash -n {} \;` exit-status propagation** (scripts audit F5) — determines whether
   the syntax gate can fail at all.
