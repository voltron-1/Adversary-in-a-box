# Milestone M13 + Issue Draft — Phase G Remediation

**Not yet executed.** This is the exact content that would be created via `gh api`/
`gh issue create` against `voltron-1/Adversary-in-a-box`, for review before any mutation
runs. Matches the *live* GitHub scheme (verified via `gh api`/`gh issue list`/
`gh label list` against milestones M1-M12, not the stale `scripts/setup/user_stories.yml`):

- Title format: `Phase G<id>: <short title>` (mirrors Phase A's clean single-prefix
  style — Phase F's actual issues are titled `Phase FF<n>`, an apparent double-letter
  quirk from whatever generated them; not replicated here unless you want consistency
  with that quirk instead).
- Body format: `Source: docs/IMPLEMENTATION_PLAN.md Phase G<id>. Estimated size: <X>.` +
  blank line + description + `**Acceptance:**` + `**Why now:**` — matches all 99
  existing issue bodies sampled.
- **No per-issue labels** — matches actual practice (all 99 sampled issues have empty
  `labels: []` despite the `points/*`, `priority:*`, `sprint:*`, `domain-*`, `persona:*`
  taxonomy existing in the repo's label list). Flagging this because it means the label
  taxonomy is effectively unused tooling debt — worth a separate decision on whether to
  start using it or remove it, out of scope for this remediation effort.
- Every issue added to project **#8 "Adversary-in-a-box Agile Project"** (not
  `user_stories.yml`'s default title `"Adversary-in-a-Box"`, which doesn't match any
  live project). Status field on that project has only `Todo`/`In Progress`/`Done`
  (not `Backlog`/`In Review` as `setup_project_board.sh` assumes).

---

## Milestone

```
Title:       M13 - Security & Measurement Remediation (Phase G)
Description: Phase G from docs/IMPLEMENTATION_PLAN.md: 2026-08-13 security audit +
             purple-team gap analysis remediation. 39 attacker technique/infra findings
             evaluated against detection coverage (1 Covered / 14 Partial / 24 Blind,
             findings/20260813-gap-analysis.md). 32 items across Phase 0 + 6 gated
             phases + an INFRA decision track. Goal: trustworthy scoreboard/dashboard,
             a proven (not asserted) air-gap, safe/observable IR containment, and
             detection coverage that isn't tautological (red team no longer controls
             its own detection by choosing a string).
State:       open
```

## Issues (32)

### Phase 0

**Phase G0.1: Runtime confirmation spike**
```
Source: docs/IMPLEMENTATION_PLAN.md Phase G0.1. Estimated size: S.

Read/test-only investigative spike, no code changes. Four environment-specific
behaviors gate later phases:
1. Does suricata.yaml:118 checksum-validation:yes discard packets pre-reassembly on
   veth capture? (suricata --dump-config | grep checksum; stats.log
   tcp.invalid_checksum during a campaign)
2. Does Docker internal:true cover the container->gateway INPUT path? Can a victim
   reach 172.20.0.1:9200? (from victim-web: socket.create_connection
   (('172.20.0.1',9200),3))
3. Is Zeek _path absent in the pinned zeek/zeek:7.0 image? (head -1
   /var/log/zeek/notice.log in the running container)
4. Does `find ... -exec bash -n {} \;` propagate exit status? (run against a
   deliberately broken .sh, check $?)

**Acceptance:** all four answered with evidence written to
findings/20260813-runtime-confirmation.md.

**Why now:** de-risks every later phase; nothing in Phase 1/3/5 that depends on
runtime behavior should be committed before this lands.
```

### Phase 1 — Make the measurement trustworthy

**Phase G1.1: Prevent score forgery & index squatting**
```
Source: docs/IMPLEMENTATION_PLAN.md Phase G1.1. Estimated size: S.

Introduce BIND_ADDR (default 127.0.0.1) in docker-compose.yml and rewrite every
published port as "${BIND_ADDR:-127.0.0.1}:HOST:CONTAINER" for ES, Kibana, scoreboard,
blue-team. Add BIND_ADDR to .env.example. Set
elasticsearch.yml action.auto_create_index to the explicit allowlist
(suricata-*,zeek-*,syslog-*,red-team-events-*,ir-events-*,.monitoring-*,-*).

**Acceptance:** ES/Kibana/scoreboard/blue-team ports bind 127.0.0.1 by default;
unlisted index patterns are rejected on write.

**Why now:** highest leverage / lowest cost in the whole backlog — an unauthenticated,
LAN-exposed ES means anyone on lab-net can forge a campaign's score. Fixing this is
~10 edited lines and unblocks trusting any other detection-coverage claim.
```

**Phase G1.2: Restore dashboard & Zeek alert semantics**
```
Source: docs/IMPLEMENTATION_PLAN.md Phase G1.2. Estimated size: M.

Add add_field => { "[event][dataset]" => "suricata"|"zeek"|"syslog" } to the top-level
mutates in zeek.conf/syslog.conf and a new one in suricata.conf (outside the
event_type==alert guard, so flow/dns/http records carry it too). Move
observer.type/observer.name out of the alert guard to top level. Fix zeek.conf:49's
`if [_path] == "notice"` to also match `[path] =~ /notice\.log$/`. Add a CI test in
tests/test_detection_ingest.py asserting every field referenced by a dashboard NDJSON
query is emitted by at least one pipeline.

**Acceptance:** operator dashboard renders live data after a campaign; new
test_detection_ingest field assertion is green; a Zeek notice carries event.kind:alert.

**Why now:** the operator dashboard currently renders zero data — the primary
measurement surface is silently broken. This is the second half of "make measurement
trustworthy."
```

**Phase G1.3: Provenance stamping + scorer integrity**
```
Source: docs/IMPLEMENTATION_PLAN.md Phase G1.3. Estimated size: S.

In syslog.conf, before the grok, copy the input sender address to
[observer][ingress][ip] and stamp [log][provenance] = "untrusted-syslog" on every doc.
In scorer.py:151, replace _sigma_detection_ts's {"match_all": {}} with a filter
requiring [observer][ingress][ip] == ATTACKER_IP. Add anomaly checks near scorer.py:
126-129 — drop campaign_end with no matching campaign_start for the same campaign_id;
drop red-team-events-* docs whose @timestamp precedes ingest time by >60s.

**Acceptance:** a syslog datagram from a non-ATTACKER_IP peer is not counted by the
scorer; anomalous campaign_end/backdated events are dropped.

**Why now:** without this, any host on lab-net can forge syslog advisories the scorer
will count as a real detection — the tautology this whole remediation effort is trying
to close.
```

**Phase G1.4: Scoreboard award audit trail logging**
```
Source: docs/IMPLEMENTATION_PLAN.md Phase G1.4. Estimated size: XS.

forensics/scoreboard/app.py is missing `import logging` + basicConfig at import time,
so the success log at :191-198 never actually emits. Add
logging.basicConfig(level=os.environ.get("LOG_LEVEL","INFO"), ...). Add
`- LOG_LEVEL=${LOG_LEVEL:-INFO}` to the scoreboard env block in docker-compose.yml,
matching red-team/blue-team.

**Acceptance:** award success events actually appear in scoreboard container logs.

**Why now:** cheap fix that restores auditability of who got awarded what and when —
currently invisible.
```

**Phase G1.5: Syslog ATT&CK tagging relaxation (T8, scoped-out)**
```
Source: docs/IMPLEMENTATION_PLAN.md Phase G1.5. Estimated size: XS.

The gap analysis's "just relax the grok" suggestion was incomplete: campaign advisories
emit program aib-<technique>, which won't match `if [program]=="sudo"` conditionals
even with the grok fixed, and the scoreboard already reads the raw message directly.
Relax syslog.conf:21 to make the timestamp/host prefix optional (so real host syslog
and logger(1) advisories both populate [program]).

**Acceptance:** real host syslog and logger(1) advisories both populate [program];
docs note that campaign-technique attribution lives in sigma_eval, not the pipeline
conditionals.

**Why now:** low priority — given the retire-Kibana decision, ES-side ATT&CK enrichment
on syslog docs only serves the analyst/dashboard surface, and its real host inputs
aren't shipped. Included for completeness, safe to slip if the phase is time-boxed.
```

### Phase 2 — Sigma layer honesty

**Phase G2.1: Fix compile_sigma.sh identity check + retire Kibana import path**
```
Source: docs/IMPLEMENTATION_PLAN.md Phase G2.1. Estimated size: S.

Replace compile_sigma.sh:31's `command -v sigma` with an identity check:
`sigma list targets >/dev/null 2>&1 || { echo "[ERROR] sigma-cli not installed";
exit 1; }`. (Not `sigma --version | grep sigma-cli` — verified to reject the correct
binary, which has no --version.) Remove the REBASE/curl .../api/detection_engine/rules
block (:67-77) or gate it behind a loud "experimental, not wired to this lab's indices"
warning.

**Acceptance:** compile_sigma.sh fails loudly against the Debian bioinformatics
`sigma` binary shadowing sigma-cli on PATH; succeeds against real sigma-cli.

**Why now:** per the locked RETIRE decision — the Kibana Sigma layer is non-functional
by design (wrong index set, degenerate keyword-only EQL, wrong API shape) and
sigma_eval is the one detection consumer that actually works. This closes the false
sense of security from a compile step that currently accepts the wrong binary silently.
```

**Phase G2.2: Delete stale compiled Sigma artifacts + CI content assertion**
```
Source: docs/IMPLEMENTATION_PLAN.md Phase G2.2. Estimated size: XS.

Delete the stale local blue-team/detection/sigma/compiled/* (gitignored, regenerated by
CI). Add `jq -e 'type=="object"'` after each convert in compile_sigma.sh; fail the loop
on non-JSON. In validate.yml:146-156, keep the compile-as-syntax-check but add the jq
content assertion so degenerate output can't pass green.

**Acceptance:** git status shows no tracked artifact churn; CI fails on
empty/invalid compile output, not just non-zero exit.

**Why now:** the retry loop in CI currently masks a MITRE-data network fetch, not a
content guard — an empty or malformed compile currently reads as success.
```

**Phase G2.3: Document sigma_eval as authoritative Sigma consumer**
```
Source: docs/IMPLEMENTATION_PLAN.md Phase G2.3. Estimated size: XS.

Add a short note (README or docs/) stating forensics/scoreboard/sigma_eval.py is the
authoritative Sigma consumer (reads .yml directly) and compile_sigma.sh is a syntax
linter only, not a functioning Kibana pipeline.

**Acceptance:** note is discoverable from README or docs/ index.

**Why now:** prevents a future contributor from "fixing" the Kibana import path the
RETIRE decision deliberately abandoned.
```

### Phase 3 — Prove the air-gap + close the red-team scope gate

**Phase G3.1: New containment compose-config test**
```
Source: docs/IMPLEMENTATION_PLAN.md Phase G3.1. Estimated size: S.

New tests/test_compose_containment.py: parse `docker compose config`; assert the three
victims have no ports/volumes/network_mode/privileged/cap_add/pid, networks are a
subset of {lab-net, quarantine-net}, and internal: true is set on both networks. Wire
into validate.yml.

**Acceptance:** test passes against current compose (becomes the regression guard
going forward); wired into CI.

**Why now:** the lab's structural containment is currently good but held together by
convention, not tests — this is the only group of findings whose failure mode is
packets actually leaving the lab.
```

**Phase G3.2: New live containment probe script**
```
Source: docs/IMPLEMENTATION_PLAN.md Phase G3.2. Estimated size: S.

New scripts/safety/containment_test.sh: assert from inside each victim, with distinct
exit codes, that external TCP is blocked, external DNS is unresolvable, and the
host-gateway :9200 is unreachable. Call from start.sh after the health poll and as an
integration.yml step.

**Acceptance:** script fails closed (non-zero) if any of the three probes succeed from
inside a victim container.

**Why now:** proves the air-gap live, at every lab startup, instead of asserting it in
documentation.
```

**Phase G3.3: Harden egress_test.sh**
```
Source: docs/IMPLEMENTATION_PLAN.md Phase G3.3. Estimated size: S.

Add a resolver control probe (hard-fail if a known-good domain won't resolve, so
"resolver broken" converts from PASS to ERROR instead of a false-positive pass). Stop
sourcing .env directly — parse the two needed keys with sed, reject non-KEY=VALUE
lines. Wrap getent/python3 resolver paths in timeout.

**Acceptance:** egress_test.sh returns non-zero on a resolving domain (real leak) and
ERROR (not PASS) on a broken resolver.

**Why now:** today a broken resolver silently passes the safety check it's supposed to
gate lab startup on.
```

**Phase G3.4: Durable AIB_SKIP_PREFLIGHT bypass artifact**
```
Source: docs/IMPLEMENTATION_PLAN.md Phase G3.4. Estimated size: XS.

In scripts/lab/start.sh, write the AIB_SKIP_PREFLIGHT=1 bypass record to a
logs/-adjacent path that reset.sh does NOT wipe (durable artifact). Drop the
AIB_SKIP_PREFLIGHT hint from the exec-bit error string (reduces accidental bypass
discovery).

**Acceptance:** a preflight bypass survives `reset.sh` and remains auditable after a
lab reset.

**Why now:** small hardening item that closes an audit trail gap on the one
documented way to skip the safety preflight.
```

**Phase G3.5: Suricata containment tripwire rule**
```
Source: docs/IMPLEMENTATION_PLAN.md Phase G3.5. Estimated size: XS.

Add to blue-team/detection/suricata/local.rules (does not exist today):
`alert ip $HOME_NET any -> !$HOME_NET any (msg:"AIB CONTAINMENT lab host reached
non-lab address"; classtype:policy-violation; sid:1000200; rev:1;)`

**Acceptance:** rule fires if traffic ever reaches a non-lab address; verified against
a deliberate test.

**Why now:** currently there's no detection-side tripwire for the exact failure mode
Phase 3 is trying to prevent — this is the belt to G3.1/G3.2's suspenders.
```

**Phase G3.6: Red-team scope gate hardening**
```
Source: docs/IMPLEMENTATION_PLAN.md Phase G3.6. Estimated size: M.

Add C2_URL, C2_DNS_DOMAIN, SIEM_HOST, SIEM_SYSLOG_HOST to TARGET_ENV_VARS in
red-team/runner.py; vet the effective value after default resolution, not just
explicitly-set variables; require ipaddress.ip_network(f"{prefix}.0/24").is_private.
Pass LAB_NET_PREFIX into the red-team service (docker-compose.yml:60-70). Fix the
TARGET_DB/TARGET_DB_HOST and TARGET_MAIL/TARGET_MAIL_HOST name mismatch. Add one
allowlist test per variable in tests/test_target_allowlist.py. Drop verify=False in
https_exfil.py.

**Acceptance:** a campaign with C2_URL=https://example.com is refused; one allowlist
unit test per variable is green; https_exfil.py no longer disables TLS verification.

**Why now:** this is Gap G from the gap analysis — the red-team's own scope gate can
currently be pointed outside the lab network via unvetted env vars, which is the
actual escape-risk primitive, not a detection gap.
```

### Phase 4 — Zeek visibility + safe/observable IR containment

**Phase G4.1: Zeek network_mode host + healthcheck**
```
Source: docs/IMPLEMENTATION_PLAN.md Phase G4.1. Estimated size: S.

Move Zeek to network_mode: host + NET_RAW/NET_ADMIN in docker-compose.yml; reuse
Suricata's br-* auto-detect (:230) to set the interface. Add a healthcheck that fails
if conn.log is empty N seconds after known lab traffic (so "no attacks" != "no
visibility").

**Acceptance:** conn.log is non-empty after a campaign; healthcheck correctly
distinguishes "no traffic" from "sensor not capturing."

**Why now:** Gap E — the sensor tier currently has no real second sensor
independent of Suricata; a Suricata blind spot is currently also a Zeek blind spot.
```

**Phase G4.2: Zeek script tuning**
```
Source: docs/IMPLEMENTATION_PLAN.md Phase G4.2. Estimated size: S.

port_scan.zeek:16 threshold 15->8 plus a second 10-minute-epoch reducer for slow scans.
dns_exfil.zeek:10 add Shannon-entropy + qtype(TXT/NULL) + NXDOMAIN-rate checks.

**Acceptance:** purple-team re-validation shows improved coverage on the corresponding
gap-analysis rows for port-scan and DNS-exfil detections.

**Why now:** current thresholds miss slow scans entirely and dns_exfil.zeek has no
entropy signal, so a red-team DNS tunnel that isn't loud gets through undetected.
```

**Phase G4.3: Symmetric restore step on ransomware_ir.yml + data_exfil_ir.yml**
```
Source: docs/IMPLEMENTATION_PLAN.md Phase G4.3. Estimated size: XS.

Append the restore_host.sh step to ransomware_ir.yml and data_exfil_ir.yml, mirroring
lateral_movement_ir.yml:67-71.

**Acceptance:** both playbooks include a restore_host.sh step as their final action.

**Why now:** restores the OQ-3/ADR-0001 invariant these two playbooks currently
violate — an isolated host with no path back to lab-net if the playbook completes.
```

**Phase G4.4: Idempotent isolate/restore + fix asymmetric `|| true` bug**
```
Source: docs/IMPLEMENTATION_PLAN.md Phase G4.4. Estimated size: S.

Make isolate_host.sh / restore_host.sh idempotent and post-condition-checked (verify
network membership via docker inspect before declaring success). Fix the asymmetric
`|| true`: restore_host.sh:20's connect (which fails "already exists" under `set -e`)
currently aborts the script before the guarded :23 disconnect ever runs.

**Acceptance:** isolate -> restore round-trips cleanly and repeatedly, including when
re-run against an already-restored host.

**Why now:** this is a real bug in the response-action scripts with production blast
radius during an actual IR exercise — a restore can currently silently fail partway.
```

**Phase G4.5: $TARGET validation (CWE-88 fix) + infra-service denylist**
```
Source: docs/IMPLEMENTATION_PLAN.md Phase G4.5. Estimated size: S.

Validate $TARGET with the dashboard's existing _validate_context/_SAFE_HOST_RE charset
guard (blue-team/dashboard/app.py:173-201), insert `--` before positionals (CWE-88),
and deny infrastructure services (elasticsearch/logstash/kibana/blue-team) by
com.docker.compose.service label.

**Acceptance:** an injection attempt via $TARGET is rejected; isolate/restore against
an infra container is refused.

**Why now:** CWE-88 (argument injection) is a real, not hypothetical, finding in
scripts that run with elevated docker permissions.
```

**Phase G4.6: IR operator attribution**
```
Source: docs/IMPLEMENTATION_PLAN.md Phase G4.6. Estimated size: XS.

POST one ir-events-* doc per action with real operator attribution — pass IR_OPERATOR
from the dashboard; ${USER:-unknown} is always unset in containers today.

**Acceptance:** ir-events-* docs carry a real operator identity, not the literal
string "unknown".

**Why now:** current IR event logs are unattributable, which defeats the point of an
audit trail for containment actions.
```

**Phase G4.7: CI playbook-symmetry test**
```
Source: docs/IMPLEMENTATION_PLAN.md Phase G4.7. Estimated size: XS.

New CI test asserting every playbook containing isolate_host.sh also contains
restore_host.sh for the same {var}.

**Acceptance:** test fails today against ransomware_ir.yml/data_exfil_ir.yml (before
G4.3 lands) and passes after.

**Why now:** turns G4.3's fix into a permanent regression guard instead of a one-time
patch — the next new playbook gets checked automatically.
```

### Phase 5 — Regression net + detection-rule logic

**Phase G5.1: pcap-replay regression harness**
```
Source: docs/IMPLEMENTATION_PLAN.md Phase G5.1. Estimated size: M.

Build first, before any other Phase 5 item. One pcap per sid, assert fires/doesn't-fire,
wired into CI.

**Acceptance:** harness runs in CI, green per sid currently expected to fire.

**Why now:** every Tier-3 rule bug in the gap analysis shipped because an unfired rule
looks identical to a covered one in the absence of a regression net — this is the
mechanism that makes G5.2-G5.5's fixes independently verifiable.
```

**Phase G5.2: Gap L sensor config (checksum/HTTP_PORTS/double-decode)**
```
Source: docs/IMPLEMENTATION_PLAN.md Phase G5.2. Estimated size: S.

Conditional on Phase 0's checksum-offload finding. If checksum offload kills
app-layer rules: suricata.yaml checksum-validation: no, broaden HTTP_PORTS to
[80,8000,8080,8888], enable double-decode, monitor stats.log.

**Acceptance:** Suricata app-layer rules fire in the live stack; stats.log shows no
unexpected invalid-checksum drops post-fix.

**Why now:** gated — do not implement until G0.1 confirms the checksum behavior;
implementing against an unconfirmed assumption risks a no-op change.
```

**Phase G5.3: Gap I own-campaign matching rules**
```
Source: docs/IMPLEMENTATION_PLAN.md Phase G5.3. Estimated size: S.

sid:1000010 add pdf|doc|docm|zip|iso extensions. Duplicate http_uri SQLi/XSS rules
against http.request_body (http-body-inline already on, suricata.yaml:161). Add
`content:"/file?name=/"; http_uri;` absolute-path read rule.

**Acceptance:** the red team's own campaign traffic fires the corresponding rule
(verified via G5.1's pcap harness).

**Why now:** Gap I — several rules currently can't even match the lab's own red-team
campaign traffic, let alone a real attacker.
```

**Phase G5.4: Gap J structurally-dead rule rewrites**
```
Source: docs/IMPLEMENTATION_PLAN.md Phase G5.4. Estimated size: S.

Rewrite sid:1000003, 1000050, 1000052 against sticky buffers (dns.query, http.*). Add
a |FE|SMB rule and enable smb: in app-layer.protocols for sid:1000040.

**Acceptance:** all four sids fire against their intended traffic pattern (verified
via G5.1's pcap harness).

**Why now:** Gap J — these rules are structurally incapable of firing as written,
regardless of traffic; they've been silently dead weight.
```

**Phase G5.5: Gap K FP/alert-storm cleanup**
```
Source: docs/IMPLEMENTATION_PLAN.md Phase G5.5. Estimated size: S.

Delete sid:1000030/1000060 (document T1548.003/T1053.003 as host-telemetry detections
instead, not Suricata's job). Add flow:established,to_server; plus a threshold to
sid:1000042. Delete or rekey sid:1000041. Ship a new threshold.config.

**Acceptance:** noisy sids no longer alert-storm; the two structurally-inappropriate
sids are documented as out of Suricata's scope, not silently left broken.

**Why now:** Gap K — these rules currently generate enough false positives/noise to
train operators to ignore alerts, which is worse than no detection.
```

### Phase 6 — Behavioural fallbacks + PKI ledger

**Phase G6.1: Gap D behavioural detection rules**
```
Source: docs/IMPLEMENTATION_PLAN.md Phase G6.1. Estimated size: M.

T1110 auth-failure-rate rule (needs Phase 1's syslog fix). T1557 duplicate-MAC /
T1048.003 entropy / T1041 volume rules, built on Phase 4's Zeek data. Score each
separately; label every rule lab-instrumentation vs real detection.

**Acceptance:** each new rule scores independently and is labeled per category.

**Why now:** Gap D — today the red team effectively controls its own detection score
by choosing which marker string to emit; these are the first rules that detect
behavior instead of a chosen signature.
```

**Phase G6.2: Gap M PKI ledger**
```
Source: docs/IMPLEMENTATION_PLAN.md Phase G6.2. Estimated size: M.

Validate issue_cert.sh CN/SAN args and refuse reserved basenames (ca/intermediate/
root) — also closes the CA-key-destruction primitive. Switch issuance to `openssl ca`
for a real ledger. Ship /zeek-logs/x509.log. Suppress SSL::Invalid_Server_Cert for the
lab PKI host. Emit an issuance event per cert.

**Acceptance:** issue_cert.sh refuses reserved basenames; each issuance produces a
verifiable ledger entry.

**Why now:** Gap M — issue_cert.sh currently has no guard against overwriting the CA's
own key material via a crafted basename argument.
```

### INFRA track (decisions, not phase-gated implementation)

**Phase G-INFRA.1: Decision — host telemetry collector strategy**
```
Source: docs/IMPLEMENTATION_PLAN.md Phase G-INFRA.1. Estimated size: XS.

No host process/file-event telemetry (auditd/Falco/osquery) exists today. This blocks
behavioural T1486/T1053.003 detection and leaves T1548.001/T1098.004 with no possible
ingest path regardless of rule quality. Decide: add a real collector, or extend
emit_syslog_advisory to the 5 currently-silent campaigns (cheap, but keeps the
detection tautological).

**Acceptance:** decision documented; either a collector is scoped as a follow-up item
or the syslog-advisory extension is scheduled, explicitly.

**Why now:** blocks G6.1's T1486/T1053.003 rules — needs a decision before that work
can be scoped.
```

**Phase G-INFRA.2: Decision — container stdout to ELK shipping**
```
Source: docs/IMPLEMENTATION_PLAN.md Phase G-INFRA.2. Estimated size: XS.

No container stdout -> ELK pipeline exists. The scoreboard award log (once G1.4 makes
it actually emit) and the victim mynetworks echo can't be alerted on without this.

**Acceptance:** decision documented on whether/when to add stdout shipping.

**Why now:** low urgency but affects whether G1.4's newly-restored logging is
actually usable by the SIEM, or just visible via `docker logs`.
```

**Phase G-INFRA.3: Document ES audit-log absence as by-design**
```
Source: docs/IMPLEMENTATION_PLAN.md Phase G-INFRA.3. Estimated size: XS.

No ES audit log exists, by design — the loopback-binding fix in G1.1 prevents
unauthorized access but doesn't produce an audit trail of who accessed what (that
would require xpack.security, deliberately not enabled per the locked decision on
teaching-artifact posture). Document that score tampering (T3/T4 in the gap analysis)
is prevented, not detectable.

**Acceptance:** docs/THREAT_MODEL.md or equivalent explicitly states this tradeoff.

**Why now:** prevents a future reader from mistaking "loopback-bound" for "audited" —
they're different guarantees.
```
