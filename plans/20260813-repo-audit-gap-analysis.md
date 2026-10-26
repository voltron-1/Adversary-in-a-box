# Repo Audit + Gap Analysis — 2026-08-13

## Scope
Full-repo security + code-quality audit, followed by a red/blue coverage gap
analysis (purple-team). Fix phase is explicitly OUT of scope for this pass —
findings only, gated before any remediation work starts.

## Module groups (security-auditor, all 7, parallel)
1. blue-team — dashboard, detection (zeek/suricata/sigma), response actions
2. red-team — campaigns, utils
3. pki-lab — CA setup, cert issuance, TLS hardening
4. target-env — victim-db, victim-mail, victim-web (intentionally vulnerable;
   audit focuses on containment/isolation, not "fixing" the vulns)
5. siem — elasticsearch, kibana, logstash
6. scripts + CI — lab lifecycle, safety (egress_test.sh), setup, .github/workflows
7. forensics/scoreboard — Flask app (has prior auth-bypass fix history)

## code-reviewer (logic-heavy modules only, parallel, alongside security-auditor)
- red-team (campaigns/utils)
- blue-team/response (isolate/restore/block action scripts — high blast radius if buggy)
- pki-lab (cert/CA scripts)
- forensics/scoreboard (Flask app logic)
- scripts/safety + scripts/setup (lifecycle/safety-critical)

## Phases
1. **Audit** (parallel): 7x security-auditor + 5x code-reviewer, one per scope
   above. Each writes full findings to `./findings/20260813-<scope>-<lens>.md`,
   returns a 3-5 line summary only.
2. **Gap analysis** (sequential, depends on phase 1): purple-team ingests all
   security-auditor findings, maps to existing detections (blue-team/detection,
   siem), returns coverage truth table + prioritized remediation backlog.
   Written to `./findings/20260813-gap-analysis.md`.
3. **Present**: synthesize phase 1 + 2 into a findings summary for the user.
   STOP here — do not start remediation without explicit go-ahead.

## Gating
Per Multi-Phase Execution Gating: stop after phase 3, wait for go-ahead before
any fix/lint/commit work.
