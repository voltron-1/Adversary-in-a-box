# Domain 5 — Security Program Management

> **SY0-701 Domain 5** covers security governance, risk management,
> third-party / supply-chain risk, compliance, and security awareness.
> These are mostly policy and process objectives — labs that work for
> Domains 1–4 don't translate cleanly. This doc uses the lab *itself*
> as the worked example: students treat Adversary-in-a-Box like a
> service they're securing, and apply Domain 5 frameworks to it.

---

## Exercise 5.1 — Maintain a Risk Register

**Objective:** Practice the risk-identification → assessment → treatment
loop using the lab's own deviations from production hygiene as the
input.

**Steps:**
1. Open `docs/IMPLEMENTATION_PLAN.md`. The "Out of scope" section and
   the open Phase items are the lab's pending risks made explicit.
2. Build a risk register table with columns: `risk_id`, `description`,
   `likelihood (1-5)`, `impact (1-5)`, `score`, `treatment`,
   `owner`. Seed it with at least 5 entries from the plan, e.g.:
   - **R-01:** blue-team `/var/run/docker.sock` mount grants host root
     (treatment: accept + isolate to disposable VM; ref audit-2 Gap #1).
   - **R-02:** Sigma compile-pipeline default could break silently
     (treatment: mitigate via `tests/test_playbooks.py` glob discovery).
   - **R-03:** Suricata `network_mode: host` works only on Linux
     (treatment: document + reference `docs/setup-guide.md` Docker
     Desktop callout).
3. Identify which risks are **inherent** (always present in a
   pen-test lab) vs **residual** (could be removed but haven't been).
4. Pick one residual risk and write the change request to address it
   (use `docs/ADRs/0001-open-question-resolutions.md` as the template).

**Security+ Connection:** Objective 5.2 — Risk identification, analysis,
treatment, register maintenance.

---

## Exercise 5.2 — Compliance Mapping (CIS Controls v8)

**Objective:** Map the lab's security controls to a recognized
framework so gaps are visible against a published baseline.

**Steps:**
1. Pull the [CIS Controls v8](https://www.cisecurity.org/controls/v8)
   reference (top-18 controls).
2. For each control, note whether the lab:
   - **Implements** it (e.g. CIS 8.5 — centralized log management is
     covered by ELK).
   - **Partially implements** (e.g. CIS 4.1 — secure configuration is
     handled by the per-student isolation but no CI baseline check).
   - **Does not** implement (e.g. CIS 14.1 — security awareness; the
     lab is the awareness training).
3. Score the lab 0–100 on each control. Justify each score with a
   pointer to the lab file that implements it.
4. Produce a one-page "compliance posture" doc for an instructor.

**Security+ Connection:** Objective 5.4 — Compliance frameworks, audit
preparation.

---

## Exercise 5.3 — Supply-Chain Risk (Pinned Dependencies as Case Study)

**Objective:** Walk through a real supply-chain failure mode using the
lab's own dependency manifests.

**Background:** audit-2 Gap #8 discovered that
`pySigma-backend-elasticsearch==1.1.7` was pinned in
`blue-team/requirements.txt` but had never been published to PyPI.
CI install would have failed silently until someone noticed. Phase A1
discovered a secondary problem: `pysigma-backend-elasticsearch 1.1.6`
requires `pyyaml>=6.0.2` but the lab pinned `pyyaml==6.0.1` — also a
CI-install failure. Both are real supply-chain failure modes that hit
production systems.

**Steps:**
1. Open the dependency manifests:
   - `red-team/requirements.txt`
   - `blue-team/requirements.txt`
   - `forensics/scoreboard/requirements.txt`
2. For each pinned version, look up: when was it published, who is the
   maintainer, are there known CVEs? (Use `pip show` plus
   [pypi.org](https://pypi.org) for the metadata.)
3. Identify the highest-risk dependency. Justify the choice using:
   maintenance activity, transitive dependency count, blast radius if
   compromised.
4. Propose a remediation: pinning policy, lockfile, SBOM generation
   (`pip freeze > requirements.lock`), Dependabot (Phase D6 in
   `docs/IMPLEMENTATION_PLAN.md`).

**Security+ Connection:** Objective 5.3 — Third-party / supply-chain
risk, software bill of materials (SBOM).

---

## Exercise 5.4 — Policy: Acceptable Use of an Intentionally Vulnerable Lab

**Objective:** Draft an Acceptable Use Policy (AUP) for students using
the lab, then map each clause to an enforcement mechanism.

**Steps:**
1. Read the LICENSE (educational-use disclaimer, lines 23–35).
2. Draft an AUP with at least these clauses:
   - The lab must only run inside its `internal: true` `lab-net`.
   - `SAFE_MODE_DOMAINS` may not be edited to allow production-network
     resolution.
   - Per-student isolation (`COMPOSE_PROJECT_NAME`) must be unique on
     shared hosts.
   - No real personal data may be placed under `evidence/`.
3. For each clause, name the enforcement mechanism in the lab:
   - `lab-net: internal: true` (network-layer)
   - `scripts/safety/egress_test.sh` (preflight check)
   - `scripts/lab/student-env.sh` (per-student generator)
   - `.gitignore` (prevents accidental commit of artifacts)
4. Identify clauses with **no** enforcement mechanism and propose one
   (or document why "accept the risk + train" is the right call).

**Security+ Connection:** Objective 5.1 — Security governance, policy
development.

---

## Exercise 5.5 — Security Awareness Training Design

**Objective:** Design a 30-minute awareness-training module that uses
the lab's phishing campaign as the active-demo segment.

**Steps:**
1. Plan the agenda (no script needed — outline only):
   - **5 min** — concept: spearphishing and benign-payload simulation
     (`docs/walkthrough_scenarios.md` Scenario 1 is the source material).
   - **10 min** — live demo: instructor runs
     `runner.py --campaign phishing` while learners watch alerts
     populate Kibana.
   - **10 min** — exercise: learners run the matching IR playbook
     (`phishing_ir.yml`) and read the resulting evidence.
   - **5 min** — debrief: lessons learned and red flags to look for
     in real email.
2. Write the learner-facing handout (1 page) covering: what they'll see,
   what they'll do, expected outcomes, and how to know they succeeded.
3. Identify one assessment question (multiple-choice or short-answer)
   for the post-training quiz.

**Security+ Connection:** Objective 5.5 — Security awareness training,
phishing simulations, learner outcomes.

---

## Exercise 5.6 — Third-Party Service Provider Risk (ELK as Vendor)

**Objective:** Practice vendor-risk evaluation using the lab's
Elasticsearch / Kibana dependency as a case study.

**Steps:**
1. Locate the ELK version pins in `docker-compose.yml` (search for
   `elasticsearch:` and `kibana:`).
2. Look up Elastic's licensing model and the SSPL/Elastic License v2
   implications for redistribution.
3. Identify the **vendor risks** the lab inherits:
   - License terms could change (mitigation: lab is internal-only).
   - Versions drop out of support (mitigation: documented pins).
   - Vulnerabilities in the image (mitigation: Dependabot tracks them;
     Phase D6).
4. Write a 1-paragraph vendor-risk acceptance memo justifying the
   continued use of ELK in the lab.

**Security+ Connection:** Objective 5.3 — Vendor and service-provider
risk assessment.

---

## Mapping to Existing Lab Artifacts

| Domain 5 Objective | Lab Artifact |
|---|---|
| 5.1 Governance / policy | `LICENSE`, this doc, `docs/IMPLEMENTATION_PLAN.md` (out-of-scope) |
| 5.2 Risk register | `docs/IMPLEMENTATION_PLAN.md`, `docs/ADRs/`, audit findings in commit history |
| 5.3 Supply chain | `red-team/requirements.txt`, `blue-team/requirements.txt`, `forensics/scoreboard/requirements.txt`, `docker-compose.yml` image pins |
| 5.4 Compliance | this doc Exercise 5.2; `docs/ADRs/0001-open-question-resolutions.md` as a "control narrative" example |
| 5.5 Security awareness | `docs/walkthrough_scenarios.md`, the phishing campaign |

## Note on Lab-Only Limitations

Domain 5 is largely about *organizational* security — policy, procurement,
training programs, audits. A self-contained Docker lab can't simulate an
organization, so these exercises lean heavily on using the lab *as the
artifact under review*. That's an honest scope: the lab teaches the
mechanics of governance using its own scaffolding, but a full Domain 5
preparation also needs reading on the organizational and regulatory side
(NIST SP 800-53, ISO 27001, frameworks the lab itself does not embody).
