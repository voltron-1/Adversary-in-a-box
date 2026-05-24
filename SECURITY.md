# Security Policy

## Scope: meta-tooling, not the deliberately-vulnerable services

Adversary-in-a-Box is a cybersecurity training lab. **Many services in
this repo are intentionally vulnerable** — they're the target of the
red-team campaigns. Vulnerabilities in those services are features, not
bugs. We do not accept reports about:

- SQL injection / XSS / path traversal in `target-env/victim-web/`
- Weak credentials in `target-env/victim-db/`
- Open-relay configuration in `target-env/victim-mail/`
- Permissive TLS settings in the **non-PKI** services
- Anything documented as "intentionally vulnerable" or "LAB SIMULATION"

We **do** accept security reports about the **meta-tooling** that
operates the lab. Examples of in-scope reports:

- Container-escape vectors that affect the **host running the lab**
  (e.g. a way to break out of `blue-team`'s docker.sock context beyond
  the documented intent — see [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)).
- Bugs in `scripts/safety/egress_test.sh` that allow the lab to start
  with the air-gap preflight bypassed without an explicit
  `AIB_SKIP_PREFLIGHT=1`.
- Path-traversal or auth-bypass in `forensics/scoreboard/app.py` or
  `blue-team/dashboard/app.py` (those are the *blue-team* tooling, not
  the vulnerable targets).
- A way for one student's compose stack to interfere with another's
  per-student-isolated stack on the same host.
- Supply-chain vectors in pinned dependencies (e.g. typosquats,
  unmaintained packages, broken hashes) — see Phase B Exercise 5.3
  for the lab's own worked example.

---

## Reporting

**Please do not file public GitHub issues for security reports.** Use
one of:

- **GitHub Security Advisory** — preferred. Open at
  https://github.com/voltron-1/Adversary-in-a-box/security/advisories/new
  (this stays private until coordinated disclosure).
- **Email** — for sensitive cases, contact the maintainer (Git author
  on `main` for the addresses).

Include:

- The vector + a minimal reproducer (compose file + commands).
- The component(s) affected (file paths, line numbers if applicable).
- Your assessment of severity (informational / low / medium / high /
  critical) — use CVSS v3.1 if you have one.

---

## Coordinated disclosure timeline

- **Acknowledgement:** within 7 days of report.
- **Triage decision** (in-scope / out-of-scope, severity):
  within 14 days.
- **Fix or accepted-risk decision:** within 30 days for high/critical,
  90 days for medium, 180 days for low.
- **Public disclosure:** coordinated with the reporter after the fix
  is shipped, or at 90 days post-report if a fix isn't available
  (whichever comes first).

For trivial fixes (typos in docs, deprecated function calls) feel
free to open a regular PR with the fix inline — the
"don't file public issues" rule is about *unmitigated* security
weaknesses, not benign hygiene.

---

## Hardening guidance (for operators)

The lab is designed to run on a **disposable VM** because it is
intentionally vulnerable + the `blue-team` container is granted
`/var/run/docker.sock`. Operating it on a laptop you also use for
real work is explicitly not supported.

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the threat
model + control inventory. The most important controls:

1. `lab-net` declared `internal: true` — no external egress.
2. `scripts/safety/egress_test.sh --strict` refuses to start if any
   production domain in `SAFE_MODE_DOMAINS` resolves from the host.
3. `blue-team` is gated behind `profiles: ["ir"]` so the docker-socket
   exposure is opt-in (default-on via `.env.example` for usability,
   but `COMPOSE_PROFILES= docker compose up -d` disables it).
4. Per-student isolation via `COMPOSE_PROJECT_NAME` + `LAB_NET_PREFIX`
   stops one student's stack from interfering with another's on a
   shared host.

If any of those controls fail, that's a security report we want.
