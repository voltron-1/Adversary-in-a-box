# Phase G-INFRA.2 — Container Stdout to ELK Shipping Decision

**Date:** 2026-08-30
**Scope:** [#198](https://github.com/voltron-1/Adversary-in-a-box/issues/198) (G-INFRA.2), per `docs/IMPLEMENTATION_PLAN.md`:

> No container stdout -> ELK pipeline exists. The scoreboard award log (once
> G1.4 makes it actually emit) and the victim mynetworks echo can't be
> alerted on without this.

## Where things actually stand today

Confirmed via `docker-compose.yml`: no service defines a `logging:` block, so
every container uses Docker's default `json-file` driver — stdout/stderr
lands in `/var/lib/docker/containers/<id>/<id>-json.log` on the Docker host
and nowhere else. `docker logs <service>` reads it; nothing ships it to
Elasticsearch.

What's actually waiting on this, concretely:

- `forensics/scoreboard/app.py`'s `/api/award` handler (G1.4, #172, already
  merged) logs `"award: %s %+d to %s from %s (detail=%r)"` via Python's
  `logging` module on every instructor score adjustment — real audit-trail
  content, currently visible only via `docker logs scoreboard`.
- `target-env/victim-mail/entrypoint.sh` echoes the Postfix `mynetworks`
  value it computed at boot — a one-line config-confirmation message, not an
  ongoing signal. Low value even if shipped.

So there's one genuinely worthwhile source (the award log) and one that
isn't (a boot-time echo nobody would query for).

## Options considered

| | Docker `syslog` logging driver | Filebeat sidecar (tail json-file) | Status quo (`docker logs` only) |
|---|---|---|---|
| New infrastructure | None — `siem/logstash/pipelines/syslog.conf` already listens on UDP :5514 | New container, new Logstash pipeline (or reconfigure syslog.conf's grok for Filebeat's envelope) | None |
| Access needed | None (log driver is a compose-level setting) | Bind-mount `/var/lib/docker/containers` — host-path-dependent, and typically needs the Docker socket or root, i.e. more privilege than this lab grants anything else | None |
| Per-service granularity | Yes — `logging:` is set per service in compose | Coarser — usually one sidecar globbing all containers' log dirs unless carefully scoped | N/A |
| Noise risk | Whichever services opt in only | Every container by default (ES/Kibana/Logstash's own high-volume startup/access logs would flood `syslog-*` unless explicitly excluded) | None |
| Reuses existing lab convention | Yes — same pattern as G-INFRA.1's `auditd` → `audisp-syslog` → this same pipeline | No | N/A |

**Recommendation: Docker's `syslog` logging driver, opted in per-service,
reusing the existing syslog.conf pipeline** — not a blanket default for
every container. Concretely: add a `logging: driver: syslog` block (with
`syslog-address: "udp://<logstash-host>:5514"` and a `tag` log-opt so
`syslog.conf`'s existing grok `%{DATA:program}` captures something
meaningful, e.g. `scoreboard`) to the `scoreboard` service only.
`victim-mail`'s echo isn't worth wiring up — it's a one-shot boot message,
not a signal an operator would ever query for or alert on.

A Filebeat sidecar was rejected: it needs host-path/Docker-socket access
this lab doesn't grant anything else (every other privileged capability —
`isolate_host.sh`'s Docker socket use, `NET_ADMIN` for containment — is
narrowly scoped and reviewed; a log-shipping sidecar reading every
container's logs would be a broader, less-reviewable privilege grant for a
P4 nice-to-have), and blanket-tailing every container's `json-file` log
would flood `syslog-*` with Elasticsearch/Kibana/Logstash's own operational
noise unless carefully filtered — more moving parts than the syslog-driver
option for less benefit.

## Disposition

Scoped as a follow-up rather than implemented in this decision doc (XS
acceptance bar is a documented decision, matching G-INFRA.1's precedent):
[#238](https://github.com/voltron-1/Adversary-in-a-box/issues/238) ("Ship
scoreboard award-log stdout to syslog-* via Docker's syslog driver").

Closes #198.
