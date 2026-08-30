# #233 Portability Spike — auditd Does Not Work Inside a Standard Container

**Date:** 2026-08-30
**Scope:** [#233](https://github.com/voltron-1/Adversary-in-a-box/issues/233), whose own text calls
this out as the first, blocking step: "confirm the audit netlink subsystem is
actually reachable from a container... If it doesn't work portably, that
itself is a decision point." This doc is that decision point.

**Bottom line: it doesn't work, and the reason is more fundamental than
"needs the right capabilities."** #233 (and the [#197](https://github.com/voltron-1/Adversary-in-a-box/issues/197)/G-INFRA.1
decision it followed from) assumed the risk was portability across *host
platforms* (native Linux vs. Docker Desktop Mac/Windows/WSL2). The real
blocker showed up on native Linux itself, empirically, before platform
portability was even in question: **the kernel audit subsystem refuses
`AUDIT_SET`/`AUDIT_ADD_RULE` from any process outside the host's init PID
namespace, regardless of capabilities.** Every `docker run` container gets
its own PID namespace by default, so auditd cannot enable itself inside any
of this lab's victim containers as originally scoped — not "might not
port to Mac," but "doesn't work in a plain `docker run` container at all."

## What was tested and how

This environment turned out to have a real (if nested) Docker daemon
reachable — `dockerd` started successfully and `docker run` worked, which
G0.1's and G-INFRA.1's own spikes didn't have available. Registry access is
policy-restricted (Docker Hub, `docker.elastic.co`, and `ghcr.io` all 403
through this session's egress proxy; `apt-get` against `deb.debian.org`
403s too, for the same reason), which ruled out installing the real
`auditd`/`audispd-plugins` packages or a real Falco/osquery image. What
*was* reachable: `mirror.gcr.io/library/debian:bullseye-slim` — the exact
base image `target-env/victim-mail` uses — pulled cleanly via Google's
public Docker Hub mirror.

So this spike tests the actual kernel primitives auditd depends on
directly, via small statically-linked C programs talking raw
`AF_NETLINK`/`NETLINK_AUDIT` and `bpf()`, run both on the host and inside
`docker run` containers with varying capabilities. Host kernel: `6.18.44`,
`CONFIG_AUDIT=y`, `CONFIG_AUDITSYSCALL=y` confirmed via `/proc/config.gz`.

### Test 1 — `AUDIT_GET` (query kernel audit status)

A minimal socket/bind/sendmsg/recvmsg round-trip on `NETLINK_AUDIT`,
requesting `AUDIT_GET`. Ran on the host, then inside a container with
**no** `--cap-add` at all:

```
socket() OK, fd=3
bind() OK
sendmsg(AUDIT_GET) OK, sent=16 bytes
recvmsg() OK, received=36 bytes
response nlmsg_type=2 nlmsg_len=36 nlmsg_pid=7
OK
```

Succeeded with zero extra capabilities. This is a weaker test than it looks:
Docker's *default* capability set already includes `CAP_AUDIT_WRITE`
(confirmed by decoding `/proc/self/status`'s `CapEff` inside the
container: `0xa80425fb` → bit 29 = `AUDIT_WRITE` is set, `AUDIT_CONTROL`
(30) and `AUDIT_READ` (37) are not). `AUDIT_GET` apparently doesn't require
more than that. This result on its own would have been misleadingly
reassuring — the real test is below.

### Test 2 — `AUDIT_SET` (actually enable auditing — what `auditctl -e 1`/`auditd` startup does)

Same approach, sending `AUDIT_SET` with `mask=AUDIT_STATUS_ENABLED,
enabled=1` — the literal operation auditd performs on startup, which the
kernel gates on `CAP_AUDIT_CONTROL`.

| Container config | Result |
|---|---|
| Default caps (no `--cap-add`) | `NACK, kernel returned errno 1 (Operation not permitted)` |
| `--cap-add=AUDIT_CONTROL --cap-add=AUDIT_WRITE --cap-add=AUDIT_READ` | **`NACK, kernel returned errno 1 (Operation not permitted)`** — same failure, despite holding the exact capability the kernel checks |
| Same capabilities **+ `--pid=host`** | `ACK (success)`, confirmed by an `AUDIT_GET` readback showing `enabled=1` |

The capability alone changed nothing. Adding `--pid=host` — sharing the
*host's* PID namespace, not the container's own — is what made it work.
This matches the kernel's actual `audit_netlink_ok()` check in
`kernel/audit.c`: control operations require **both**
`CAP_AUDIT_CONTROL` **and** `task_active_pid_ns(current) == &init_pid_ns`.
A default `docker run` container fails the second check no matter what
capabilities it holds.

### Test 3 — a lighter-weight comparison: can a container load an eBPF program at all?

Since the natural fallback the original G-INFRA.1 evaluation considered
(and set aside for auditd) was Falco, a cheap sanity check: does the same
init-namespace wall apply to `bpf()`? Loaded the smallest legal eBPF
program (`r0 = 0; exit;`, `BPF_PROG_TYPE_SOCKET_FILTER`) via a raw
`bpf(BPF_PROG_LOAD, ...)` syscall:

| Container config | Result |
|---|---|
| Default caps, default seccomp | `bpf(BPF_PROG_LOAD) failed: Operation not permitted` |
| `--cap-add=SYS_ADMIN --cap-add=BPF --cap-add=PERFMON`, default seccomp, **default (container-scoped) PID namespace** | `bpf(BPF_PROG_LOAD) OK, prog_fd=3` |

No `--pid=host` needed — a materially more favorable signal than auditd's
hard wall: **basic eBPF program loading is scoped to the calling
container's own capabilities, not gated on host PID namespace membership**.

### Test 4 — the real `falco` binary, not just a synthetic probe

Unlike Docker Hub / `docker.elastic.co` / `ghcr.io` (all policy-403'd),
`mirror.gcr.io` turned out to mirror `falcosecurity/falco` and
`falcosecurity/falco-no-driver` cleanly, so this went further than a
synthetic program load: actually ran real Falco 0.39.2 against this real
kernel.

Falco starts, loads its config and the 25 default rules, and attempts to
open the syscall source — with `-o log_level=debug -o
libs_logger.severity=debug` the precise failure is:

```
[libs]: libpman: unable to bump RLIMIT_MEMLOCK to RLIM_INFINITY (errno: 1 | message: Operation not permitted)
Error: unable to configure the libpman state.
```

Both Falco's modern-eBPF driver (`libpman`, ring-buffer/CO-RE based) *and*
its legacy eBPF driver hit the identical wall: a `setrlimit(RLIMIT_MEMLOCK,
RLIM_INFINITY)` call that needs `CAP_SYS_RESOURCE`. Confirmed via
`/proc/1/status`: this session's own outer sandbox process is missing
`CAP_SYS_RESOURCE` from its capability *bounding set* (not just its
effective set), so the nested `dockerd` running inside it structurally
cannot grant that capability to any child container, however it's
`--cap-add`'d — this is the same class of restriction that blocked
`docker pull hello-world` before `mirror.gcr.io` was found reachable, an
artifact of this specific sandbox, not of Docker or Falco.

**This is a materially better outcome than it looks.** Unlike auditd's
`--pid=host` requirement (a security-posture tradeoff with no clean
answer), `CAP_SYS_RESOURCE` is an ordinary Linux capability every real
Docker host — bare metal, a cloud VM, even Docker Desktop's Linux VM — can
grant to one container without touching any other container's isolation.
The failure here is fully diagnosed and is specific to this sandbox's own
restricted capability bounding set, not a property of Falco or of
containerized eBPF in general. `falco -V/--validate <rules_file>` (schema
validation only, no syscall source needed) still runs cleanly in this
sandbox and was used to validate the lab's actual rules
(`blue-team/detection/falco/lab_rules.yaml`) against the real binary in
the implementation that followed this spike.

## What this means for #233 as scoped

\#233's plan — `apt-get install auditd` inside `victim-web` (and later
other victim images), configure watch rules for
T1053.003/T1548.001/T1098.004/T1486, ship via `audisp-syslog` — assumed the
open risk was *whether the container could reach the audit netlink
subsystem on unusual host platforms*. The actual finding: it doesn't reach
it *anywhere* under normal `docker run` isolation, on any platform,
because the kernel gate is PID-namespace membership, not host-specific
netlink plumbing. Granting `--pid=host` to unblock it would mean:

- The victim container could see and signal every process on the Docker
  **host** — a materially larger blast radius than anything else this lab
  grants a container today, including `blue-team`'s `docker.sock` mount
  (scoped through the Docker API, not raw process visibility/control) and
  `NET_ADMIN` for containment. `docs/THREAT_MODEL.md` §4.1 treats
  container-escape-equivalent capabilities on `blue-team` as the lab's
  single highest residual risk *specifically because* of what host access
  they grant — `--pid=host` on a victim container the red team is actively
  attacking is a comparable or worse grant, on a container designed to be
  compromised.
- Audit watch rules operate on the **host's view of the filesystem**, not
  a container-scoped one — `-w /etc/cron.d -p wa` would need the host-side
  overlayfs merged path for that specific container, which is
  runtime-internal and shifts on every container recreation. This isn't
  the clean "watch a path inside the container" story #233 was written
  against.

That's not a small implementation detail to work around inside #233's
existing scope — it's a different technology bet than the one G-INFRA.1
recommended, with a real security-posture tradeoff attached.

## Disposition

This finding reopens the choice G-INFRA.1 (#197) made rather than
completing #233 as scoped. Recommend against implementing #233 as
currently written (per-container auditd via capabilities alone; it
cannot work regardless of platform). Presented the fork — re-scope to
Falco, accept `--pid=host` for auditd, move auditd to the host instead
of per-container, or leave #233 blocked — for a decision, since the
`--pid=host` tradeoff isn't this doc's to resolve unilaterally.

**Decision: re-scope #233 to Falco.** Test 4 above is the deciding
evidence — Falco's actual blocker (`CAP_SYS_RESOURCE`, an ordinary
per-container capability grant) is a fundamentally different, much
smaller ask than auditd's (`--pid=host`, host-wide process visibility on
a container designed to be attacked), and it's specific to this sandbox
rather than to containerized deployment generally. The Falco-based
implementation (compose service, custom rules for
T1053.003/T1548.001/T1098.004/T1486, syslog ingestion, scoring) is a
separate change; see its own PR for what shipped and what remains
unverified end-to-end in this sandbox (full syscall capture, since
`CAP_SYS_RESOURCE` couldn't be exercised here) versus what real-binary
validation (`falco -V`) did confirm.
