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

No `--pid=host` needed. This is only a primitive-level, socket-filter-type
program load, nowhere near a full Falco kprobe/tracepoint pipeline with a
ring buffer — real Falco packages couldn't be pulled here either (same
registry restriction), so this is not proof Falco itself would deploy
cleanly. But it's a materially different, more favorable signal than
auditd's hard wall: **basic eBPF program loading is scoped to the calling
container's own capabilities, not gated on host PID namespace membership**,
and this kernel does carry `/sys/kernel/btf/vmlinux` (needed for modern
CO-RE eBPF probes, which is what Falco's default driver uses today).

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

Not resolved here — this finding reopens the choice G-INFRA.1 (#197)
made, rather than completing #233 as scoped. Recommend against
implementing #233 as currently written (per-container auditd via
capabilities alone; it cannot work). Two real paths forward, both
needing a decision this doc doesn't make unilaterally given the
`--pid=host` tradeoff above:

1. **Falco (or another eBPF-based collector)**, re-evaluated as the
   primary candidate instead of auditd, given eBPF program loading did
   *not* hit the same init-PID-namespace wall in this environment.
   Genuinely unverified beyond the primitive-load test above (no live
   Falco build was reachable to test end-to-end here).
2. **Host-level auditd** (not per-container) watching the Docker
   storage driver's per-container overlay paths, accepting the
   runtime-coupling fragility named above, closer in shape to what
   G-INFRA.1's own evaluation table already flagged as a downside of
   any host-wide approach.

Neither is implemented in this change. #233 should not proceed on its
current text without this decision being made first.
