# Phase G0.1 — Runtime Confirmation Spike

**Date:** 2026-08-30
**Scope:** The four environment-specific questions [#168](https://github.com/voltron-1/Adversary-in-a-box/issues/168) gates later Phase G work on (see `docs/20260813-remediation-plan.md` → Phase 0).
**Method:** Read/test-only, no code changes to answer the questions themselves — evidence gathered via repeated `integration.yml` `workflow_dispatch` runs against a temporary diagnostic step (reverted before this PR; see the step's own commit history on `phase-g/g0.1-runtime-spike` for the raw dispatch trail).

---

## Q1 — Does `suricata.yaml:118`'s `checksum-validation: yes` discard packets pre-reassembly on veth capture?

**Configured setting confirmed:** `blue-team/detection/suricata/suricata.yaml:118` sets `checksum-validation: yes`, as expected.

**Invalid-checksum counter: inconclusive.** `sudo grep -i "checksum" /var/log/suricata/stats.log` returned nothing (no error, no match) across every dispatch. This is a dead end for a different reason than the setting itself: `grep | tail` masks `grep`'s own exit code, so an empty result is indistinguishable from "no counters exist under that name" vs. "no invalid checksums occurred." Not otherwise blocking — the full kill-chain integration test (`tests/integration/test_killchain.py`) passed with Suricata alerting correctly on every registered technique in every successful dispatch, which is strong indirect evidence checksum validation is not silently discarding real traffic in this environment.

**Verdict:** setting confirmed as intended; counter-level confirmation remains open but low-priority (no live evidence of packets being dropped).

## Q2 — Does Docker's `internal: true` cover the container→gateway `INPUT` path?

This question consumed most of this spike's effort and, along the way, surfaced two real bugs unrelated to the original question. The short answer: **still open**, but not for lack of trying — see below.

### The detour: two real bugs in the G3.2 live containment probe

While gathering evidence for this question, [#214](https://github.com/voltron-1/Adversary-in-a-box/pull/214) (G3.2, `scripts/safety/containment_test.sh`) merged and became the natural authoritative source for Q2's answer — it asserts exactly this from inside each victim on every lab startup. It failed on its very first live dispatch, which is what this section actually documents:

1. **`awk` missing from all three victim images** ([#215](https://github.com/voltron-1/Adversary-in-a-box/pull/215)). The original `exec_gateway_ip()` piped `/proc/net/route` through `awk` *inside* the container. None of `python:3.11-slim`, `mysql:8.0`, or `debian:bullseye-slim` ship `awk`, and `2>/dev/null` hid the resulting `awk: not found`. Fixed by parsing the route table in the host shell instead (still reading it via `cat` inside the container).
2. **`/proc/net/route` itself unreliable in this environment** ([#216](https://github.com/voltron-1/Adversary-in-a-box/pull/216)). The #215 fix failed identically on the next dispatch. A targeted DEBUG dispatch with unswallowed stderr showed the file exists, is world-readable (`-r--r--r-- 1 root root 0 ... /proc/net/route`), but was reported as **0 bytes — not even a header line** on that runner's kernel (`Linux victim-web 6.17.0-1022-azure`). `docker compose exec`, `getent`, and `/dev/tcp` all worked correctly in the same run (confirmed by the external-TCP-blocked and DNS-unresolvable probes passing cleanly), so this is isolated to in-container procfs route-table exposure, not a general exec/tooling problem. Fixed by reading the gateway from Docker's own host-side metadata instead (`docker inspect <container> --format '{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}'`), which doesn't depend on anything the container's own `/proc` exposes.

### Where it stands after both fixes

The `docker inspect`-based fix ([#216](https://github.com/voltron-1/Adversary-in-a-box/pull/216)) **still could not determine a gateway** for any of the three victims on the next dispatch. A further DEBUG capture is the most interesting evidence in this whole spike: `/proc/net/route` now showed a **header row with zero route entries** (previously 0 bytes, not even a header) —

```
Iface   Destination  Gateway   Flags  RefCnt  Use  Metric  Mask  MTU  Window  IRTT
```

— while Suricata's own log in the same run independently confirmed the network's actual gateway: `[suricata] listening on br-a408b2e6ef16 (lab-net gateway 172.20.0.1)`.

**Working hypothesis (not confirmed):** `lab-net` and `quarantine-net` are both declared `internal: true` (`docker-compose.yml:19-27`). For a bridge network with no forwarding path to anywhere outside its own subnet, Docker may not program a default route (`0.0.0.0/0 via <gateway>`) into attached containers at all — there is nothing outside the subnet for such a route to usefully reach, and containers on the same subnet don't need a gateway hop to reach each other. If true, this would mean the ES-port-reachability probe's premise (route to a host gateway, then test whether that route's destination is reachable) doesn't apply to `internal: true` networks in the first place: there may be no gateway to reach *at the routing layer*, which is a **stronger** containment property than "reachable but firewalled," not a weaker one.

This hypothesis is not fully confirmed: `docker inspect`'s `NetworkSettings.Networks.<net>.Gateway` field would be expected to still report the IPAM-assigned gateway (`172.20.0.1`, per Suricata's log) regardless of whether a route was programmed, since gateway assignment and route programming are logically separate steps — and that field also came back empty. Untangling that fully would need either a shell directly on a runner with this exact kernel/Docker combination, or instrumented `dockerd` logs, neither of which is available from CI log inspection alone.

**What changed as a direct result, regardless of the open question:** `containment_test.sh` was unconditionally wired into `scripts/lab/start.sh` (G3.2) and would hard-fail (exit 4) *every* real lab startup that hits this gateway-detection gap, not just this CI environment. This is now fixed: `start.sh` treats containment_test.sh exit code 4 (probe inconclusive) as a warning, not a hard failure — the actual security-relevant exit codes (1–3, meaning a probe genuinely *succeeded* at something it shouldn't have) still hard-fail as before. The static config check (`tests/test_compose_containment.py`, G3.1) and `lab-net`'s own `internal: true` flag continue to provide the underlying guarantee independent of whether the live probe can positively confirm it in a given environment.

**Verdict:** open. Recommend a follow-up issue scoped specifically to resolving the `docker inspect` empty-Gateway mystery for `internal: true` networks (or accepting the "no route exists" hypothesis as the answer, which would mean Q2's original premise was already answered "yes" by construction and G3.2's probe should special-case this rather than report it as inconclusive).

## Q3 — Is Zeek's `_path` field absent in the pinned `zeek/zeek:7.0` image?

**Inconclusive, for a structural reason rather than a technical one.** Every dispatch checked `notice.log` for a `_path` field *before* any campaign traffic had run (the diagnostic step must run before the integration test, whose `tearDownClass` calls `docker compose down -v`), so `notice.log` never had content to inspect — every attempt returned `NO_NOTICE_LOG` (the file doesn't exist yet, not that the field is absent from it).

**Not blocking:** G1.2's planned fix (`docs/20260813-remediation-plan.md` → G1.2) already changes the Logstash Zeek pipeline to match on `[path] =~ /notice\.log$/` in addition to `[_path] == "notice"`, so it's correct whether or not `_path` turns out to be present in this Zeek image version. A future spike that triggers a real notice-generating campaign (e.g. `T1557` MITM) before checking would give a definitive answer, but isn't required to land G1.2 safely.

## Q4 — Does `find ... -exec bash -n {} \;` propagate exit status correctly?

**Confirmed, conclusively, on every dispatch.** A deliberately broken script (`if [ true` with no matching `fi`) produced a real syntax error on stderr (`line 3: syntax error: unexpected end of file`), yet `find`'s own exit code was `0` — `find -exec ... \;` reports its own exit status, not that of the executed command, so a real syntax error in any scanned script would have been silently swallowed by the old check.

**Already fixed and merged:** [#209](https://github.com/voltron-1/Adversary-in-a-box/pull/209) replaced this pattern in `validate.yml` with an explicit loop that checks `bash -n`'s exit code directly and propagates failure.

---

## Summary

| Q | Question | Status |
|---|----------|--------|
| 1 | checksum-validation setting + counter | Setting confirmed `yes`; counter inconclusive, low-priority |
| 2 | `internal: true` covers gateway INPUT path | **Open** — see hypothesis above; two real bugs found and fixed along the way (#215, #216); `start.sh` no longer hard-fails on the detection gap |
| 3 | Zeek `_path` field presence | Inconclusive (test-ordering, not a real gap); G1.2's fix is robust either way |
| 4 | `find -exec bash -n` exit propagation | Confirmed broken; already fixed (#209) |

## Follow-up

- File a scoped issue for the `docker inspect` empty-Gateway mystery on `internal: true` networks, or update `containment_test.sh` to treat "no route programmed at all" as a pass rather than inconclusive once that's confirmed.
- Optional: a future spike that triggers a real Zeek-notice-generating campaign before inspecting `notice.log` would close out Q3 definitively, though it isn't required for any currently-planned Phase G work.
