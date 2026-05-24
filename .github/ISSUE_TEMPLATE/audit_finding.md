---
name: Audit finding
about: Something you noticed while reviewing the lab (not a runtime bug)
title: "audit: <one-line finding>"
labels: audit-finding
---

> Use this for the kind of finding the two prior audit rounds produced
> -- code smell, doc drift, missing test coverage, brittle config,
> dependency-pin issues you spotted reading the code, etc. For a
> reproducible runtime failure, use the bug template instead.

## Finding

<!-- One sentence + the file:line where you noticed it. -->

## Why it matters

<!-- What breaks (or could break) if this isn't fixed? -->

## Suggested fix

<!-- Optional but appreciated. -->

## Where to track it

- [ ] Already covered by a Phase item in
      `docs/IMPLEMENTATION_PLAN.md` (cite the phase code).
- [ ] New -- needs to be added to the plan.
- [ ] Worth a fresh ADR before the fix lands.
