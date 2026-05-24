---
name: Bug report
about: Something in the lab tooling is broken (not the intentionally-vulnerable services)
title: "bug: <one-line summary>"
labels: bug
---

> **Scope reminder:** SQL injection in `victim-web`, weak creds in
> `victim-db`, open relay in `victim-mail`, weak ciphers outside the
> PKI lab -- all features, not bugs (see `SECURITY.md`). If your
> finding might be a **security vulnerability in the meta-tooling**
> (container escape, preflight bypass, etc.), please file a private
> GitHub Security Advisory instead of a public issue.

## What broke

<!-- One or two sentences. -->

## Reproduce

```bash
# Exact commands. Paste from your shell.
```

## Expected vs actual

- **Expected:**
- **Actual:**

## Environment

- OS / Docker version:
- Python version:
- Are you on Docker Desktop (Mac / Windows / WSL2) or native Linux?
- Output of `git log -1 --format='%h %s'` (which commit):

## Logs / output (if useful)

<details>
<summary>compose logs / pytest output / etc.</summary>

```
paste here
```

</details>

## Anything else

<!-- Suspected cause, related issues, your fix-attempt if any. -->
