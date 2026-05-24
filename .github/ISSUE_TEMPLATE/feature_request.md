---
name: Feature request
about: Suggest a new campaign / detection rule / playbook / lab capability
title: "feat: <one-line summary>"
labels: enhancement
---

## What

<!-- One sentence: the capability you'd like to see. -->

## Why

<!-- Who benefits and how. If it maps to a Security+ SY0-701 objective
or a specific MITRE ATT&CK technique, name it. -->

## Where it fits in the plan

<!-- Check the closest phase in docs/IMPLEMENTATION_PLAN.md. If it's
new (not already listed), explain why it's a fit for the lab's
current scope. -->

- Closest plan phase: `Phase X.Y` (or "new")
- ADR needed first? (yes / no)

## Sketch

<!-- Rough outline of files this would touch. Doesn't have to be a
full design -- just enough to scope the work. -->

## Definition of done

- [ ] Code lands under the appropriate `red-team/` or `blue-team/`
      subtree (or new docs only).
- [ ] Paired Sigma rule + Suricata rule (if it's a new campaign).
- [ ] Unit test added (template in CONTRIBUTING.md).
- [ ] Linked from docs/IMPLEMENTATION_PLAN.md if it's a new phase
      item.
- [ ] CI green.
