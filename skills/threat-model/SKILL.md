---
name: Threat model
description: >-
  Use when building a threat model, attack-surface map, or STRIDE-style risk
  backlog for an authorized system.
---
# Threat model (white-hat)

Use when the user wants a threat model, attack-surface map, STRIDE/LINDDUN-style review, or trust-boundary diagram for an app, domain, or feature.

## Steps
1. Confirm scope + assets (data classes, identities, money/ops impact).
2. Draw trust boundaries: users, admins, APIs, third parties, CI/CD, secrets stores.
3. Enumerate entry points (auth, uploads, webhooks, LLM prompts, admin).
4. Apply STRIDE per boundary (Spoofing, Tampering, Repudiation, Info disclosure, DoS, Elevation) — or LINDDUN for privacy when relevant.
5. Rank risks by likelihood × impact; map each to a control (prevent / detect / respond).
6. Deliver: short narrative + prioritized backlog (P0–P2) + detection ideas for SOC.

## Rules
Authorized systems only. Describe attacker *goals* and *control gaps*, not exploit steps or PoCs. Prefer diagrams (mermaid) when they clarify boundaries.
