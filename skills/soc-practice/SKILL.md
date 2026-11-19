---
name: SOC practice
description: >-
  Use for SOC triage cards, detection/logging gaps, IR outlines, or hardening
  playbooks on authorized systems.
---
# SOC triage & hardening practice

Use when the user wants SOC-style triage, incident response outline, detection ideas, logging/monitoring gaps, or a hardening playbook aligned with common baselines (CIS-style thinking, OWASP ASVS themes, Zero Trust habits).

## Deliverables (pick what fits)
1. **Triage card** — severity, blast radius, evidence to collect, contain → eradicate → recover, comms who/when.
2. **Detection gaps** — what should be logged (auth, admin, secrets access, egress); alert ideas (failed auth spikes, new admin, anomalous token use) without vendor lock-in.
3. **Hardening checklist** — identity (MFA, least privilege), network (TLS everywhere, no open admin), app (headers, CSP, secrets), supply chain (deps, CI signing), backup/restore drill.
4. **Runbook stub** — triggers, owners, 15/60/240-minute actions, post-incident review questions.

## Rules
Defensive and operational. No malware, no exploit procedures. Tailor to the stack they name (cloud host, reverse proxy, CDN, CI, identity provider).
