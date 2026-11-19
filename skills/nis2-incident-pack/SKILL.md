---
name: NIS2 incident pack
description: >-
  Use when preparing NIS2 Art. 21 minimum measures, Art. 23 incident reporting
  templates and drills, or a minimum-viable SOC for an SME.
---
# NIS2 incident-reporting & minimum-SOC pack

For an EU (or EU-serving) organization that is, or supplies, an essential/important entity under Directive (EU) 2022/2555. Advisory; national transposition and the competent authority/CSIRT rules take precedence; tell the user to check them. Implementing Regulation (EU) 2024/2690 sets more specific requirements for digital-infrastructure and ICT service providers.

## 1. Applicability
Sector (Annex I/II), size (medium+ by default, some regardless of size), member state(s), competent authority and CSIRT, essential vs important. Management body accountability (Art. 20) and training.

## 2. Art. 21(2) minimum measures (map status: met / partial / missing + evidence)
(a) risk analysis & IS policies; (b) incident handling; (c) business continuity, backup, DR, crisis mgmt; (d) supply-chain security; (e) security in acquisition, development, maintenance, vulnerability handling/disclosure; (f) effectiveness assessment; (g) cyber hygiene & training; (h) cryptography & encryption policy; (i) HR security, access control, asset management; (j) MFA / continuous authentication, secured comms, emergency comms.

## 3. Art. 23 reporting clock (significant incidents)
| Stage | Deadline from awareness | Content |
|---|---|---|
| Early warning | 24 h | suspected unlawful/malicious? cross-border impact? |
| Incident notification | 72 h (24 h for trust service providers) | update, initial assessment: severity, impact, IoCs where available |
| Intermediate report | on CSIRT/authority request | status updates |
| Final report | 1 month after notification | detailed description, severity & impact, threat type/root cause, mitigations applied and ongoing, cross-border impact |
| Progress report | if still ongoing at 1 month; final within 1 month of handling | |
"Significant" = severe operational disruption or financial loss, or considerable material/non-material damage to others. Also inform service recipients where appropriate. Templates in `templates/nis2/`.

## 4. Minimum-viable SOC (SME)
- Log sources: identity provider/SSO, email, cloud admin, endpoints (EDR), firewall/VPN, critical SaaS, CI/CD, backups.
- Central log store with ≥12 months retention (or as required) and time sync.
- Starter detections: impossible travel / MFA fatigue, new admin or role grant, mass download/deletion, mailbox forwarding rule, disabled logging or EDR, new OAuth app consent, backup deletion, unusual egress volume.
- Coverage: named on-call (or MDR provider) with escalation matrix; 24h-clock decision owner.
- Weekly review, monthly metrics (time to detect/triage), quarterly detection tuning.

## 5. Tabletop drill outline (90 min, twice a year)
1. Brief, roles (incident lead, comms, legal/DPO, management, scribe) — 10 min.
2. Inject 1: detection signal; decide severity & "significant?" — 15 min.
3. Inject 2: scope grows / third party involved; decide 24 h early warning — 20 min.
4. Inject 3: data impact; GDPR 72 h breach notice interplay; customer comms — 20 min.
5. Recovery & 72 h notification draft — 15 min.
6. Hot debrief: what worked, gaps, owners, dates — 10 min.
Pass criteria: early-warning draft ready inside simulated 24 h; decision owner named; contact list current; evidence logged.

## 6. Evidence register
One row per artefact: id, Art. 21 measure, control, artefact (policy, screenshot, log export, drill report), owner, date, location, review due. Schema `evidence.schema.json`.

## Deliverable
Applicability note, Art. 21 coverage map with gaps prioritized P0/P1/P2, filled reporting templates, drill script, SOC starter list, evidence register.

## Rules
Advisory, not legal advice or certification. Never invent authority contact details or deadlines beyond the Directive; flag national variations to verify.
