---
name: Maturity assessment
description: >-
  Use when running a scored security & crypto-agility (post-quantum) maturity
  assessment for an authorized organization, offline, as a client deliverable.
---
# Security & Crypto-Agility Maturity Assessment (offline)

Scored assessment for an organization that has authorized it. Produces a client-ready report plus JSON scores. Heuristic self-assessment, **not an audit or certification**; say so in the report.

## 1. Scope
Confirm org name, authorization, in-scope systems/domains, sector (NIS2 essential/important?), whether AI agents/LLMs are in use (enables D9), and whether evidence (screenshots, configs, policies) will be shared or answers are self-reported.

## 2. Domains and weights
| Domain | Weight |
|---|---|
| D1 Governance & people | 12% |
| D2 Asset & crypto inventory | 12% |
| D3 Identity & access | 14% |
| D4 Crypto-agility & post-quantum readiness | 12% |
| D5 Secure build, web & supply chain | 12% |
| D6 Detection & logging | 10% |
| D7 Incident response & NIS2 reporting | 10% |
| D8 Backup & continuity | 10% |
| D9 AI & agent security (only if applicable) | 8% |
If D9 is out of scope, redistribute its weight proportionally.

## 3. Questions (about 5-7 per domain)
- D1: named security owner, policy set, risk register, awareness training, management sign-off (NIS2 Art. 20/21).
- D2: hardware/software/SaaS inventory, data classification, inventory of where crypto is used (TLS, VPN, signing, at-rest, keys/certs, wallets), cert lifecycle and expiry tracking.
- D3: MFA on email/admin/cloud, least privilege, joiner-mover-leaver, privileged access, secrets management.
- D4: TLS 1.2+/1.3 everywhere, hybrid PQ key exchange (X25519MLKEM768) where supported, NIST FIPS 203/204/205 awareness, ability to swap algorithms/keys quickly, vendor PQ roadmap, harvest-now-decrypt-later exposure.
- D5: security headers/CSP, dependency scanning, CI secrets hygiene, code review, signed releases, third-party risk.
- D6: centralized logs for auth/admin/secrets/egress, retention, alerting, someone actually watching.
- D7: IR plan, roles, tested in last 12 months, NIS2 reporting clock (24h early warning, 72h notification, 1-month final report), contact lists.
- D8: 3-2-1 backups, immutable/offline copy, restore tested, RTO/RPO defined.
- D9: inventory of agents/LLM endpoints, prompt-injection controls, tool permissions, secrets kept out of prompts, output handling, OWASP LLM Top 10 coverage.

## 4. Scoring
- Each question 0-5 (0 none, 1 ad hoc, 2 partial, 3 defined, 4 managed/measured, 5 optimized/tested). Mark each answer **evidence-seen** or **self-reported**.
- Domain score = mean x 20 (0-100). Overall = weighted sum.
- Report two numbers: **Claimed** (all answers) and **Verified** (self-reported answers capped at 3).
- Bands: Exposed <40, Developing 40-59, Managed 60-79, Resilient 80+.
- **Critical gates** cap the overall band at Developing: no MFA on admin/email, backups never restore-tested, no IR plan, public TLS invalid or expired, no asset inventory.
- Separate **Quantum readiness** score from D2+D4, and place the org on a decision matrix of data sensitivity (low/med/high) x data shelf life (<3y, 3-10y, >10y). High sensitivity + long shelf life = urgent PQ migration.

## 5. Findings and plan
For every question scored <=2: finding, why it matters, fix, effort (S/M/L), priority P0 (<=30 days), P1 (<=90 days), P2 (<=12 months). Use a 5-Whys line for the top 3 root causes.

## 6. Report shape
1. One-page executive summary: overall band, Claimed vs Verified, Quantum readiness, top 5 risks, 30/60/90-day plan.
2. D1-D9 scorecard (table, optional radar chart).
3. Findings and fix list (P0/P1/P2).
4. Quantum-readiness annex: crypto inventory, decision-matrix placement, migration steps.
5. NIS2 Art. 21(2)(a)-(j) coverage map (only if EU and in scope).
6. Method and limits: heuristic, self-reported caps, not a certification.
7. Appendix: JSON `{org, date, domains:{D1..D9}, overall_claimed, overall_verified, quantum_readiness, band, gates_triggered}`.

Deliver as a document or web page the client can keep. JSON appendix must validate against `schemas/assessment.schema.json`; compute scores with `scripts/score_assessment.py`.

## Rules
- Authorized orgs only. Never invent scores, evidence, certifications or CVSS.
- Optional live inputs: run the security-posture skill (or `scripts/posture_check.py`) on their public domains and feed results into D4/D5 as evidence-seen.
- Defensive framing; no exploit steps.
