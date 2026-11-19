---
name: Redteam program
description: 'Use when running or scheduling the recurring red-team and stress-test program for an AI-agent ecosystem or an authorized customer, aligned to enterprise compliance frameworks.'
---
# Recurring red-team & stress-test program (defensive, test-plan level)

A framework for running a recurring, evidence-producing security test program. It supports audit readiness; it is not a certification. Compliance (ISO 27001, SOC 2, NIS2, DORA) needs an independent auditor or the competent authority.

## Guardrails
- Authorized scope only. Before any test, record a signed Rules of Engagement (RoE): owner, scope (assets, environments), out-of-scope items, test windows, allowed methods, stop conditions, emergency contact, data handling, and approver.
- Staging or dedicated test tenants first. Production tests only for passive checks (TLS, headers, config review) or with explicit written approval and a rollback plan.
- Describe what to verify and the pass criteria. Never write exploit payloads, jailbreak strings, or attack procedures.
- Never invent findings, scores, CVSS, evidence or certifications. Unverified items are marked "self-reported".
- Any externally visible action (tickets, emails, posts, regulator notices) needs explicit human approval.

## Inputs
Scope and asset list, data flows, agent/tool inventory with permissions, connector list, environments, owners, prior findings, applicable frameworks (sector, NIS2 entity status, finance → DORA, AI system role → EU AI Act).

## Steps
1. **Scope & RoE**: fill the RoE template; get it approved; log approver and date in the evidence register.
2. **Map controls**: for each test category, record the framework refs (ISO 27001:2022 Annex A, SOC 2 TSC, NIS2 Art. 21(2), NIST CSF 2.0, OWASP LLM Top 10 2025, OWASP Agentic threats, MITRE ATLAS, NIST AI RMF, DORA where relevant).
3. **Schedule by cadence**:
   - Weekly: external posture drift (TLS, cert expiry, headers, PQ hybrid KEX), secrets hygiene, dependency alerts.
   - Monthly: LLM/agent test suite (prompt injection, tool misuse, connector exfiltration, approval-gate bypass, memory poisoning) in staging; rate-limit/load smoke test.
   - Quarterly: access review, backup restore test, full load/stress test, IR tabletop with regulatory clock drill (e.g. NIS2 24 h / 72 h / 1 month).
   - Annually: full-scope exercise, third-party/independent assessment, program review.
4. **Run each test** to its written objective, method and pass criteria. Capture evidence at run time (timestamped logs, screenshots, configs, signed attestations), never reconstructed later.
5. **Rate findings** with the severity table (Critical/High/Medium/Low) and assign SLA and owner. Critical: contain within 24 h and assess whether it is a reportable incident.
6. **Record** every run in the evidence register: ID, date, control refs, scope, method, result (pass/fail/partial), evidence location and hash, finding IDs, owner, approver, retention date.
7. **Retest** fixes before closing; closure needs evidence of the retest.
8. **Report**: monthly one-page summary (pass rate, open findings by severity, SLA breaches, drift); quarterly management review; annual program review with lessons learned.
9. **Improve**: add a regression test for every confirmed finding; feed outcomes to the learning loop if one exists.

## Severity & SLA (default; adjust to the organization's risk appetite)
| Severity | Example | Fix SLA |
|---|---|---|
| Critical | Approval gate bypass, secret exposed, data exfiltration path confirmed | Contain 24 h, fix 7 days |
| High | Invalid public TLS, unscoped tool permission, failed restore | 30 days |
| Medium | Missing security headers, stale access, weak rate limits | 90 days |
| Low | Hygiene, documentation gaps | Next cycle |

## Outputs
RoE, test plan, evidence register entries, findings backlog with SLAs, monthly summary, tabletop after-action report, and a disclaimer: "framework and evidence pack, not a certification".
