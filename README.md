# Security Kit — portable, defensive security & crypto-agility capabilities

A vendor-neutral bundle of **skills (runbooks), schemas, templates and stdlib scripts** for advisory security work: web posture with post-quantum checks, scored maturity assessments, AI-agent/LLM reviews, NIS2 incident readiness, Web3 key-management and PQ readiness, threat modelling, SOC practice, and a recurring red-team/stress-test *program* (test plans, not attacks).

It runs the same way in an AI agent platform, behind any LLM, as an MCP or HTTP tool, or as a printed playbook for a human team.

## Principles (non-negotiable)
1. **Authorized targets only.** Every engagement starts with a signed rules of engagement (`templates/rules-of-engagement.md`, `schemas/engagement.schema.json`).
2. **Defensive and passive.** Public reads, one handshake/header fetch per host, document review, interviews, staging test plans, and tabletops. No exploitation, fuzzing, credential attacks, payloads or attack procedures.
3. **Evidence over claims.** Every finding records how we know it: `observed`, `evidence-seen` or `self-reported`. Self-reported answers are capped in Verified scores. Never invent findings, scores, CVSS, certifications or customer data.
4. **Advisory, not certification.** Outputs support audit readiness (ISO/IEC 27001, SOC 2, NIS2, DORA, EU AI Act). They do not replace an accredited auditor, competent authority or legal advice.
5. **Human approval** for anything externally visible: tickets, client emails, regulator notifications.

## Contents
```
skills/        Runbooks (SKILL.md with "Use when..." frontmatter)
  security-posture/      TLS, SAN, expiry, hybrid PQ KEX, redirects, headers, manifests, claims integrity
  maturity-assessment/   D1-D9 scored assessment, Claimed vs Verified, gates, quantum readiness
  agentic-ai-review/     OWASP LLM Top 10 2025, agentic threats, ATLAS, AI RMF, EU AI Act tier; verdict
  redteam-quick/         lightweight alias of agentic-ai-review
  redteam-program/       recurring red-team & stress-test program, cadence, SLAs, evidence
  threat-model/          STRIDE/LINDDUN, trust boundaries, P0-P2 backlog
  soc-practice/          triage cards, detection gaps, hardening, runbooks
  nis2-incident-pack/    Art. 21 coverage, Art. 23 reporting clock, minimum SOC, tabletop
  web3-pq-checklist/     custody, multisig/admin keys, audits, ECDSA/EdDSA quantum exposure, migration
schemas/       JSON Schema 2020-12: finding, assessment, engagement (RoE), evidence register entry
templates/     RoE/authorization letter, report skeleton, risk backlog CSV, evidence register CSV,
               nis2/ early warning 24h, notification 72h, intermediate, final 1-month, tabletop script
scripts/       posture_check.py, score_assessment.py (Python 3.9+, stdlib only; OpenSSL 3.5+ optional for PQ)
adapters/      MCP server and OpenAPI notes, example agent-card.json
examples/      sample answers, engagement, and outputs
```

## Quick start
```bash
# 1. Record authorization (fill and sign the RoE; keep JSON alongside)
cp templates/rules-of-engagement.md my-engagement-roe.md

# 2. Passive posture check of in-scope hosts (exit code 1 if critical/high gaps)
python3 scripts/posture_check.py example.com www.example.com -o posture.json

# 3. Score a maturity assessment from interview/evidence answers
python3 scripts/score_assessment.py examples/answers.sample.json -o assessment.json

# 4. Write the report from templates/report-skeleton.md; log artefacts in templates/evidence-register.csv
```

## Adopting it
| Where | How |
|---|---|
| AI agent platform with skills | Copy `skills/*` into the platform's skill library; frontmatter routes them automatically. |
| Any LLM (chat, API, assistant builder) | Paste the relevant SKILL.md into the system prompt or attach as knowledge; ask for output matching `schemas/`. |
| Tool-calling agents | Wrap scripts as MCP tools or an HTTP API (`adapters/README.md`). Gate network tools on an approved engagement scope. |
| Multi-agent / A2A | Publish an agent card (`adapters/agent-card.json`). |
| Human team | Use skills as runbooks, templates as documents, CSVs in a spreadsheet. |
| CI / scheduler | Run `posture_check.py` weekly on owned domains; diff JSON for drift (cert expiry, headers, PQ). |

## Customizing
- Weights, bands and gates live at the top of `scripts/score_assessment.py` and in `skills/maturity-assessment/SKILL.md`; change both together.
- Framework refs in findings use short IDs (e.g. `NIS2-21(2)(h)`, `ISO27001:2022-A.8.24`, `OWASP-LLM01:2025`); map to your control library.
- Branding: add your name and logo to templates only; skills stay neutral.

## Known limits
- `posture_check.py` reports what *this network* sees. Behind a transparent proxy (resolver returns `198.18.0.0/15`) DNS and plain-HTTP results are not authoritative; the script flags this. Port-80 errors are reported as `not_tested`.
- The PQ test offers only `X25519MLKEM768`; a failed handshake is reported as "no hybrid PQ", which is the expected result for servers without it.
- Scores are heuristics, not audits.

## Versioning & licensing
Version 1.0.0. **License: MIT** — see [LICENSE](LICENSE). Open-core terms (what is and isn't included here) are in [LICENSING.md](LICENSING.md). Framework names (OWASP, NIST, MITRE ATLAS, ISO, NIS2, EU AI Act) are referenced for mapping only; consult the original publications.
