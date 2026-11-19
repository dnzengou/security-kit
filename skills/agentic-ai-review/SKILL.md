---
name: Agentic AI review
description: >-
  Use when reviewing the security of an LLM app, chatbot, RAG system, or AI
  agent (tools, connectors, memory) and giving a safe/warn/vulnerable verdict.
---
# Agentic AI & LLM security review (offline, white-hat)

Supersedes `redteam-quick`. Defensive review of an LLM application or AI agent the requester owns or is authorized to assess. Delivers control gaps, a safe test plan and a verdict. Never writes jailbreak strings, injection payloads or exploit code.

## Frameworks
OWASP Top 10 for LLM Applications 2025 (LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM03 Supply Chain, LLM04 Data & Model Poisoning, LLM05 Improper Output Handling, LLM06 Excessive Agency, LLM07 System Prompt Leakage, LLM08 Vector & Embedding Weaknesses, LLM09 Misinformation, LLM10 Unbounded Consumption); OWASP Agentic AI Threats & Mitigations (memory poisoning, tool misuse, privilege compromise, identity spoofing, cascading hallucination, goal manipulation, overwhelming human-in-the-loop, repudiation); MITRE ATLAS (tactic-level mapping only); NIST AI RMF 1.0 + GenAI Profile (Govern/Map/Measure/Manage); EU AI Act risk tier.

## 1. Scope & authorization
Confirm owner, written authorization, environment (staging preferred), model(s)/gateway, user population, and data classes the system touches. No testing on production or third-party endpoints without explicit sign-off.

## 2. Inventory (build a table)
- Models, providers, hosting, gateway, fine-tunes, embeddings/vector stores.
- Every tool/connector/MCP server: actions it can take (read / write / send / pay / delete / execute), credential it uses, scope of that credential.
- Untrusted content ingress: web pages, email, files, tickets, RAG documents, other agents' outputs.
- Memory: what persists, who can write it, how it is reviewed or expired.
- Egress: outbound HTTP, email/chat send, file shares, rendered links/images, code execution.
- Secrets: where keys live; confirm none in system prompts, memory, logs or client code.

## 3. Control review (score each: present / partial / missing, with evidence)
1. **Excessive agency (LLM06)**: least-privilege credentials per tool; irreversible or external actions (send, post, pay, delete, share) behind human approval gates; rate and spend limits.
2. **Prompt-injection exposure (LLM01)**: untrusted content clearly fenced and treated as data; tool calls triggered by fetched content need confirmation; "lethal trifecta" check (private data + untrusted content + exfil channel in one agent) flagged as High.
3. **Memory poisoning**: provenance on memory writes, no auto-save from untrusted content, review/expiry, per-tenant isolation.
4. **Data exfil paths (LLM02/LLM05)**: output encoding, markdown image/link rendering policy, URL allowlists, DLP/redaction on outbound.
5. **System prompt & secrets (LLM07)**: assume prompt is disclosable; no secrets or authz logic in it.
6. **Supply chain (LLM03/LLM04)**: model and dataset provenance, pinned versions, MCP/plugin vetting, signed artifacts.
7. **RAG/vector (LLM08)**: per-user access control enforced at retrieval, not by prompt.
8. **Output handling & misinformation (LLM05/LLM09)**: downstream code/SQL/HTML never executed unsanitized; citations for factual claims.
9. **Unbounded consumption (LLM10)**: auth on endpoint, quotas, timeouts, loop/recursion caps.
10. **Identity & multi-agent**: agent identities distinct, inter-agent messages authenticated and treated as untrusted.
11. **Logging & repudiation**: prompts, tool calls, approvals and outputs logged with actor + timestamp, retained, reviewable, secrets redacted.
12. **Governance**: owner, AI use policy, risk register entry, EU AI Act tier (prohibited / high-risk / limited-transparency / minimal), transparency notice to users.

## 4. Test plan (what to verify, not how to attack)
For each control gap, write a test case: ID, OWASP/ATLAS ref, objective, precondition (staging, seeded canary data), safe method category (e.g. "seed a canary secret in a test document and verify it never appears in outbound requests"), pass criterion, evidence to keep. Prefer canary tokens, synthetic data and established open-source eval harnesses run in the owner's lab. Re-run after each fix and on every model/tool change.

## 5. Verdict
- **vulnerable**: any missing control on an irreversible/external action, an unauthenticated endpoint, secrets reachable by the model, or an open lethal trifecta.
- **warn**: controls partial, or untested.
- **safe**: no High gaps and test plan passed with evidence in the last 90 days.
State the evidence behind the verdict. Self-reported only → cap at **warn**.

## 6. Deliverable
Verdict + one-paragraph rationale; inventory table; control scorecard; findings (High/Medium/Low, framework refs, fix, owner: app / infra / model gateway / governance, P0 ≤30d, P1 ≤90d, P2 ≤12m); test plan table; JSON findings per `finding.schema.json`.

## Rules
Authorized systems only. Never invent findings, scores, CVSS or certifications. No jailbreak/injection payloads, PoC scripts or bypass techniques. Advisory, not an audit.
