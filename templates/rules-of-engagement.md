# Authorization Letter & Rules of Engagement

**Engagement ID:** {{ENGAGEMENT_ID}}  **Date:** {{DATE}}

## 1. Authorization
I, {{AUTHORIZER_NAME}}, {{AUTHORIZER_ROLE}} of {{CLIENT_LEGAL_NAME}}, confirm that I have authority over the assets listed below and authorize {{ASSESSOR}} to perform the security assessment activities described in this document during the stated window.

## 2. Scope
| Asset | Type | Environment | Notes |
|---|---|---|---|
| {{ASSET}} | domain / app / agent / contract / process | production / staging | |

**Out of scope:** {{OUT_OF_SCOPE}} (third-party platforms are out of scope unless their owner also authorizes in writing).

## 3. Window
From {{START}} to {{END}} ({{TIMEZONE}}).

## 4. Allowed methods
- [ ] Passive public reads (DNS, public web pages, well-known manifests)
- [ ] One TLS handshake and header fetch per host
- [ ] Configuration and document review
- [ ] Interviews / questionnaire
- [ ] Execution of written test plans in staging by the client's team
- [ ] Tabletop exercise
- [ ] Load/stress test in staging (limits: {{LIMITS}})

**Prohibited:** exploitation, credential attacks, denial of service against production, social engineering of staff, access to personal data beyond what is strictly needed, any action on third-party systems.

## 5. Stop conditions
Unexpected access to sensitive data, service degradation, signs of a live incident, or request by the client. On stop: halt, notify the emergency contact within {{MINUTES}} minutes, record in the evidence register.

## 6. Contacts
Client lead: {{NAME, PHONE, EMAIL}}  Emergency: {{24x7 CONTACT}}  Assessor lead: {{NAME, CONTACT}}

## 7. Data handling
Evidence stored at {{LOCATION}}, encrypted, access limited to {{ROLES}}, retained until {{DATE}}, then deleted. No secrets, keys or seed phrases are to be shared with the assessor.

## 8. Deliverables & limits
{{DELIVERABLES}}. Results are heuristic advisory findings, not an audit, certification or legal opinion.

Signed (client): ____________________  Date: ________
Signed (assessor): __________________  Date: ________
