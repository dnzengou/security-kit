---
name: Security posture
description: >-
  Use when running an offline TLS/header/post-quantum posture check, or a claims
  and agent-manifest integrity check, on an authorized domain.
---
# Security posture (offline-first)

Use for a quick posture check on a domain the requester owns or is authorized to assess. Steps A1-A5 and B6 are automated by `scripts/posture_check.py` (stdlib Python + optional OpenSSL 3.5+); its JSON output follows `schemas/finding.schema.json`.

## A. Transport and headers
1. Resolve apex and `www` (A/AAAA). Flag stray or extra apex records pointing outside the expected hosting provider.
2. TLS verify both names. Read cert subject, SAN, issuer, expiry (`openssl s_client` + `openssl x509 -ext subjectAltName`). Flag hostname mismatch, expired, or <21 days to expiry.
3. Post-quantum check: `openssl s_client -connect host:443 -groups X25519MLKEM768` (OpenSSL 3.5+). Report whether hybrid PQ key exchange is negotiated.
4. HTTP apex without following redirects: expect 301/308 to HTTPS. Flag 200, 302/307 (temporary), or HSTS `max-age=0`. If port 80 is blocked from the box, say it couldn't be checked.
5. HTTPS headers only: HSTS (with includeSubDomains/preload), CSP (flag `unsafe-inline`/`unsafe-eval`, check `frame-ancestors`), X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP/CORP.

## B. Trust and manifest integrity (public pages only)
6. Fetch `/llms.txt`, `/robots.txt`, `/sitemap.xml`, `/.well-known/security.txt`, `/.well-known/agent-card.json`, `/.well-known/mcp.json`, `/openapi.json` if referenced. Flag links that 404, point at a different host, or advertise endpoints that don't exist.
7. Read homepage/pricing/about for unverifiable security claims (certifications, client counts), placeholder contacts or analytics IDs, expired offers, and price or contact conflicts across the owner's own sites. Flag publicly reachable internal docs.

## Report
Verdict first (solid / needs work / critical gaps). Then findings ordered High > Medium > Low with the fix (hosting-platform header config, DNS change, reverse-proxy/CDN snippet). Then what's already good. Label as local advisory; never invent scan IDs or CVSS.

## Rules
Authorized targets only. Public reads and one handshake/header fetch per host only. No hidden-path probing, fuzzing, or payloads.
