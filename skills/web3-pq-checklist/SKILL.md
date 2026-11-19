---
name: Web3 PQ checklist
description: >-
  Use when assessing smart-contract, wallet, or custody key management and
  post-quantum migration readiness for an authorized project, advisory only.
---
# Smart-contract & wallet post-quantum / key-management checklist

Advisory checklist for a project or treasury the requester controls or is authorized to review. Reads public on-chain data and documents only; no transactions, no key handling, no exploit research. Not an audit; recommend a professional smart-contract audit where gaps exist.

## 1. Scope
Chains, contracts (addresses or repos), wallets/treasuries, custody provider, signer set, value at risk band (owner-stated), regulatory context (e.g. MiCA, DORA if financial entity).

## 2. Key custody
- Custody model: self-custody HSM, MPC, multisig, exchange/qualified custodian. Documented.
- Keys generated and stored in hardware (HSM / hardware wallet / secure enclave); no seed phrases in cloud docs, chat or code.
- Backup and recovery tested; geographic split; dead-man / inheritance procedure.
- Signer onboarding/offboarding (joiner-mover-leaver) and device hygiene.

## 3. Multisig & admin keys
- Threshold appropriate (e.g. not 1-of-N); signers independent (different people, devices, locations).
- Upgradeable contracts: who holds proxy-admin / owner roles; timelock on upgrades and parameter changes; emergency pause scoped and itself multisig.
- Role inventory (owner, minter, pauser, oracle updater) with holders listed; renounced where not needed.
- Monitoring/alerts on admin actions, large transfers and role changes.

## 4. Code assurance
- Independent audit(s): firm, date, commit hash audited vs deployed bytecode (verified source). Unresolved findings tracked.
- Test coverage, static analysis in CI, bug bounty, incident/pause runbook.
- Oracle and bridge dependencies listed with their own trust assumptions.

## 5. Post-quantum exposure
- Signature schemes in use: ECDSA secp256k1, EdDSA Ed25519, BLS, Schnorr. All are breakable by a cryptographically relevant quantum computer (Shor); hashes (Keccak/SHA-256) are only weakened (Grover).
- **Public-key exposure**: addresses that have signed (public key revealed on chain) or reused addresses carry more exposure than never-spent hash-locked addresses; prefer fresh addresses and minimize long-lived exposed keys holding large value.
- **Harvest-now-decrypt-later**: off-chain encrypted data (backups, key shares in transit, KYC data, API traffic) captured today could be decrypted later; use hybrid PQ TLS (X25519MLKEM768) and PQ-ready encryption for long-shelf-life secrets.
- Standards to reference: NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA); NIST IR 8547 transition timeline (quantum-vulnerable algorithms deprecated 2030, disallowed 2035); hash-based signatures as a candidate path for long-lived keys.
- Migration readiness: account abstraction / smart-contract wallets that allow swapping the signature verifier; upgrade path documented; watch the chain's own PQ roadmap (governance proposals) rather than assuming dates.

## 6. Scoring & output
Each item: met / partial / missing / n/a, with evidence-seen or self-reported. Rating: **Ready** (no missing in §2–3, audit current, PQ plan documented), **Partial**, **At risk** (single-key admin, no audit, seed phrases in software, or no recovery test). Deliver findings with fix, priority P0/P1/P2, and a PQ migration roadmap (inventory → hybrid where available → crypto-agile wallets → migrate high-value long-lived keys first). JSON per `finding.schema.json`.

## Rules
Advisory only. Never request, view or store private keys or seed phrases. No exploit, MEV or drain techniques. Never invent audit status, TVL or dates; cite sources for any public on-chain fact.
