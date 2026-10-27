# Nexora threat model and P0 security review (draft)

**Status:** Initial engineering threat model, 2026-10-27. **Not a completed security audit.**
**Scope:** Current Fastify/Node API, PostgreSQL, static web client, user and bot WebSocket gateways, community invites, messages, sessions and developer applications.

## Assets, trust boundaries and attacker capabilities

| Asset / boundary | Threat | Required control / verification |
|---|---|---|
| Browser/client ↔ API | Stolen bearer tokens, injected JS, network interception | HTTPS/WSS-only deployment, strict origin/CSP, secure browser token storage, login CSRF review |
| User password ↔ login | Credential stuffing, enumeration, expensive scrypt DoS | Generic errors, distributed per-account + per-IP quotas, global KDF concurrency ceiling, monitoring |
| API ↔ PostgreSQL | SQL injection, stolen database dump, privilege escalation | Parameterized queries, least-privilege DB account, migration discipline, backups, encryption-key separation |
| Users ↔ guild/channel | Cross-tenant read/write; stale membership subscriptions | Authorization on every write/read/broadcast, atomic membership changes, negative tests |
| User session ↔ Gateway | Logged-out socket continues receiving events | Immediate local socket close, shared invalidation and periodic DB revalidation, race tests |
| Bot token ↔ bot Gateway | Rotated/stolen token receives metadata | Hashed credentials, scoped install permissions, revocation broadcast, recheck on every delivery/replay |
| Invites ↔ memberships | Guessing, reuse, races on max uses | Hash invite codes, transactional redemption, per-IP quotas, concurrent redemption test |
| E2EE keys ↔ untrusted server | Malicious key substitution, weak randomness, nonce reuse, device impersonation | Mature audited E2EE protocol, identity verification/transparency, device authentication, membership epoch rotation |
| Message metadata ↔ bots | Cross-community leakage, inference from timestamps/IDs | Permissioned metadata-only responses, retention, privacy documentation |
| Logs/telemetry | Bearer token/key leakage | Sensitive-header and body redaction, access controls, retention policy |
| Deployment | Spoofed X-Forwarded-For, insecure TLS, credential exposure | Explicit trusted proxy chain, WSS/TLS, secret rotation, isolated DB access and restore drills |

## Current limitations / findings (do not claim these are remediated)

1. **Critical: no verifiable E2EE.** `client-encrypted-v1` is a caller-controlled field. The server stores opaque payloads, but clients do not yet implement audited authenticated encryption, per-device distribution, identity verification, group epoch rekeying or recovery. Do not send sensitive conversation content.
2. **High: in-memory abuse limits.** Registration and login quotas are per-process, not global; distributed deployments can bypass them. Username variation can weaken login protections; no shared KDF concurrency guard.
3. **High: distributed authorization.** Logout and bot-token rotation close local sockets and watchdogs poll PostgreSQL, but cross-instance invalidation is delayed. Membership changes and broadcasts need cross-instance tests and centralized events.
4. **High: browser delivery and origins need review.** A compromised app server or replaced JavaScript can defeat browser E2EE. Define CSP, origin checking for WebSocket upgrades, secure token storage and security headers.
5. **Medium/high: data lifecycle.** No reviewed migration rollback, message/attachment deletion semantics, legal retention policy, restore drill or automated backup verification.
6. **Medium: bot replay semantics.** Message-metadata catch-up is not an immutable event log, does not include edits/deletes, and is not guaranteed exactly once. Persisted cursor alone is insufficient.
7. **Medium: permissions.** Owner/member authorization and bot install grants exist, but require systematic endpoint matrix, TOCTOU tests and audit trails.

## E2EE implementation acceptance criteria (all required)

- Select a vetted protocol/library (e.g. standards-based MLS implementation) and document cryptographic security assumptions and interoperability tests. **Do not invent an ad hoc group protocol.**
- Devices generate private keys locally; use authenticated encryption with proven nonce management and associated data binding guild/channel/message/sender/epoch.
- Establish verifiable device identity and key authenticity, detect key substitution, support safety-number or equivalent out-of-band verification; document web-host compromise limitations.
- Perform authenticated per-device or group key distribution; membership removal triggers new group epochs and blocks removed devices from future messages. Verify offline members and out-of-order delivery.
- Specify key recovery, rotation, lost-device removal, encrypted backups, and forward secrecy/post-compromise security properties.
- Do not allow plaintext bots to silently access private messages; make bot membership and key access explicit and reviewable.
- Run protocol test vectors, independent crypto/security review, downgrade/rollback adversarial tests, and cross-device integration tests before enabling a security claim.

## Distributed security work plan

1. Add Redis (or similarly durable shared service) for rate-limit counters using atomic increment-with-expiry, combined account/IP limits and KDF admission control; configure trusted proxies explicitly and test across 2 API instances.
2. Add a shared session, bot-token and guild-membership revocation event channel. Each instance must close affected sockets promptly and fail closed when identity freshness cannot be verified; add two-instance integration tests.
3. Design cross-instance Gateway event fanout with delivery identifiers, authenticated source, bounds/backpressure, replay rules and graceful restart. Separate user ciphertext event flow from bot metadata.
4. Build an endpoint-by-endpoint matrix of authorization decisions; test guest, non-member, former member, revoked token, bot without grant, cross-guild cursor and concurrent membership changes.

## SQL, recovery and deletion audit checklist

- [ ] Enumerate all tables, foreign keys, indexes, unique constraints and sensitive columns; verify constraints against API behavior.
- [ ] Create versioned, reversible schema migrations with CI migration-from-empty and upgrade tests.
- [ ] Review every query for parameterization, least privilege, transactions, race conditions and bounded pagination.
- [ ] Define message deletion/tombstone behavior, metadata retention, encrypted attachments lifecycle, and expired-session/invite cleanup.
- [ ] Document automated PostgreSQL backup scheduling, encrypt backup artifacts, perform periodic isolated restore drills; log recovery time/objective without secrets.
- [ ] Test concurrent invite redemption, guild removal during broadcast, token rotation during replay, expired cursors and stale sessions across instances.

## Production gate

Treat these as **blocking**: real E2EE before claiming encrypted private chat, shared abuse controls and multi-instance revocation, security header/origin review, endpoint authorization review, repeatable migrations and backup restoration, security regression tests, independent review. Until then, run only in trusted/private experimental environments.

This document establishes a review baseline and exposes risks; it **does not certify** Nexora as secure.
