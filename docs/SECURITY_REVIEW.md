# Nexora security review — 2026-10-27

**Review type:** internal, source-guided, preliminary. **Not independent penetration testing or a production security certification.**
Scope reviewed: `apps/api/src/index.ts`, `apps/web/app.js`, `apps/web/index.html`, `database/schema.sql`, `docs/THREAT_MODEL.md`.

## Assets and trust boundaries
Credentials, hashed session tokens, bot tokens and E2EE private keys are high-value. The browser/HTTP boundary, WebSocket gateway, application/PostgreSQL boundary, community authorization boundary and developer bot token/install boundary each require separate enforcement. An attacker may control their own account, send arbitrary REST or WebSocket packets, create invites they own, and host malicious cross-origin pages. A server operator or compromised static JavaScript host is **not** currently excluded by the threat model.

## Findings and status

| ID | Severity | Area | Finding and evidence | Status |
|---|---|---|---|---|
| SEC-01 | Critical | E2EE | Browser crypto helper exists, but chat does not use it, keys are not verified or managed and multi-device membership rotation is absent. | Open; do not claim E2EE |
| SEC-02 | High | Account takeover | Password+bearer-token authentication without MFA or verified account recovery. Session tokens last seven days. | Open |
| SEC-03 | High | Brute force | PostgreSQL atomic counters share per-IP/username caps, but there is no global KDF concurrency limit, global IP quota or tested distributed proxy deployment. | Partial |
| SEC-04 | High | Gateway revocation | Local socket eviction and periodic PostgreSQL checks exist, but cross-instance membership revocation and broadcast sequencing are not immediate. | Open |
| SEC-05 | High | Web security | Origin policy, protective response headers and log redaction were not explicit. Same-origin Origin enforcement, response headers and Fastify redaction added in this commit; reverse proxy deployment still needs review. | Mitigated locally, verify |
| SEC-06 | High | Bots | Bot credentials can receive metadata, with per-event checks and token rotation. Need cross-instance revocation tests and permission audit across all endpoints. | Partial |
| SEC-07 | Medium | Invitations | Cryptographically random hashed invite tokens and a row-locked transactional use counter exist; invitation guessing quotas, abuse monitoring and concurrent redemption stress tests remain. | Partial |
| SEC-08 | Medium | Metadata | Message author/channel/timestamps and bot event history disclose social graph/activity; no minimization/retention or consent policy. | Open |
| SEC-09 | Medium | Sessions | Bearer tokens are held in the browser runtime; there is no MFA and no durable device-level risk signal. No cookie-based authentication is used, reducing conventional cookie-CSRF exposure. | Partial |
| SEC-10 | High | Secrets and logs | App logs must never include auth headers, request bodies, bot tokens or private keys; redaction added for common fields. Reverse proxy logs, error processors, backups and external monitoring remain unaudited. | Partial |

## Abuse and authorization review
- **Sessions:** PostgreSQL checks expiration; logout-all deletes session rows and closes local sockets. Test stale sockets after cross-process revocation, concurrent renewal/revocation and accidental token exposure.
- **Invites:** membership insert and invite-use update are inside one transaction with `FOR UPDATE`. Test parallel join requests, expired invites and invite-code brute force.
- **Guild/channel:** endpoints require membership or owner privileges. Test cross-guild channel identifiers and membership removal during broadcasts: users should not continue receiving encrypted envelopes.
- **Bots:** bot credentials are distinct from human tokens; metadata is permission-scoped. Test revoked installs, rotated tokens, forged cursors and bot Gateway reconnect against a separate API instance.
- **XSS:** web UI uses `textContent` for untrusted message fields. Retain this; do not render unsanitized message HTML. In-page scripts and browser E2EE code delivered by the server remain compromise-sensitive.
- **CSRF/CORS:** bearer Authorization headers rather than ambient cookies lower traditional CSRF exposure; browser `Origin` checks and a same-origin policy are added. Deployments using reverse proxies must configure `PUBLIC_BASE_URL`; never blindly trust client-controlled forwarding headers.
- **CSP:** a restrictive baseline is in place, but inline CSS currently requires `style-src 'unsafe-inline'`. Remove this by extracting CSS into a static stylesheet and test with actual browsers.
- **Logging/secrets:** avoid storing tokens in URLs, never put encryption private keys in DB or logs; use secret injection in deployment and rotate compromised credentials.

## Required verification before closing the security-review TODO
- [ ] Independent reviewer examines endpoint authorization and WebSocket state machines and signs off findings.
- [ ] DAST/browser tests validate CSP, Origin, CORS, reflected/stored XSS and token leaks.
- [ ] Red-team tests for credential stuffing, scrypt resource exhaustion, invite abuse and bot privilege escalation.
- [ ] Two-instance revocation/membership tests and cross-community negative tests.
- [ ] Full E2EE cryptographic protocol review with device substitution and epoch rekey scenarios.
- [ ] Audit reverse proxy logging, deployed secrets, backup/restore, database privileges and retention.
- [ ] Track findings as GitHub issues with assignees and remediation evidence.

**Security conclusion:** Nexora remains a developer preview; the new headers, Origin guard and logging redaction are incremental controls, not proof of overall security.

## Incremental cross-instance event bus (PostgreSQL LISTEN/NOTIFY)
Each API instance now listens to `nexora_security` and receives user-session, bot-token, guild-member invalidation, and message notifications. On message delivery, the receiver rechecks both the session and guild membership in PostgreSQL; bot notifications continue through the permission-controlled metadata emitter. This is **best-effort pub/sub**, not durable delivery: PostgreSQL LISTEN/NOTIFY can lose messages while an instance is disconnected; reconnect orchestration, fencing, transactional outbox and multi-instance integration tests are still release blockers. A listener error closes the API process rather than continuing without security notifications. Do not mark P0 complete until verified.

## Negative-path authorization coverage (2026-10-27)
Added PostgreSQL integration cases denying cross-community channel reads, message reads/writes, invite creation, member listings/removal, channel creation and rename. Existing tests also cover bot grant revocation and session invalidation. Fixed cross-instance membership test to execute the removal before awaiting revocation. **Remaining review:** enumerate every route in an access-control matrix, test races under contention (membership change between auth and write), multi-instance bot token events and all WebSocket subscribe/unsubscribe edge cases. This is not a completed audit.

## Incremental browser verification and reviewer readiness
CI now exercises real HTTP cross-origin rejection, same-origin access and headers; the second-instance membership test was corrected to issue an actual removal before waiting for notification. See `docs/SECURITY_VALIDATION.md` for deployment checks, MFA/account-recovery acceptance criteria and independent review handoff. This does **not** implement MFA or replace external review.

## Additional abuse hardening
A shared PostgreSQL IP-wide login budget (60 attempts / 15 minutes) now supplements the per username/IP budget. A per-process bounded scrypt admission gate defaults to four concurrent KDF jobs; excess requests return 503 instead of growing unbounded KDF work. These are **starter limits**, not tuned deployment guarantees: tune `MAX_ACTIVE_KDF`, validate proxy IP handling, add cross-instance load tests, and schedule expired quota cleanup. The shared database may become a denial-of-service dependency and needs monitoring.

## October 2026 P0 batch: invite abuse, membership SQL and bot invalidation
- Invite redemption now has shared PostgreSQL user/IP hourly attempt budgets; test concurrent limits and consider differentiated legitimate-user thresholds.
- Membership deletion rechecks owner/self authorization and owner protection in the same SQL DELETE (instead of trusting a prior select).
- Bot uninstall now publishes an event that evicts corresponding remote bot Gateway subscriptions. Recheck install permissions at message delivery as before. LISTEN/NOTIFY remains non-durable; do not claim complete cross-instance security.

## Device directory onboarding restrictions
Added fresh-password verification and a shared PostgreSQL abuse budget before a device public key can be enrolled, reducing the risk from stolen bearer tokens. Device-key lookups are scoped to users in the requesting user’s communities; no global account enumeration of device identities. This authenticates account control at enrollment, not genuine device possession or identity pinning. Device signatures, key transparency, TOFU pinning and out-of-band verification remain required before calling client E2EE secure.
