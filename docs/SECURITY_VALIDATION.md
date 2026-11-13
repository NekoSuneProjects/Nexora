# Production security validation and account-recovery plan

**Status: NOT signed off.** These are release gates and verification procedures, not completed controls.

## Browser and deployment validation
- Test real HTTP `Origin` rejection and same-origin access, CSP, X-Frame-Options and nosniff in PostgreSQL CI. Supplement with Playwright tests for reflected/stored XSS, malicious links, WebSocket upgrades, CSP violations and browser credential leaks.
- Deploy only behind HTTPS/WSS termination with an explicit `PUBLIC_BASE_URL`; require the proxy to overwrite forwarding headers and disable proxy access logs of Authorization or tokens. Do not expose the API, PostgreSQL or private logs publicly.
- Use environment-injected secrets, minimum DB roles, encrypted off-host backup archives, regular credential rotation, DAST/dependency scanning and restoration drills.
- Confirm subscription and bot revocation with **two live instances**, packet loss, reconnects, concurrent membership changes and database outages before production deployment.

## MFA and recovery security design (not implemented)
- Prefer WebAuthn/passkeys with phishing-resistant origin binding; enforce HTTPS, user verification and a verified account bootstrap.
- Require an authenticated fresh session for passkey enrollment; prevent silently enrolling an attacker-controlled credential.
- Use one-time high-entropy **hashed** recovery codes, show only at generation, invalidate on use, and offer secure rotation after proof of ownership.
- Require step-up authentication for disabling MFA, rotating recovery codes, changing account credentials and revoking other devices. Revoke existing sessions on account recovery, record audit events.
- Rate-limit MFA verification, enrollment and recovery globally per account/IP with atomic counters; never log codes or raw assertions.
- Document lost-device recovery and anti-social-engineering safeguards. Avoid email-only recovery without account takeover risk review.
- Add unit, database-backed integration and browser tests for replay/reuse, concurrent recovery requests, lost-device scenarios and session revocation.

## Independent review handoff
- Review `docs/THREAT_MODEL.md`, `docs/SECURITY_REVIEW.md` and all auth/WebSocket/membership SQL paths against a route matrix.
- Reviewer must be independent of implementation, record reproducible findings with severity, proof-of-concept and remediation evidence, and verify fixes.
- Open issues for critical/high findings. Do not mark any independent-review or overall P0 security item complete before signed approval.

## Trusted proxy configuration and account-level quotas
By default Fastify does **not** trust `X-Forwarded-For`. If deployed behind a controlled reverse proxy, set `TRUSTED_PROXY_CIDRS` to a comma-separated list of only the proxy's trusted addresses/CIDRs (for example `127.0.0.1/8` for a loopback-only proxy), and configure the proxy to overwrite client-supplied forwarded headers. Validate the actual client IP in integration tests for your topology; never set an unrestricted trust-all proxy mode. Login budgets are now enforced at the IP (60/15m), normalized username (40/15m), and pair (7/15m) scopes in shared PostgreSQL counters. These limits are initial safeguards and may block shared-network users; monitoring, tuning and recovery testing remain needed.
