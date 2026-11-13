# Nexora P0 release gate and security verification matrix

Status: NOT approved for production. A passing CI suite is not an independent audit.

| Gate | Implemented evidence | Still required |
| --- | --- | --- |
| E2EE | WebCrypto prototype in apps/web/crypto.mjs | Real chat integration, device identity pinning, secure key persistence, membership epochs, recovery, independent cryptographic review |
| Authentication | Hashed sessions, shared IP/account quotas, bounded scrypt concurrency | MFA/passkeys, secure recovery, account takeover testing, concurrency/load validation |
| Gateway authorization | Session checks, per-event permissions, LISTEN/NOTIFY triggers, periodic subscription reconciliation | Durable events, disconnected-listener replay, strict bounded revocation SLO |
| Browser | Origin policy, CSP and security headers; CI HTTP checks | Real browser tests, proxy/TLS penetration validation, XSS/CSRF review |
| Database | Parametrized SQL, constraint migration, isolated CI restore | Migration ledger, production restore rehearsal, deletion/tombstone policy |
| Review | Internal threat model and source review | Independent reviewer signs off every high/critical finding |

## Blocking validation tasks

- [ ] Test authenticated device enrollment and key authenticity against a malicious server.
- [ ] Test removed members cannot decrypt messages from subsequent group epochs.
- [ ] Test replay and replacement of session, bot and membership invalidations after DB listener outages.
- [ ] Test all auth and WebSocket flows under concurrency, two API processes and compromised client origins.
- [ ] Implement phishing-resistant MFA and secure account recovery with session revocation.
- [ ] Run an independent penetration test and cryptographic review; log findings, fixes and retests.

Do not check the entire P0 section until those gates are demonstrated, tested and independently reviewed.