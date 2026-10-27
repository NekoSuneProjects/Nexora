# Nexora architecture (initial roadmap)

Nexora is an independent product, **not a fork of Spacebar or Discord**.

## Implemented in the first foundation

- Fastify API with PostgreSQL-backed users, hashed passwords and opaque expiring sessions.
- Guild creation, membership, one default channel, retrieval and encrypted-envelope storage.
- Native WebSocket gateway proof of concept for authorized channel subscriptions.
- Early Discord-shaped REST paths as a compatibility target, **not** full Discord API equivalence.
- Docker Compose PostgreSQL and API; static web placeholder.

## Deliberately not claimed as complete

- **E2EE:** server accepts opaque ciphertext but no cryptographic client, key exchange, device verification, encrypted backup, or secure sender identity exists yet. The `client-encrypted-v1` marker is caller-supplied and DOES NOT attest encryption. Do not use for confidential conversations yet.
- **Discord.js:** API schemas, Snowflake IDs, Gateway lifecycle, event seq/resume, interactions, OAuth2, permissions and bot tokens are not implemented. Current gateway op 42 is Nexora-specific. Existing Discord bots cannot yet connect unchanged.
- **Security:** rate limiting, MFA, abuse controls, CORS policy, HTTPS proxy, audit logs, invite flows and key transparency still needed before public deployment.
- **Voice/video:** self-hosted LiveKit (with independent key exchange for media E2EE) is planned but not integrated.
- **Profiles:** OAuth account linking, verified badges, Fortnite/Apex providers, animated assets and import tooling are planned.

## Security model and design decisions

1. Client-generated E2EE keys must never be held by the server. Use a vetted protocol/implementation (MLS or mature Matrix crypto), never roll custom crypto.
2. Device verification must mitigate malicious server key substitution; a hostile web-host operator can replace served JavaScript, so signed desktop/mobile distributions are important.
3. Encrypt attachments locally; minimise visible metadata and keep encrypted backup/recovery user controlled.
4. Bots may decrypt messages only as explicitly approved E2EE members. Discord-style plaintext bots must not silently bypass privacy.
5. Use a native domain/API plus a separate versioned Discord compatibility adapter; avoid coupling your DB to Discord-specific IDs.
6. Public game stats need user consent and provider-compliant data; no impersonated API access.
7. Animated avatars and banners are free features; fair storage and bandwidth limits are instance administrator settings.

## Next milestones

1. Integration tests + rate limiting + session revocation + invite membership.
2. Full frontend auth, guild and channel UI.
3. Independently reviewed E2EE protocol client and cross-device recovery.
4. Discord bot REST and Gateway conformance suite.
5. LiveKit calls, OAuth/social connections, game cards and templates.
