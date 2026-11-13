# Nexora architecture (initial roadmap)

Nexora is an independent product, **not a fork of Spacebar or Discord**.

## Implemented

- A Fastify API (`apps/api/src/index.ts` covers core/auth/gateway; `community.ts` covers roles, moderation, DMs, social features and key distribution) backed by PostgreSQL, with hashed passwords and opaque expiring sessions.
- Communities with roles and Nexora-native permission bits (`permissions.ts`), a role hierarchy, categories, announcement channels, bans, an audit log and invites.
- Direct and group messages, stored as private `guilds.kind='dm'` communities. They reuse membership checks, key epochs and Gateway delivery, so DMs get exactly the same authorization and E2EE path as servers.
- A friends and block graph, plus presence derived from Gateway heartbeats (`user_presence`), so every API instance agrees on status.
- A native WebSocket Gateway: channel subscriptions, typing, and member-targeted dispatch events delivered through the cross-instance PostgreSQL outbox (`security_events` plus LISTEN/NOTIFY, deduplicated by row ID).
- A browser client (`apps/web`) that encrypts every message with `crypto.mjs`, and multi-member room-key distribution in `e2ee.mjs`. See `docs/E2EE_CHAT_PREVIEW.md`.
- Some early Discord-shaped REST paths as a compatibility target, **not** full Discord API equivalence.
- Docker Compose (PostgreSQL + API), an nginx web container, and an Electron desktop shell.

## Deliberately not claimed as complete

- **E2EE:** a prototype group scheme (per-epoch AES keys, signed ECDH grants, TOFU device pinning, key commitments). It has no MLS, no forward secrecy within an epoch and no message signatures, the server can add devices, and nothing has been reviewed independently. Do not use it for confidential conversations.
- **Discord.js:** Snowflake IDs, Gateway resume, interactions and OAuth2 are not implemented. Existing Discord bots cannot connect unchanged.
- **Voice/video, attachments, per-channel permissions:** planned (see TODO.md).

## Security model and design decisions

1. Client-generated E2EE keys must never be held by the server. Use a vetted protocol/implementation (MLS or mature Matrix crypto), never roll custom crypto.
2. Device verification must mitigate malicious server key substitution; a hostile web-host operator can replace served JavaScript, so signed desktop/mobile distributions are important.
3. Encrypt attachments locally; minimise visible metadata and keep encrypted backup/recovery user controlled.
4. Bots may decrypt messages only as explicitly approved E2EE members. Discord-style plaintext bots must not silently bypass privacy.
5. Use a native domain/API plus a separate versioned Discord compatibility adapter; avoid coupling your DB to Discord-specific IDs.
6. Public game stats need user consent and provider-compliant data; no impersonated API access.
7. Animated avatars and banners are free features; fair storage and bandwidth limits are instance administrator settings.

## Next milestones

See [TODO.md](../TODO.md) for the prioritised backlog: P0 security gates (MLS, sender signatures, key transparency, independent review), then attachments, per-channel permissions, voice and video, and the Discord compatibility adapter.
