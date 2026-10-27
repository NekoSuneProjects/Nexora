# Nexora
**Your space. Your people. Your privacy.**

An independent self-hosted chat platform under active development. Not based on Spacebar.

## Current status: early API foundation, not production-ready

Implemented: device public-key registration/listing/revocation (not yet E2EE), active session count and revoke-all-sessions, owner-only channel creation and renaming, owner-created expiring limited-use community invites and member joining, editable profiles and manually added **unverified** Twitch/YouTube/GitHub/Steam profile links, basic browser sign-in and guild/channel browsing, register/login/logout, PostgreSQL users and hashed sessions, create/list guilds, default encrypted-envelope text channel, message history and a simple authenticated WebSocket event gateway.

**No working E2EE client or cross-device key management yet.** Ciphertext storage alone does not guarantee privacy against the server; do not use this project for sensitive communication. **Discord.js compatibility is also not ready.** Voice/video, screen sharing, gaming player cards, Discord template import, profile animation, OAuth and bots remain planned.

## Local development

Requirements: Node.js 22+, PostgreSQL 17+, npm.

1. Copy `.env.example` to `.env`, set a unique database password/connection string.
2. Initialise the DB using `database/schema.sql`.
3. `npm install`
4. `npm run dev`
5. Open `http://127.0.0.1:3000/` for the developer UI; API health is `/health`.

The initial web client does **not** send chat messages until proper client-side E2EE has been designed. It can browse encrypted envelopes, but cannot decrypt them.

Or for isolated Docker development: set `POSTGRES_PASSWORD` and `DATABASE_URL` in `.env`, then run `docker compose up --build`. Docker API binds to loopback only. Do not expose to the public internet yet.

### Example API

```bash
curl -X POST http://127.0.0.1:3000/api/v1/auth/register -H 'content-type: application/json' -d '{"username":"alice","password":"choose-a-long-unique-password"}'
curl -X POST http://127.0.0.1:3000/api/v1/auth/login -H 'content-type: application/json' -d '{"username":"alice","password":"choose-a-long-unique-password"}'
```

Use returned `token` as an Authorization `Bearer` token for `POST /api/v10/guilds`, `GET /api/v10/users/@me/guilds`, `GET /api/v10/guilds/:id/channels`, and encrypted-envelope messaging.

Read [architecture and security status](docs/ARCHITECTURE.md) before deploying.

## Updating an existing PostgreSQL volume
Run `database/schema.sql` again on your existing Nexora database after pulling changes. The new tables use `CREATE TABLE IF NOT EXISTS`; Docker init scripts only execute on initial database creation. Never delete a production database volume to apply schema updates.

OAuth account ownership verification is not implemented. All manually added links are labelled unverified.

## Invites
Community owners can create random 24-byte invite codes at `POST /api/v1/guilds/:id/invites` with `max_uses` and `expires_hours`. Authenticated users can join at `POST /api/v1/invites/:code/join`. Only hashes of invite codes are stored. Existing memberships do not use another invite slot. Invites are secrets: share only with intended members.

## Device key groundwork
Authenticated users can register a 32-byte base64url-encoded public identity key using `POST /api/v1/devices`, list devices, fetch a user's device public keys, and revoke their own device records. These APIs never ask for private keys. **A malicious server could substitute public keys; device verification, key transparency, encrypted backups, signed key bundles, and cryptographic client integration remain unimplemented. This is not end-to-end encryption.** Revoking a record does not yet rotate any conversation keys.

## Experimental real-time client
The browser now connects to the native Gateway, authenticates, subscribes to the selected channel, and refreshes opaque message envelopes on `MESSAGE_CREATE`. Heartbeats, a basic timeout, and unsubscribe handling are implemented. This is **not** a Discord.js-compatible Gateway, and it is not a message-decryption implementation. Real-time subscriptions currently rely on membership at subscribe time; membership revocation push enforcement and multi-instance fanout still need implementation.

## Membership limitations
A community member list is accessible only to members; the owner may remove other users, and non-owner members may leave via the API. **Important:** the real-time gateway does not yet forcibly unsubscribe removed members, and client-side cryptographic key rotation is not yet implemented. Removing someone from a community is not yet a complete real-time or E2EE revocation guarantee.

## Membership eviction (single API process)
Removing a member now clears their existing channel subscriptions and notifies their connected clients with `CHANNEL_ACCESS_REVOKED`, preventing further broadcast delivery through those subscriptions. This is **not sufficient for multi-instance deployments**, where event fanout and membership invalidation require a shared bus such as Redis. Existing E2EE session keys, once implemented, must be rotated separately. This prototype remains single-instance and should not be exposed publicly.

## Request helper fix
The browser and integration-test HTTP helpers now send JSON Content-Type only when sending a JSON body. Fastify rejects empty application/json requests; this previously broke empty-body actions such as join invite, sign out, and member removal.

## Developer apps (initial)
Authenticated users may create, list and revoke developer applications. Each app is issued a 256-bit bot credential once; only its SHA-256 hash is stored. Bot credentials authenticate to `GET /api/v1/bots/@me` using `Authorization: Bot <token>`, and cannot authenticate as human sessions. **Bots cannot yet be invited, receive Gateway events or execute discord.js commands.** Production token rotation, rate limits and granular scopes remain future work.
