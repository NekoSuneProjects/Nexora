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

## Initial community bot installations
Community owners may install their own active developer apps via `POST /api/v1/guilds/:id/bots`, list installed apps, or uninstall them. The `can_read_events` permission is stored explicitly but **is not yet an implemented event delivery mechanism**. Bot credentials are not accepted by normal human endpoints and cannot read encrypted messages. Cross-owner OAuth installation, bot Gateway sessions, interactions and discord.js parity remain future work.

## Bot-scoped community discovery
`GET /api/v1/bots/@me/guilds` lists communities where a bot is installed. `GET /api/v1/bots/guilds/:id/channels` lists channel metadata only when its community installation has `can_read_events=true`. These endpoints use `Authorization: Bot <token>`; no message bodies or key material are returned. Live bot Gateway subscriptions and Discord.js compatibility remain unimplemented.

## Experimental bot Gateway
Bot applications can connect to `/bot-gateway` with WebSocket and send op 2 `{token}` to authenticate, then op 42 `{guild_id}` to subscribe when `can_read_events` is granted. Op 1 heartbeats and op 43 unsubscribe are supported. Bots receive only `MESSAGE_METADATA_CREATE` events containing guild/channel/message identifiers, **never message content or ciphertext**. Each emission rechecks the bot's installed permission and revocation status. This is a custom experimental protocol, not the Discord Gateway. It is single-process, without replay, rate limiting or reconnect resume.

## Example metadata bot
After creating a developer application and installing it in your community with `can_read_events: true`, run `NEXORA_BOT_TOKEN=... NEXORA_GUILD_ID=... node examples/metadata-bot.mjs` with Node 22+. Set `NEXORA_GATEWAY_URL=wss://...` for nonlocal deployments; **plain ws:// is only appropriate for local development**. The example receives opaque message identifiers, not message contents, and does not support automatic reconnect yet.

## Bot credential rotation
The owner may call `POST /api/v1/developer/apps/:id/rotate-token` (authenticated human Bearer session) to atomically replace an active application's bot token. Only the new token is returned, once; the previous credential fails REST authentication and is rejected for future bot event delivery, including on already-established WebSockets. Keep credentials secret, use TLS/WSS outside localhost, and remember that this is still a prototype.

## Bot example reconnect policy
The experimental metadata bot now reconnects with capped exponential backoff (1–30 seconds), re-authenticates and re-subscribes after disconnects, and stops cleanly on SIGINT/SIGTERM. It intentionally stops retrying on bot authentication rejection (code 4004/4005). **Missed events are not replayed**; reconnection is not an event-delivery guarantee. Avoid placing tokens in shell history or logs.

## Experimental Gateway abuse controls
The bot Gateway now closes a WebSocket exceeding 100 inbound messages per 10 seconds or 25 subscribed communities (code 4008). Payloads remain capped at 8 KiB and heartbeat timeouts continue to apply. These **per-connection** controls are not substitutes for IP/account admission limits, distributed quotas, or production anti-abuse controls.

## Human Gateway per-connection limits
The user Gateway now enforces the same 8 KiB frame cap, 100 incoming messages per 10 seconds and 25 live channel subscriptions per connection as the bot Gateway (close code 4008 on rate/subscription excess). This does not provide per-IP, cross-connection or cross-instance rate limiting; production abuse controls are outstanding.

## Login abuse mitigation
Six failed login attempts against the same username from the same Fastify client IP temporarily block further attempts for 15 minutes with HTTP 429 and Retry-After. Keys are SHA-256 hashed and the in-memory cache is bounded. This is **single-process, best-effort** protection, not a distributed rate limiter; an attacker can vary source IP/usernames, and shared proxies may affect the grouping. Configure trusted proxy handling carefully and add production-wide rate limits and account safeguards before public launch.

## Registration quota
The API now reserves up to five valid registration attempts per client IP per hour (429 / Retry-After: 3600 thereafter), before spending resources on password hashing. Failed insertions still consume a slot to limit username probing. This in-memory, per-process quota is preliminary and requires a distributed store and proxy/IP configuration before production deployment.

## Gateway session revocation (single process)
The user Gateway now tracks WebSocket connections by authenticated account and session hash. `POST /api/v1/auth/logout` closes connections for the revoked session; `POST /api/v1/auth/logout-all` closes all account connections (close code 4004), preventing those sockets receiving further in-process broadcasts. **Other API instances do not receive these invalidations**; multi-instance deployment still requires shared session revocation and event coordination.

## Gateway session expiry checks
On each heartbeat-watchdog interval (30 seconds), authenticated user Gateway connections revalidate their session hash against PostgreSQL and close with code 4004 if revoked or expired. This supplements immediate same-process logout invalidation and helps detect session deletion by another API instance, but **is not instantaneous distributed revocation**. A database check failure closes the connection rather than continuing indefinitely.

## Live session-expiry integration test
CI now connects through the user WebSocket, expires its session directly in PostgreSQL, and verifies the Gateway closes it with 4004. The API uses a 1-second watchdog interval **only with NODE_ENV=test**, so CI can test expiry promptly; normal deployments use the 30-second interval. Never configure production with NODE_ENV=test.

## Bot Gateway credential revalidation
Authenticated bot WebSockets now recheck their application ID and token hash against PostgreSQL every 30 seconds, closing with code 4004 if the app is revoked or the credential rotated. Community subscriptions also verify the current token hash. This reduces stale-credential windows but is not instantaneous cross-instance revocation; production deployments require a shared revocation bus.

## Live bot credential rotation test
CI authenticates a bot WebSocket, rotates its credential, and checks that the next server credential check closes the connection with code 4004. In test mode the bot watchdog uses a one-second interval; production retains 30 seconds. This still is not instantaneous revocation.

## CI assertion regression
Updated the bot rotation source check to match the current credential-hash assignment, and added an integration check that another user cannot rotate a developer application they do not own.

## Immediate local bot disconnects
Bot token rotation and app revocation now close all authenticated bot WebSockets associated with that application in the current API process (4004). This supplements the 30-second PostgreSQL watchdog on other processes. In a multi-instance setup, remote sockets may remain connected until their next check; shared invalidation remains unimplemented.

## Immediate revocation integration assertion
The PostgreSQL-backed bot Gateway test now checks that an active bot socket closes within 900 ms of token rotation, rather than merely relying on the 1-second test-only credential watchdog. This validates same-process revocation timing in CI, not instantaneous multi-instance invalidation.
