# Nexora
**Your space. Your people. Your privacy.**

An independent self-hosted chat platform under active development. Not based on Spacebar.

## Current status: early API foundation, not production-ready

Implemented: editable profiles and manually added **unverified** Twitch/YouTube/GitHub/Steam profile links, basic browser sign-in and guild/channel browsing, register/login/logout, PostgreSQL users and hashed sessions, create/list guilds, default encrypted-envelope text channel, message history and a simple authenticated WebSocket event gateway.

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
