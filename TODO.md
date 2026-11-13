# Nexora TODO

Nexora is an open-source, self-hosted, **end-to-end-encrypted** community chat platform: an
alternative to Discord with a different structure. It is not a clone and not a Spacebar fork.

What makes it different:

- **E2EE first.** Messages are encrypted in the client, and the server stores only ciphertext.
- **DMs are private communities.** Direct and group conversations reuse the same membership,
  key-epoch and Gateway machinery as servers. There is no separate, weaker DM path.
- **Bots see metadata only.** They never receive message content or ciphertext unless a future,
  explicit E2EE bot membership is granted.
- **A native API first.** The permission bits are Nexora's own. Discord compatibility is a
  separate adapter (planned), not the core data model.

Legend: `[x]` done · `[~]` partial or prototype · `[ ]` not started.
**P0** blocks any public deployment. **P1** is needed for a usable 1.0. **P2** comes later.

---

## Done

### Foundation (before this round)
- [x] Fastify API, PostgreSQL, hashed opaque sessions, scrypt passwords with a bounded KDF gate
- [x] Shared PostgreSQL rate limits for registration, login (per IP, per account, per pair) and invites
- [x] TOTP MFA with encrypted secrets, replay protection and one-time recovery codes
- [x] Origin policy, CSP, security headers and log redaction
- [x] User Gateway (heartbeat, subscribe/unsubscribe, rate and size limits, revocation)
- [x] Cross-instance security bus (LISTEN/NOTIFY plus a persisted outbox with catch-up)
- [x] Developer apps, bot tokens (hashed, rotatable), bot installs, metadata-only bot Gateway and event catch-up
- [x] Device public-key registry, browser device vault (PBKDF2 + AES-GCM), WebCrypto primitives
- [x] Message tombstones, membership key epochs, a migration ledger, backup and restore scripts, Docker, Electron shell

### Community core (this round)
- [x] **Roles and permissions**: 15 Nexora-native permission bits, an `@everyone` default role,
      role hierarchy (you can only manage roles below your top role), no granting permissions you lack
- [x] Role CRUD and member role assignment; hoisted roles in the member list; role colours on names
- [x] **Channels**: categories, topics, ordering/reparenting, announcement channels (moderators post),
      deletion (keeps at least one text channel)
- [x] **Server management**: edit name and description, transfer ownership, delete server
- [x] **Moderation**: kick (KICK_MEMBERS plus hierarchy), bans (block rejoining), unban, audit log
- [x] **Invites**: role-based creation, management list (stores only a hint, never the code), revoke, preview
- [x] **Nicknames** (own and moderated)
- [x] **Messages**: edit (author only, current epoch), replies, reactions (with limits), pins,
      cursor pagination, moderator deletion (audited), read states and unread markers
- [x] **Social graph**: friend requests, accept, remove, block (blocked users look like they don't exist)
- [x] **Direct messages**: canonical 1:1 DMs, group DMs (up to 10), add a recipient, leave (ownership hands over)
- [x] **Profiles**: public profile with mutual servers, status (online/idle/dnd/invisible), custom status, accent colour
- [x] **Presence** from heartbeats, consistent across API instances
- [x] **Real-time events**: GUILD_*, CHANNEL_*, GUILD_MEMBER_*, GUILD_ROLES_UPDATE, MESSAGE_UPDATE,
      MESSAGE_REACTION_*, CHANNEL_PINS_UPDATE, TYPING_START (op 44), PRESENCE_UPDATE,
      RELATIONSHIP_UPDATE, DM_*, KEY_REQUEST
- [x] **Password change** (revokes every other session)
- [~] **Multi-member E2EE** (`apps/web/e2ee.mjs`):
  - per-epoch room keys, where the first member to claim an epoch wins (no forked keys)
  - an HMAC key commitment that every member verifies
  - signed key grants for every member device, with server-verified public bundles
  - trust-on-first-use device pinning with key-change detection
  - safety numbers, plus manual "mark verified"
  - key requests for newly added devices
  - joiners cannot read earlier epochs
- [x] **New web client**: server rail, channel sidebar, chat, member list, friends, DMs, settings modals,
      markdown, emoji reactions, typing indicator, unread markers, notifications, Gateway auto-reconnect
- [x] CSS moved out of inline styles, so the CSP is now `style-src 'self'` (API and nginx)

### Bugs fixed this round
- [x] `scripts/start-api.mjs` never ran migrations: its regex was over-escaped. Fresh Docker
      databases crashed on start because `security_events` did not exist.
- [x] The API served `/`, `/app` and the client scripts from the wrong directory, so they always returned 500.
- [x] Key-grant signatures failed after a PostgreSQL `jsonb` round-trip, because `jsonb` reorders keys.
      They now use canonical JSON.
- [x] The catch-up loop redelivered every event already received through NOTIFY. Stale replays could evict a member who had rejoined.
- [x] Deleting a guild cascaded into the epoch trigger, which then violated a foreign key.
- [x] Integration suites were flaky when run in parallel. CI now runs them serially, with a larger replica start budget.

---

## P0: security and release gates (blocking public deployment)

### Done (P0 round, migration `0009_p0_security.sql`)
- [x] **Sender authenticity.** Every message envelope carries an ECDSA signature from the sender's device over
      the nonce, ciphertext and context (room, sender, epoch). Receivers check that the signing device belongs to
      the author and is trusted. Forged messages are hidden; badges show ✓, unsigned, or unapproved device.
- [x] **Device cross-signing** (`evaluateDevices` in `e2ee.mjs`, `PUT /api/v1/devices/:id/attestation`). Once an
      account has a device, any new device must be **approved** (attested) by an existing trusted device of the
      same account. Clients refuse keys to unapproved devices, so a server that silently adds a device gets
      nothing. Attestations are verified on both the server and the client. The UI prompts for approval and shows safety numbers.
- [x] **Encrypted key backup and history sharing.** A recovery key (160-bit, shown once) encrypts all room
      keys into an opaque server-side backup. Uploads use versioned optimistic concurrency, so devices never
      overwrite each other. A new device restores the full history from the backup, and devices that are online
      keep the backup merged automatically. On each device the recovery key is sealed to that device's key.
- [x] **Passkeys (WebAuthn).** Register a passkey (requires the password) and sign in passwordlessly with
      discoverable credentials. A verifier with no dependencies (`webauthn.ts`) handles ES256 and RS256 (Windows Hello).
      It enforces single-use challenges, origin, RP ID, user verification and the signature counter (detects
      cloned authenticators).
- [x] **Web-host compromise, partial.** Subresource Integrity on every client asset (`npm run sri`, with a drift
      test and LF-pinned assets via `.gitattributes`). Imported modules are pinned with `modulepreload` integrity.
- [x] **Authorization matrix test.** 28 routes × 7 actor states (anonymous, outsider, banned, former member,
      member, moderator, owner): over 180 checks, plus role-hierarchy checks (`tests-integration/security.test.mjs`).
      Verified to catch an injected violation.
- [x] **Browser E2E in CI** (`tests-e2e/ui.e2e.mjs`, the CI `e2e` job, Playwright/Chromium, screenshots uploaded on failure):
      two users, signed E2EE chat, reactions, typing, passkey sign-in, backup restore on a second device,
      device approval, DMs, and a report reviewed by an admin.
- [x] **Instance admin tooling.** `INSTANCE_ADMINS` env bootstrap; an admin panel with stats, user search,
      suspend/unsuspend (sessions revoked on every instance; login refused only after a correct password),
      delete user, take down server, delete reported message, and a report queue (open/resolved/dismissed with notes).
      Users can report messages, users and servers, optionally attaching the decrypted text as reporter-supplied evidence.
- [x] **Account self-deletion** (requires the password; you must hand over servers you own first).

### Still open
- [ ] **Independent cryptographic review** of `crypto.mjs` + `e2ee.mjs`, and an **external penetration test**.
      This needs outside reviewers and cannot be done in-repo. Start from `docs/SECURITY_REVIEW.md`, `docs/E2EE_CHAT_PREVIEW.md` and `docs/API.md`.
- [ ] Replace the prototype group scheme with **MLS** (RFC 9420), e.g. OpenMLS in WASM or the `ts-mls` library.
      Remaining gaps: no forward secrecy or post-compromise security *within* an epoch. Key epochs rotate only on membership changes.
- [ ] **Key transparency log**, so an account's *first* device is not trusted on first use (cross-signing protects every later device)
- [ ] Desktop: ship the web client inside the signed Electron app instead of loading it from the server (needs a
      configurable API base URL and an Origin allow-list). Code-signing certificates, reproducible builds, mobile apps.
- [ ] Account recovery without a password or passkey (email or a trusted-contact flow; today recovery uses MFA recovery codes or a passkey)
- [ ] Redis/NATS (or similar) for Gateway fanout at scale. LISTEN/NOTIFY has an 8 KB payload limit and one DB
      connection per instance (events already carry IDs only, so the limit is not hit today).
- [ ] Legal takedown workflow: retention of moderation records, notices to affected users, transparency report
- [ ] Rate-limit and abuse tuning for reports and passkey endpoints under real traffic

> Notes: passkeys need Nexora served on a hostname (or `localhost`); browsers refuse IP addresses as WebAuthn RP IDs.
> After editing anything in `apps/web/`, run `npm run sri` or `npm test` fails.

## P1: features for a usable 1.0

### Messaging
- [ ] **Encrypted attachments**: client-side encryption, chunked upload, object storage (S3/MinIO), quotas, thumbnails generated client-side
- [ ] Link previews generated by the client, with an opt-in privacy warning
- [ ] Client-side message search (local encrypted index; the server cannot search ciphertext)
- [ ] Threads and forum channels
- [ ] Per-channel and per-server notification settings, mute, mention-only mode
- [ ] Slowmode and per-channel rate limits
- [ ] Mention autocomplete and `@everyone` (MENTION_EVERYONE exists as a bit but is not enforced; mentions are inside ciphertext)
- [ ] Unread counts for channels the socket is not subscribed to (server push of `CHANNEL_ACTIVITY` metadata)
- [ ] Message history beyond the current window on reconnect (Gateway `RESUME` with sequence numbers)
- [ ] Custom emoji and stickers (encrypted, per server)

### Channels and permissions
- [ ] **Per-channel permission overwrites and private channels.** This needs channel-scoped key distribution:
      today every member of a server holds keys for every channel.
- [ ] **Voice and video**: self-hosted LiveKit with SFrame/insertable-streams E2EE; stage channels
- [ ] Screen sharing
- [ ] Drag-and-drop channel reordering in the UI (the API `PUT /guilds/:id/channels/order` exists)

### Servers
- [ ] Server icons, banners and avatars (uploads, animated allowed; storage limits set by the instance admin)
- [ ] Server templates and a Discord template import tool
- [ ] Welcome or rules screen and onboarding
- [ ] Server discovery (opt-in and public; metadata only)
- [ ] Vanity invite URLs, invite links with landing pages
- [ ] Client-side AutoMod (word filters run on the receiving clients, because of E2EE)
- [ ] Timeouts (temporary mutes)

### Users
- [ ] Avatars and banners (uploads), pronouns field
- [ ] Verified social links through OAuth (Twitch, YouTube, GitHub, Steam). They are currently labelled unverified.
- [ ] Game player cards (provider APIs, opt-in)
- [ ] Username change, account deletion, data export (GDPR)
- [ ] An email address (optional) for recovery and notifications
- [ ] Session list with device names and per-session revoke (only revoke-all exists today)
- [ ] Remember an unlocked device on trusted browsers (non-extractable WebCrypto keys in IndexedDB)

### Bots and developer platform
- [ ] **Discord compatibility adapter** (`/api/v10` shapes, Snowflake mapping, Gateway opcodes) for discord.js bots
- [ ] OAuth2 install flow so other people's bots can be added (today you can only install your own apps)
- [ ] Slash commands and interactions
- [ ] Incoming webhooks. These would need a decision on plaintext versus E2EE, for example webhook messages marked as unencrypted.
- [ ] Explicit **E2EE bot membership**: a bot device that users can see holds room keys
- [ ] OpenAPI spec generated from the route schemas, and an SDK

### Clients
- [ ] Desktop: native notifications, tray icon, auto-update, code signing, deep links (`nexora://invite/...`)
- [ ] Mobile apps (React Native or Capacitor) with push notifications. Push payloads must not contain plaintext.
- [ ] Installable PWA (service worker) and offline cache of decrypted history (encrypted at rest)
- [ ] Accessibility audit (keyboard navigation, screen reader labels), i18n, light theme

## P2: later

- [ ] Federation between Nexora instances
- [ ] Prometheus metrics, OpenTelemetry traces, admin dashboard
- [ ] Helm chart and a reference Kubernetes deployment; managed object storage and backups
- [ ] Load tests (k6) for the Gateway and fanout; fuzzing of the Gateway protocol
- [ ] Split `apps/api/src/index.ts` (it has grown to over 1,100 lines) into route modules, like `community.ts`
- [ ] Move the web client to a build step (TypeScript, bundling, SRI hashes)

---

## Testing status

| Suite | Command | Status |
|---|---|---|
| Unit and source checks (77) | `npm test` | passing |
| Typecheck | `npm run typecheck` | passing |
| API integration (real PostgreSQL, 2 instances) | `npm run test:integration` | passing |
| Community integration (roles, moderation, DMs, keys) | included above | passing |
| P0 security integration + authorization matrix | included above | passing |
| Browser E2E (Chromium; 2 users; E2EE, passkeys, backup, approval, admin) | `npm run test:e2e` (CI `e2e` job) | passing locally (twice in a row, Edge); not yet run in GitHub CI |
