# Nexora API reference (native)

All bodies are JSON. Human endpoints use `Authorization: Bearer <session token>`. Bot endpoints use
`Authorization: Bot <token>`. IDs are UUIDs. Errors return `{ "message": "..." }` with a 4xx status code.
Permission names refer to `apps/api/src/permissions.ts`. Owners and `ADMINISTRATOR` holders have every permission.

Message bodies are **always ciphertext**: `{ algorithm: "client-encrypted-v1", ciphertext: "<JSON envelope>" }`.
The server never sees plaintext. When the ciphertext is JSON, the server checks that `context.epoch` matches
the community's current key epoch.

## Auth and account
| Method | Path | Notes |
|---|---|---|
| POST | `/api/v1/auth/register` | `{username, password}`. Limited to 5 per IP per hour |
| POST | `/api/v1/auth/login` | `{username, password, mfa_code?, recovery_code?}` → `{token}` |
| POST | `/api/v1/auth/logout` · `/logout-all` | Revokes this session, or every session |
| GET | `/api/v1/auth/sessions` | Active sessions |
| POST | `/api/v1/auth/password` | `{current_password, new_password}`. Revokes your other sessions |
| POST | `/api/v1/auth/mfa/enroll` · `/confirm` | TOTP set-up. `enroll` requires `{password}`; `confirm` takes `{code}` |
| GET | `/api/v10/users/@me` | The current user |

## Profiles, presence and the social graph
| Method | Path | Notes |
|---|---|---|
| GET/PUT | `/api/v1/profiles/@me` | `{display_name, bio}` |
| PUT/DELETE | `/api/v1/profiles/@me/links[/:provider]` | Unverified Twitch/YouTube/GitHub/Steam links |
| GET/PATCH | `/api/v1/users/@me/settings` | `{status: online\|idle\|dnd\|invisible, custom_status, accent_color}` |
| GET | `/api/v1/users/:id/profile` | Requires a shared community or a relationship. Includes mutual servers |
| GET | `/api/v1/users/@me/relationships` | Friends, requests and blocks, with presence |
| POST | `/api/v1/users/@me/relationships` | `{username}`: sends a friend request, or accepts one if they already requested you |
| PUT | `/api/v1/users/@me/relationships/:userId` | `{type: "friend"}` to accept · `{type: "blocked"}` to block |
| DELETE | `/api/v1/users/@me/relationships/:userId` | Unfriend, cancel, decline or unblock |
| GET | `/api/v1/users/@me/read-states` | Last read time per channel |

## Direct messages (implemented as private `kind='dm'` communities)
| Method | Path | Notes |
|---|---|---|
| GET | `/api/v1/users/@me/channels` | DM list with recipients and presence |
| POST | `/api/v1/users/@me/channels` | `{recipient_ids:[...], name?}`. 1 recipient gives the canonical 1:1 DM; 2–9 make a group. Requires a friendship or a shared server, and no block in either direction |
| PUT | `/api/v1/users/@me/channels/:guildId/recipients/:userId` | Add someone to a group (max 10) |
| DELETE | `/api/v1/users/@me/channels/:guildId` | Leave a group |

## Servers (communities)
| Method | Path | Permission |
|---|---|---|
| POST | `/api/v10/guilds` | Any user. Creates `#general` and `@everyone` |
| GET | `/api/v10/users/@me/guilds` | Your servers (DMs excluded) |
| GET | `/api/v1/guilds/:id` | Member. Includes `permissions` (your effective permissions, as a string) and `roles` |
| PATCH | `/api/v1/guilds/:id` | MANAGE_GUILD · `{name?, description?}` |
| DELETE | `/api/v1/guilds/:id` | Owner |
| POST | `/api/v1/guilds/:id/transfer` | Owner · `{user_id}` |
| GET | `/api/v1/guilds/:id/audit-log?before=` | VIEW_AUDIT_LOG |
| GET | `/api/v1/guilds/:id/members` | Member. Includes nickname, roles, presence |
| PATCH | `/api/v1/guilds/:id/members/:userId\|@me` | `{nickname}`. CHANGE_NICKNAME for yourself, MANAGE_NICKNAMES plus hierarchy for others |
| DELETE | `/api/v1/guilds/:id/members/:userId` | Leave (yourself), or KICK_MEMBERS plus hierarchy |
| GET/POST | `/api/v1/guilds/:id/roles` | Member to list · MANAGE_ROLES to create `{name, color, permissions, hoist}` |
| PATCH/DELETE | `/api/v1/guilds/:id/roles/:roleId` | MANAGE_ROLES. The role must be below your top role, and you cannot grant permissions you lack |
| PUT/DELETE | `/api/v1/guilds/:id/members/:userId/roles/:roleId` | MANAGE_ROLES plus hierarchy |
| GET | `/api/v1/guilds/:id/bans` | BAN_MEMBERS |
| PUT/DELETE | `/api/v1/guilds/:id/bans/:userId` | BAN_MEMBERS plus hierarchy · `{reason}` |
| POST | `/api/v1/guilds/:id/invites` | CREATE_INVITE · `{max_uses, expires_hours}`. The code is shown once |
| GET | `/api/v1/guilds/:id/invites` | MANAGE_GUILD. Shows hints only |
| DELETE | `/api/v1/guilds/:id/invites/:inviteId` | MANAGE_GUILD, or the invite's creator |
| GET | `/api/v1/invites/:code` | Preview |
| POST | `/api/v1/invites/:code/join` | Banned users are refused |

## Channels and messages
| Method | Path | Permission |
|---|---|---|
| GET | `/api/v10/guilds/:id/channels` | Member. Includes `topic, position, parent_id, last_message_at, last_read_at` |
| POST | `/api/v1/guilds/:id/channels` | MANAGE_CHANNELS · `{name, kind: encrypted_text\|announcement\|category, topic?, parent_id?}` |
| PATCH | `/api/v1/channels/:id` | MANAGE_CHANNELS · `{name?, topic?}` |
| DELETE | `/api/v1/channels/:id` | MANAGE_CHANNELS |
| PUT | `/api/v1/guilds/:id/channels/order` | MANAGE_CHANNELS · `[{id, position, parent_id?}]` |
| GET | `/api/v10/channels/:id/messages?before=&limit=` | Member. Includes reactions, pinned, edited_at, reply_to |
| POST | `/api/v10/channels/:id/messages` | SEND_MESSAGES (MANAGE_MESSAGES in announcement channels) · `{algorithm, ciphertext, reply_to?}` |
| PATCH | `/api/v10/channels/:id/messages/:mid` | Author only; must use the current epoch |
| DELETE | `/api/v10/channels/:id/messages/:mid` | Author, or MANAGE_MESSAGES (audited) |
| GET | `/api/v10/channels/:id/deletions?after=` | Tombstones, for offline resync |
| PUT/DELETE | `/api/v10/channels/:id/messages/:mid/reactions/:emoji/@me` | ADD_REACTIONS. Emoji are visible metadata |
| GET | `/api/v10/channels/:id/messages/:mid/reactions/:emoji` | Who reacted |
| GET | `/api/v10/channels/:id/pins` | Member |
| PUT/DELETE | `/api/v10/channels/:id/pins/:mid` | MANAGE_MESSAGES (any member in DMs). Max 50 |
| POST | `/api/v1/channels/:id/ack` | `{message_id?}`: marks the channel read |

## E2EE devices and room keys
| Method | Path | Notes |
|---|---|---|
| POST | `/api/v1/devices` | `{name, identity_key, public_bundle, password}`. The bundle must hash to `identity_key` |
| PUT | `/api/v1/devices/:id/bundle` | Upload the bundle for a device enrolled before bundles existed |
| GET/DELETE | `/api/v1/devices[/:id]` | List or revoke your devices |
| GET | `/api/v1/users/:id/devices` | Requires a shared community |
| GET | `/api/v1/channels/:id/keys` | `{epoch, recipients[...public_bundle], wrapped (yours), granted_device_ids, claim, history}` |
| POST | `/api/v1/channels/:id/keys/claim` | `{epoch, device_id, key_commitment}`. The first writer wins; later claims get 409 with the existing claim |
| PUT | `/api/v1/channels/:id/keys/:deviceId` | `{epoch, wrapped_key, granter_device_id}`, a signed grant for one device |
| POST | `/api/v1/channels/:id/keys/request` | Asks online holders to share the key (dispatches `KEY_REQUEST`) |

## Gateway (`GET /api/v10/gateway` → `wss://…/gateway`)
Server sends op 10 `{heartbeat_interval}`. Client sends op 2 `{token}` and receives `READY`. Then:
op 1 heartbeat (answered by op 11) · op 42 `{channel_id}` to subscribe (max 25) · op 43 to unsubscribe · op 44 `{channel_id}` for typing.
Dispatches (op 0) include `MESSAGE_CREATE/UPDATE/DELETE`, `MESSAGE_REACTION_ADD/REMOVE`, `CHANNEL_PINS_UPDATE`,
`TYPING_START`, `PRESENCE_UPDATE`, `CHANNEL_CREATE/UPDATE/DELETE`, `CHANNELS_REORDER`, `GUILD_CREATE/UPDATE/DELETE`,
`GUILD_MEMBER_ADD/REMOVE/UPDATE`, `GUILD_ROLES_UPDATE`, `RELATIONSHIP_UPDATE`, `DM_CREATE/UPDATE`, `KEY_REQUEST`,
and `CHANNEL_ACCESS_REVOKED`. Close code 4004 means the session was revoked.

## Bots
See the README sections on developer apps, the bot Gateway (`/bot-gateway`) and metadata catch-up
(`/api/v1/bots/...`). Bots receive identifiers only, never content or ciphertext.

## Security (P0 round)
| Method | Path | Notes |
|---|---|---|
| POST | `/api/v1/auth/passkeys/register/options` · `/register` | Add a passkey (requires `{password}` first) |
| POST | `/api/v1/auth/passkeys/login/options` · `/login` | Passwordless sign-in (discoverable credentials) |
| GET/DELETE | `/api/v1/auth/passkeys[/:id]` | List or remove passkeys |
| PUT | `/api/v1/devices/:id/attestation` | `{signer_device_id, signature}`: approve your new device from an existing one |
| GET/PUT/DELETE | `/api/v1/users/@me/key-backup` | Opaque encrypted backup. `PUT {version: current+1, ciphertext}`; a stale version returns 409 |
| DELETE | `/api/v1/users/@me` | `{password}`: delete your account (hand over owned servers first) |
| POST | `/api/v1/reports` | `{target_type: message\|user\|guild, target_id, reason, evidence?}` |
| * | `/api/v1/admin/...` | Instance admins only: `stats`, `users?q=`, `users/:id/suspend\|unsuspend`, `DELETE users/:id`, `guilds`, `DELETE guilds/:id`, `reports?status=`, `POST reports/:id`, `DELETE messages/:id` |
