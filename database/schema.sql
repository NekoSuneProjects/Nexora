CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY,
  username text NOT NULL UNIQUE,
  password_salt text NOT NULL,
  password_hash text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash text PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON sessions(user_id);
CREATE TABLE IF NOT EXISTS guilds (
  id uuid PRIMARY KEY,
  name text NOT NULL,
  owner_id uuid NOT NULL REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS guild_members (
  guild_id uuid NOT NULL REFERENCES guilds(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY (guild_id,user_id)
);
CREATE TABLE IF NOT EXISTS channels (
  id uuid PRIMARY KEY,
  guild_id uuid NOT NULL REFERENCES guilds(id) ON DELETE CASCADE,
  name text NOT NULL,
  kind text NOT NULL DEFAULT 'encrypted_text',
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS messages (
  id uuid PRIMARY KEY,
  channel_id uuid NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  author_id uuid NOT NULL REFERENCES users(id),
  ciphertext text NOT NULL,
  algorithm text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS messages_channel_idx ON messages(channel_id,created_at,id);

CREATE TABLE IF NOT EXISTS user_profiles (
  user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  display_name text NOT NULL DEFAULT '',
  bio text NOT NULL DEFAULT '',
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS user_social_links (
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider text NOT NULL CHECK (provider IN ('twitch','youtube','github','steam')),
  url text NOT NULL,
  verified boolean NOT NULL DEFAULT false,
  PRIMARY KEY (user_id,provider)
);

CREATE TABLE IF NOT EXISTS guild_invites (
  code_hash text PRIMARY KEY,
  guild_id uuid NOT NULL REFERENCES guilds(id) ON DELETE CASCADE,
  created_by uuid NOT NULL REFERENCES users(id),
  expires_at timestamptz NOT NULL,
  max_uses integer NOT NULL CHECK(max_uses BETWEEN 1 AND 100),
  uses integer NOT NULL DEFAULT 0 CHECK(uses >= 0)
);
CREATE INDEX IF NOT EXISTS guild_invites_guild_idx ON guild_invites(guild_id);

CREATE TABLE IF NOT EXISTS user_devices (
 id uuid PRIMARY KEY,
 user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 name text NOT NULL,
 identity_key text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 revoked_at timestamptz,
 UNIQUE(user_id,identity_key)
);
CREATE INDEX IF NOT EXISTS user_devices_lookup ON user_devices(user_id) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS developer_apps (
 id uuid PRIMARY KEY,
 owner_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 name text NOT NULL,
 bot_token_hash text NOT NULL UNIQUE,
 created_at timestamptz NOT NULL DEFAULT now(),
 revoked_at timestamptz
);
CREATE INDEX IF NOT EXISTS developer_apps_owner_idx ON developer_apps(owner_id);

CREATE TABLE IF NOT EXISTS guild_bots (
 guild_id uuid NOT NULL REFERENCES guilds(id) ON DELETE CASCADE,
 app_id uuid NOT NULL REFERENCES developer_apps(id) ON DELETE CASCADE,
 can_read_events boolean NOT NULL DEFAULT false,
 installed_by uuid NOT NULL REFERENCES users(id),
 installed_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(guild_id,app_id)
);

-- Shared, atomic authentication quotas. Schedule deletion of expired rows operationally.
CREATE TABLE IF NOT EXISTS auth_rate_limits (
 key_hash text PRIMARY KEY,
 count integer NOT NULL CHECK (count >= 0),
 expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS auth_rate_limits_expiry_idx ON auth_rate_limits(expires_at);

CREATE TABLE IF NOT EXISTS user_mfa (user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, secret_enc text NOT NULL, enabled boolean NOT NULL DEFAULT false, last_step bigint NOT NULL DEFAULT -1);

CREATE TABLE IF NOT EXISTS mfa_recovery_codes (user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,code_hash text NOT NULL,PRIMARY KEY(user_id,code_hash));

-- Deletion metadata only; retain until an approved policy applies.
CREATE TABLE IF NOT EXISTS message_tombstones (
 id uuid PRIMARY KEY,
 channel_id uuid NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
 deleted_by uuid REFERENCES users(id) ON DELETE SET NULL,
 deleted_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS message_tombstones_channel_idx ON message_tombstones(channel_id,deleted_at,id);

-- Membership epoch advances on join and removal; older envelopes remain historical.
CREATE TABLE IF NOT EXISTS guild_key_epochs (guild_id uuid PRIMARY KEY REFERENCES guilds(id) ON DELETE CASCADE, epoch bigint NOT NULL DEFAULT 1 CHECK(epoch>0));
CREATE TABLE IF NOT EXISTS channel_device_keys (
 channel_id uuid NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
 epoch bigint NOT NULL CHECK(epoch>0),
 device_id uuid NOT NULL REFERENCES user_devices(id) ON DELETE CASCADE,
 wrapped_key jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(channel_id,epoch,device_id)
);
CREATE OR REPLACE FUNCTION nexora_bump_membership_epoch() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM guilds WHERE id=COALESCE(NEW.guild_id,OLD.guild_id)) THEN RETURN NULL; END IF;
 INSERT INTO guild_key_epochs(guild_id,epoch) VALUES(COALESCE(NEW.guild_id,OLD.guild_id),2)
 ON CONFLICT(guild_id) DO UPDATE SET epoch=guild_key_epochs.epoch+1;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS nexora_epoch_on_join ON guild_members;
CREATE TRIGGER nexora_epoch_on_join AFTER INSERT ON guild_members FOR EACH ROW EXECUTE FUNCTION nexora_bump_membership_epoch();
DROP TRIGGER IF EXISTS nexora_epoch_on_leave ON guild_members;
CREATE TRIGGER nexora_epoch_on_leave AFTER DELETE ON guild_members FOR EACH ROW EXECUTE FUNCTION nexora_bump_membership_epoch();

-- ===== 0008 community core (kept in sync with database/migrations/0008_community_core.sql) =====
-- 0008: community core — roles/permissions, channel structure, moderation, message
-- features, social graph, direct messages, presence and multi-device key distribution.
-- Idempotent: safe to apply more than once. Never drops data.

-- Communities: descriptions and a kind discriminator. Direct messages reuse the
-- community/membership/epoch machinery with kind='dm' and are hidden from server lists.
ALTER TABLE guilds ADD COLUMN IF NOT EXISTS description text NOT NULL DEFAULT '';
ALTER TABLE guilds ADD COLUMN IF NOT EXISTS kind text NOT NULL DEFAULT 'community';
ALTER TABLE guilds ADD COLUMN IF NOT EXISTS dm_key text;
ALTER TABLE guilds ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='guilds_kind_chk') THEN
  ALTER TABLE guilds ADD CONSTRAINT guilds_kind_chk CHECK(kind IN ('community','dm'));
 END IF;
END $$;
-- One canonical 1:1 conversation per user pair (sorted user IDs). Group DMs have no key.
CREATE UNIQUE INDEX IF NOT EXISTS guilds_dm_key_idx ON guilds(dm_key) WHERE dm_key IS NOT NULL;

ALTER TABLE guild_members ADD COLUMN IF NOT EXISTS nickname text;
ALTER TABLE guild_members ADD COLUMN IF NOT EXISTS joined_at timestamptz NOT NULL DEFAULT now();
CREATE INDEX IF NOT EXISTS guild_members_user_idx ON guild_members(user_id);

-- Channels: topic, ordering and one level of categories.
ALTER TABLE channels ADD COLUMN IF NOT EXISTS topic text NOT NULL DEFAULT '';
ALTER TABLE channels ADD COLUMN IF NOT EXISTS position integer NOT NULL DEFAULT 0;
ALTER TABLE channels ADD COLUMN IF NOT EXISTS parent_id uuid REFERENCES channels(id) ON DELETE SET NULL;
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='channels_kind_chk') THEN
  ALTER TABLE channels ADD CONSTRAINT channels_kind_chk CHECK(kind IN ('encrypted_text','announcement','category'));
 END IF;
END $$;
CREATE INDEX IF NOT EXISTS channels_guild_idx ON channels(guild_id,position,created_at);

-- Roles. Permissions are a Nexora-native 64-bit field (see apps/api/src/permissions.ts).
CREATE TABLE IF NOT EXISTS guild_roles (
 id uuid PRIMARY KEY,
 guild_id uuid NOT NULL REFERENCES guilds(id) ON DELETE CASCADE,
 name text NOT NULL CHECK(length(name) BETWEEN 1 AND 100),
 color integer NOT NULL DEFAULT 0 CHECK(color BETWEEN 0 AND 16777215),
 permissions bigint NOT NULL DEFAULT 0,
 position integer NOT NULL DEFAULT 0,
 hoist boolean NOT NULL DEFAULT false,
 is_default boolean NOT NULL DEFAULT false,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS guild_roles_guild_idx ON guild_roles(guild_id,position);
CREATE UNIQUE INDEX IF NOT EXISTS guild_roles_default_idx ON guild_roles(guild_id) WHERE is_default;
CREATE TABLE IF NOT EXISTS guild_member_roles (
 guild_id uuid NOT NULL,
 user_id uuid NOT NULL,
 role_id uuid NOT NULL REFERENCES guild_roles(id) ON DELETE CASCADE,
 PRIMARY KEY(guild_id,user_id,role_id),
 FOREIGN KEY(guild_id,user_id) REFERENCES guild_members(guild_id,user_id) ON DELETE CASCADE
);
-- Every existing community receives an @everyone role with the default permission set
-- (CREATE_INVITE | CHANGE_NICKNAME | SEND_MESSAGES | ADD_REACTIONS = 3392).
INSERT INTO guild_roles(id,guild_id,name,permissions,position,is_default)
SELECT g.id,g.id,'@everyone',3392,0,true FROM guilds g
WHERE NOT EXISTS (SELECT 1 FROM guild_roles r WHERE r.guild_id=g.id AND r.is_default);

-- Moderation.
CREATE TABLE IF NOT EXISTS guild_bans (
 guild_id uuid NOT NULL REFERENCES guilds(id) ON DELETE CASCADE,
 user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 reason text NOT NULL DEFAULT '' CHECK(length(reason)<=512),
 banned_by uuid REFERENCES users(id) ON DELETE SET NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(guild_id,user_id)
);
CREATE TABLE IF NOT EXISTS guild_audit_log (
 id bigserial PRIMARY KEY,
 guild_id uuid NOT NULL REFERENCES guilds(id) ON DELETE CASCADE,
 actor_id uuid REFERENCES users(id) ON DELETE SET NULL,
 action text NOT NULL,
 target_id text,
 details jsonb NOT NULL DEFAULT '{}'::jsonb,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS guild_audit_log_guild_idx ON guild_audit_log(guild_id,id DESC);
-- Invite metadata for management lists. Codes themselves are still stored only as hashes.
ALTER TABLE guild_invites ADD COLUMN IF NOT EXISTS created_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE guild_invites ADD COLUMN IF NOT EXISTS code_hint text NOT NULL DEFAULT '';

-- Messages: edits, replies, reactions and pins. Reaction emoji are visible metadata.
ALTER TABLE messages ADD COLUMN IF NOT EXISTS edited_at timestamptz;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS reply_to uuid;
CREATE TABLE IF NOT EXISTS message_reactions (
 message_id uuid NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
 user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 emoji text NOT NULL CHECK(length(emoji) BETWEEN 1 AND 32),
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(message_id,user_id,emoji)
);
CREATE INDEX IF NOT EXISTS message_reactions_message_idx ON message_reactions(message_id);
CREATE TABLE IF NOT EXISTS message_pins (
 channel_id uuid NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
 message_id uuid NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
 pinned_by uuid REFERENCES users(id) ON DELETE SET NULL,
 pinned_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(channel_id,message_id)
);
CREATE TABLE IF NOT EXISTS channel_read_states (
 user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 channel_id uuid NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
 last_read_at timestamptz NOT NULL DEFAULT now(),
 last_message_id uuid,
 PRIMARY KEY(user_id,channel_id)
);

-- Social graph: one row per direction. Friendship is two 'friend' rows.
CREATE TABLE IF NOT EXISTS user_relationships (
 user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 target_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 status text NOT NULL CHECK(status IN ('friend','outgoing','incoming','blocked')),
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(user_id,target_id),
 CHECK(user_id<>target_id)
);
CREATE INDEX IF NOT EXISTS user_relationships_target_idx ON user_relationships(target_id);

-- Presence: user-selected status plus a heartbeat-maintained last-seen time.
ALTER TABLE user_profiles ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'online';
ALTER TABLE user_profiles ADD COLUMN IF NOT EXISTS custom_status text NOT NULL DEFAULT '';
ALTER TABLE user_profiles ADD COLUMN IF NOT EXISTS accent_color integer NOT NULL DEFAULT 7331258;
CREATE TABLE IF NOT EXISTS user_presence (
 user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 last_seen timestamptz NOT NULL DEFAULT now()
);

-- Multi-device key distribution: full signed public bundles (the fingerprint remains
-- in identity_key), and a single creator claim per channel epoch so concurrent members
-- cannot fork a room key. key_commitment is an HMAC of the room key, not the key.
ALTER TABLE user_devices ADD COLUMN IF NOT EXISTS public_bundle jsonb;
CREATE TABLE IF NOT EXISTS channel_epoch_keys (
 channel_id uuid NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
 epoch bigint NOT NULL CHECK(epoch>0),
 creator_device_id uuid NOT NULL REFERENCES user_devices(id) ON DELETE CASCADE,
 key_commitment text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(channel_id,epoch)
);
ALTER TABLE channel_device_keys ADD COLUMN IF NOT EXISTS granted_by uuid REFERENCES user_devices(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS channel_device_keys_device_idx ON channel_device_keys(device_id,channel_id);

-- Guild deletion cascades into guild_members; the epoch trigger must not recreate a
-- key-epoch row for a community that no longer exists (FK violation).
CREATE OR REPLACE FUNCTION nexora_bump_membership_epoch() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM guilds WHERE id=COALESCE(NEW.guild_id,OLD.guild_id)) THEN RETURN NULL; END IF;
 INSERT INTO guild_key_epochs(guild_id,epoch) VALUES(COALESCE(NEW.guild_id,OLD.guild_id),2)
 ON CONFLICT(guild_id) DO UPDATE SET epoch=guild_key_epochs.epoch+1;
 RETURN NULL;
END $$;

-- ===== 0009 P0 security (kept in sync with database/migrations/0009_p0_security.sql) =====
-- 0009: P0 security — instance administration, suspension, abuse reports, device
-- cross-signing (attestations), encrypted room-key backups and WebAuthn passkeys.
-- Idempotent: safe to apply more than once.

ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin boolean NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS suspended_at timestamptz;
ALTER TABLE users ADD COLUMN IF NOT EXISTS suspension_reason text NOT NULL DEFAULT '';

-- Abuse reports. Message content is end-to-end encrypted, so evidence is whatever the
-- reporter chooses to disclose from their own decrypted view (and is labelled as such).
CREATE TABLE IF NOT EXISTS abuse_reports (
 id uuid PRIMARY KEY,
 reporter_id uuid REFERENCES users(id) ON DELETE SET NULL,
 target_type text NOT NULL CHECK(target_type IN ('message','user','guild')),
 target_id uuid NOT NULL,
 guild_id uuid,
 reason text NOT NULL CHECK(length(reason) BETWEEN 1 AND 1000),
 evidence text NOT NULL DEFAULT '' CHECK(length(evidence)<=4000),
 status text NOT NULL DEFAULT 'open' CHECK(status IN ('open','resolved','dismissed')),
 resolved_by uuid REFERENCES users(id) ON DELETE SET NULL,
 resolution_note text NOT NULL DEFAULT '',
 created_at timestamptz NOT NULL DEFAULT now(),
 resolved_at timestamptz
);
CREATE INDEX IF NOT EXISTS abuse_reports_status_idx ON abuse_reports(status,created_at DESC);

-- Device cross-signing: a device added to an account with existing devices must be
-- attested (signed) by one of that account's existing devices before others trust it.
ALTER TABLE user_devices ADD COLUMN IF NOT EXISTS attestation jsonb;

-- Encrypted room-key backup: opaque ciphertext under a client-held recovery key.
CREATE TABLE IF NOT EXISTS user_key_backups (
 user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 version integer NOT NULL CHECK(version>0),
 ciphertext text NOT NULL CHECK(length(ciphertext)<=4000000),
 updated_at timestamptz NOT NULL DEFAULT now()
);

-- WebAuthn passkeys (ES256 only) and single-use ceremony challenges.
CREATE TABLE IF NOT EXISTS webauthn_credentials (
 id text PRIMARY KEY,
 user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 name text NOT NULL DEFAULT 'Passkey',
 public_key jsonb NOT NULL,
 sign_count bigint NOT NULL DEFAULT 0,
 created_at timestamptz NOT NULL DEFAULT now(),
 last_used_at timestamptz
);
CREATE INDEX IF NOT EXISTS webauthn_credentials_user_idx ON webauthn_credentials(user_id);
CREATE TABLE IF NOT EXISTS webauthn_challenges (
 challenge text PRIMARY KEY,
 user_id uuid REFERENCES users(id) ON DELETE CASCADE,
 kind text NOT NULL CHECK(kind IN ('register','login')),
 expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS webauthn_challenges_expiry_idx ON webauthn_challenges(expires_at);
