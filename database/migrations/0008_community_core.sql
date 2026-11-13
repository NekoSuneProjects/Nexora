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

-- Trigger-originated security events now carry their outbox row ID in the notification,
-- so the periodic catch-up replay does not deliver them a second time (stale replays could
-- otherwise evict a member who had already rejoined).
CREATE OR REPLACE FUNCTION nexora_emit_security_event(event jsonb) RETURNS void LANGUAGE plpgsql AS $$
DECLARE new_id bigint;
BEGIN
 INSERT INTO security_events(payload) VALUES(event) RETURNING id INTO new_id;
 PERFORM pg_notify('nexora_security',(event||jsonb_build_object('_id',new_id::text))::text);
END $$;
CREATE OR REPLACE FUNCTION nexora_notify_security_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
 IF TG_TABLE_NAME = 'sessions' AND TG_OP = 'DELETE' THEN
  PERFORM nexora_emit_security_event(jsonb_build_object('kind','session','user',OLD.user_id,'hash',OLD.token_hash));
 ELSIF TG_TABLE_NAME = 'developer_apps' THEN
  IF TG_OP = 'DELETE' OR (TG_OP = 'UPDATE' AND
      (OLD.bot_token_hash IS DISTINCT FROM NEW.bot_token_hash OR OLD.revoked_at IS DISTINCT FROM NEW.revoked_at)) THEN
   PERFORM nexora_emit_security_event(jsonb_build_object('kind','bot','app',OLD.id));
  END IF;
 ELSIF TG_TABLE_NAME = 'guild_members' AND TG_OP = 'DELETE' THEN
  PERFORM nexora_emit_security_event(jsonb_build_object('kind','member','user',OLD.user_id,'guild',OLD.guild_id));
 ELSIF TG_TABLE_NAME = 'guild_bots' AND (TG_OP = 'DELETE' OR (TG_OP = 'UPDATE' AND OLD.can_read_events = true AND NEW.can_read_events = false)) THEN
  PERFORM nexora_emit_security_event(jsonb_build_object('kind','bot_uninstall','app',OLD.app_id,'guild',OLD.guild_id));
 END IF;
 RETURN NULL;
END $$;
