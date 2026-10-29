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
 INSERT INTO guild_key_epochs(guild_id,epoch) VALUES(COALESCE(NEW.guild_id,OLD.guild_id),2)
 ON CONFLICT(guild_id) DO UPDATE SET epoch=guild_key_epochs.epoch+1;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS nexora_epoch_on_join ON guild_members;
CREATE TRIGGER nexora_epoch_on_join AFTER INSERT ON guild_members FOR EACH ROW EXECUTE FUNCTION nexora_bump_membership_epoch();
DROP TRIGGER IF EXISTS nexora_epoch_on_leave ON guild_members;
CREATE TRIGGER nexora_epoch_on_leave AFTER DELETE ON guild_members FOR EACH ROW EXECUTE FUNCTION nexora_bump_membership_epoch();
