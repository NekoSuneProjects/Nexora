
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
