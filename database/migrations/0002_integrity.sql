-- Nexora incremental migration 0002: integrity constraints and retention indexes.
-- Apply with psql -v ON_ERROR_STOP=1 -1 -f database/migrations/0002_integrity.sql
-- Existing data violating a check must be repaired before application.
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='guild_invites_uses_bound_chk') THEN
  ALTER TABLE guild_invites ADD CONSTRAINT guild_invites_uses_bound_chk CHECK(uses <= max_uses);
 END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='messages_ciphertext_not_empty_chk') THEN
  ALTER TABLE messages ADD CONSTRAINT messages_ciphertext_not_empty_chk CHECK(length(ciphertext)>0);
 END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='messages_algorithm_chk') THEN
  ALTER TABLE messages ADD CONSTRAINT messages_algorithm_chk CHECK(algorithm='client-encrypted-v1');
 END IF;
END $$;
CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS guild_invites_expiry_idx ON guild_invites(expires_at);
CREATE INDEX IF NOT EXISTS messages_created_idx ON messages(created_at,id);
