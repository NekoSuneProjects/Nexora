CREATE TABLE IF NOT EXISTS user_mfa (user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, secret_enc text NOT NULL, enabled boolean NOT NULL DEFAULT false, last_step bigint NOT NULL DEFAULT -1);

CREATE TABLE IF NOT EXISTS mfa_recovery_codes (user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,code_hash text NOT NULL,PRIMARY KEY(user_id,code_hash));
