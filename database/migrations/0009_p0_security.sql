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
