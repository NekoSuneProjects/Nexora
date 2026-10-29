-- Safe repeatable cleanup for transient data. Run only with operator approval.
-- Does NOT delete message ciphertext. Retention must be a separate policy.
BEGIN;
DELETE FROM sessions WHERE expires_at < now();
DELETE FROM guild_invites WHERE expires_at < now();
DELETE FROM auth_rate_limits WHERE expires_at < now();
COMMIT;
