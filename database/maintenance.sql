-- Safe repeatable cleanup for transient data. Run only with operator approval.
-- Does NOT delete message ciphertext. Retention must be a separate policy.
BEGIN;
DELETE FROM sessions WHERE expires_at < now();
DELETE FROM guild_invites WHERE expires_at < now();
DELETE FROM auth_rate_limits WHERE expires_at < now();
-- The security/dispatch outbox only needs to cover listener outages; API instances replay
-- from their start-up cursor, so rows older than a day are no longer needed.
DELETE FROM security_events WHERE created_at < now() - interval '1 day';
DELETE FROM user_presence WHERE last_seen < now() - interval '30 days';
DELETE FROM webauthn_challenges WHERE expires_at < now();
COMMIT;
