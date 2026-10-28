# Commit-scoped security invalidation

Versioned migration `0003_security_notifications.sql` adds PostgreSQL AFTER triggers for session deletion, bot token rotation/revocation, membership deletion and bot uninstall or permission downgrade. Notifications reach all listening API instances **only after database commit**, including changes initiated outside the API. This removes the authorization-state-versus-notification gap for these operations when listeners are connected, while explicit route notifications remain for compatibility.

Apply in sequence after `0002_integrity.sql` using `psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -1 -f database/migrations/0003_security_notifications.sql`. CI applies the migration twice to test idempotency.

**Open issues:** LISTEN/NOTIFY is best-effort and has no replay. After listener outages, stale subscriptions must be revalidated; implement an outbox and reconnect reconciliation before a production security guarantee. Notifications reveal identifiers to database clients with LISTEN privilege, so use a least-privilege database account and isolate connection strings. A real multi-instance disconnect/rollback test is still required.
