# Nexora PostgreSQL audit, migrations and recovery runbook

**Status:** Source-level review and operator procedure, not an executed restore drill or certified SQL audit.

## Findings
- SQL queries reviewed in `apps/api/src/index.ts` predominantly use parameterized `pg` placeholders; do not introduce interpolated SQL for identifiers or values. Audit each future query in code review.
- The invite redemption transaction locks the invite row, but concurrent membership changes, message writes and multi-instance notifications need serializability/TOCTOU testing. Message writes currently check membership separately from their INSERT (race: removal may occur between checks).
- `messages.author_id` references `users` without a deletion strategy; deleting users can be blocked by messages. Document account erasure/tombstoning before implementing user deletion.
- Message data has **no approved retention/deletion implementation** and opaque ciphertext may still expose metadata. Do not automatically expire messages until product privacy and legal requirements are set.
- A removed member can still hold old ciphertext and previously received room keys. Database deletion alone cannot revoke cryptographic access.
- The original `database/schema.sql` provisions a new instance; future schema changes must use versioned migration files rather than editing the bootstrap schema alone.

## Migration and deploy procedure
1. Take a verified backup and record its filename, database version, deployed commit and maintenance window.
2. Provision schema on an empty DB with `psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f database/schema.sql`.
3. Apply incremental migrations in order: `psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -1 -f database/migrations/0002_integrity.sql`. This migration uses idempotent guards; **do not** interpret that as a complete migration ledger.
4. On a running system apply only the outstanding migrations and first inspect existing rows for new constraint violations. Use staged deploys for blocking DDL.
5. Verify indexes, constraints, API health, session creation and channel reads, then start instances.
6. **Rollback:** there is no automatically safe down-migration for data/constraint changes. Stop writers and restore the pre-migration backup to a separate DB, test it, and switch over under a recovery plan.

## Backup and recovery
- On an operator-controlled host run `DATABASE_URL=... BACKUP_DIR=/protected/nexora-backups bash scripts/backup-postgres.sh`. This writes a custom-format `pg_dump` archive with restrictive permissions and validates its archive TOC. **This is not a restore test**.
- Encrypt archives with an approved operator-managed solution, store them off-host with restricted access, and rotate/retain backups to a documented schedule. Backup filenames and operational logs should not contain credentials.
- **Restore drill (on an isolated disposable database only):** `createdb nexora_restore_test`; run `pg_restore --dbname="$RESTORE_DATABASE_URL" --no-owner --no-acl --exit-on-error /protected/nexora-backups/FILE.dump`, where `RESTORE_DATABASE_URL` points to the *isolated* database. Never point restore at production. Verify row counts, schema indexes/constraints, bot installations and sample API behavior.
- Record RPO (interval between successful backups), RTO (timed restore), checksums and operator sign-off from a real drill. Confirm that saved secrets and object storage are handled independently.

## Retention and deletion
- `database/maintenance.sql` deletes expired sessions, invites and auth quota counters only. Schedule after manual staging verification. No automatic ciphertext/message deletion.
- Decide organization-specific message retention, owner/author deletion permissions, moderation/audit events, tombstones, bot event replay boundaries, encrypted backups and legal hold before shipping deletion APIs.
- A message deletion API must atomically enforce channel membership and author/moderator privilege, delete or tombstone by UUID, and synchronize websocket/bot deletion metadata across instances. Audit/backups and device-held ciphertext remain independent copies.
- Before running cleanup in production, snapshot the database and test that active sessions/invites survive.

## Remaining blockers
Versioned migration ledger/locking, upgrade-from-old-schema CI, real isolated restore drill, message lifecycle semantics, cross-instance race tests, automated backup encryption and retention policy sign-off.

## Implemented author-only message deletion (incremental)
The API now exposes `DELETE /api/v10/channels/:id/messages/:messageId`. A parameterized atomic `DELETE` requires matching author, message/channel relationship and current community membership; other users, other channels and already deleted messages return 404. On success, a PostgreSQL notification emits `MESSAGE_DELETE` with IDs only to currently authorized connected user Gateway sessions (no ciphertext). The database integration suite covers author-only deletion and idempotent failure.

**Limitations:** This is physical deletion from the live `messages` table, not guaranteed erasure from existing backups, cached clients or previously copied ciphertext. A durable deletion log/tombstone, replay for offline clients, moderation deletion privileges, retention-policy sign-off and multi-instance deletion tests are still required.

## CI restore evidence
CI now takes a PostgreSQL custom-format dump after integration tests and restores it into an independent `nexora_restore_ci` database. The workflow verifies the restored user table and messages table existence. This is an isolated, disposable CI drill; it does not replace encrypted off-site backup management, production-sized restore rehearsal, RPO/RTO measurement or incident response testing.

## Message tombstones and offline reconciliation
A deleted message now creates a metadata-only tombstone inside the same PostgreSQL transaction that deletes the ciphertext. The authenticated endpoint `GET /api/v10/channels/:id/deletions?after=<ISO timestamp>` returns up to 100 tombstones to current community members. No ciphertext is preserved in the tombstone, and cross-community reads return 403. Cursor pagination must include the last timestamp with care: multiple deletions at the same timestamp may require a composite cursor in a later version. The tombstone lifetime is currently indefinite, pending an approved retention/legal-hold policy. Backup snapshots and clients may retain older copies of ciphertext.
