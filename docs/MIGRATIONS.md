# PostgreSQL migration ledger

Run `DATABASE_URL=... bash scripts/migrate.sh` after bootstrapping fresh databases using `database/schema.sql`. This runner applies migrations in numeric order, stores SHA-256 checksums in `schema_migrations`, and records each migration transactionally using a PostgreSQL advisory transaction lock.

**Existing installations:** Apply a one-time baseline/ledger reconciliation under a maintenance window. The earlier CI and deployment flow applied migrations manually. Before running this runner on an upgraded database, inspect schema differences; migrations are repeatable but may reapply DDL unnecessarily. Do not auto-baseline unknown production schemas.

**Concurrency limitation:** The current runner checks the ledger before acquiring the per-file transaction lock. Simultaneous runner processes may both observe an unapplied migration and one will fail on the ledger's primary-key constraint; the transaction rolls back cleanly. Retry after the other deployment finishes. Use one migration runner per deployment for deterministic rollout.

Back up first, run on staging, inspect checksums and never rewrite historical migration files once applied.
