#!/usr/bin/env bash
set -euo pipefail
: "${DATABASE_URL:?DATABASE_URL required}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Use a database-level lock, not per-session locks: psql connections are separate.
# Disallow concurrent migration runners via PostgreSQL advisory lock in one session.
# All file contents are fixed repository files; never source SQL paths from user input.
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 <<'SQL'
CREATE TABLE IF NOT EXISTS schema_migrations (
 version text PRIMARY KEY,
 applied_at timestamptz NOT NULL DEFAULT now(),
 checksum text NOT NULL
);
SQL
for file in "$ROOT"/database/migrations/[0-9][0-9][0-9][0-9]_*.sql; do
 [ -f "$file" ] || continue
 version="$(basename "$file" .sql)"
 checksum="$(sha256sum "$file" | cut -d' ' -f1)"
 prior="$(psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -Atc "SELECT checksum FROM schema_migrations WHERE version='$version'")"
 if [ -n "$prior" ]; then
  if [ "$prior" != "$checksum" ]; then echo "Migration checksum mismatch: $version" >&2; exit 1; fi
  echo "Already applied $version"
  continue
 fi
 # The runner holds an exclusive cross-process lock using an explicit session.
 # psql single-session BEGIN/COMMIT ensures schema and ledger are committed together.
 { printf 'BEGIN;\nSELECT pg_advisory_xact_lock(841745923);\n';
   printf "\\i '%s'\n" "$file";
   printf "INSERT INTO schema_migrations(version,checksum) VALUES('%s','%s');\nCOMMIT;\n" "$version" "$checksum";
 } | psql "$DATABASE_URL" -v ON_ERROR_STOP=1
 echo "Applied $version"
done
