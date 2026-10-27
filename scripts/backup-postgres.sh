#!/usr/bin/env bash
set -euo pipefail
: "${DATABASE_URL:?Set DATABASE_URL to a PostgreSQL connection string}"
: "${BACKUP_DIR:?Set BACKUP_DIR to a protected destination}"
umask 077
mkdir -p -- "$BACKUP_DIR"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
output="$BACKUP_DIR/nexora-$stamp.dump"
partial="$output.partial"
trap 'rm -f -- "$partial"' EXIT
pg_dump --dbname="$DATABASE_URL" --format=custom --no-owner --no-acl --file="$partial"
pg_restore --list "$partial" >/dev/null
mv -- "$partial" "$output"
trap - EXIT
printf 'Verified PostgreSQL archive: %s\n' "$output"
