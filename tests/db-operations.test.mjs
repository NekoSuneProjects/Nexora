import test from "node:test";import assert from "node:assert/strict";import{readFile}from"node:fs/promises";
test("database provides guarded integrity migration and non-message retention maintenance",async()=>{
 const migration=await readFile(new URL("../database/migrations/0002_integrity.sql",import.meta.url),"utf8");
 const cleanup=await readFile(new URL("../database/maintenance.sql",import.meta.url),"utf8");
 const backup=await readFile(new URL("../scripts/backup-postgres.sh",import.meta.url),"utf8");
 for(const x of ["guild_invites_uses_bound_chk","messages_algorithm_chk","messages_ciphertext_not_empty_chk"])assert.ok(migration.includes(x));
 assert.match(cleanup,/DELETE FROM sessions WHERE expires_at/);
 assert.doesNotMatch(cleanup,/DELETE FROM messages/);
 assert.match(backup,/pg_dump/);assert.match(backup,/pg_restore --list/);
});
