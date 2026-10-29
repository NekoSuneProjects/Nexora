import test from "node:test";import assert from "node:assert/strict";import{readFile}from"node:fs/promises";
test("authorized deletions atomically persist ciphertext-free tombstones",async()=>{
 const sql=await readFile(new URL("../database/migrations/0006_message_tombstones.sql",import.meta.url),"utf8");
 const api=await readFile(new URL("../apps/api/src/index.ts",import.meta.url),"utf8");
 assert.match(sql,/CREATE TABLE IF NOT EXISTS message_tombstones/);
 assert.doesNotMatch(sql,/ciphertext/);
 assert.match(api,/INSERT INTO message_tombstones/);
 assert.match(api,/\/api\/v10\/channels\/:id\/deletions/);
});
