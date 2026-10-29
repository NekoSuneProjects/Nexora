import test from "node:test";import assert from "node:assert/strict";import{readFile}from"node:fs/promises";
test("bot installations are guild scoped with explicit opt-in permission",async()=>{
 const sql=await readFile(new URL("../database/schema.sql",import.meta.url),"utf8");
 assert.match(sql,/CREATE TABLE IF NOT EXISTS guild_bots/);
 assert.match(sql,/can_read_events boolean NOT NULL DEFAULT false/);
 assert.match(sql,/PRIMARY KEY\(guild_id,app_id\)/);
});
test("bot installation validates guild ownership and owned application",async()=>{
 const api=await readFile(new URL("../apps/api/src/index.ts",import.meta.url),"utf8");
 assert.match(api,/Only community owners may install bots/);
 assert.match(api,/owner_id=\$2 AND revoked_at IS NULL/);
});
