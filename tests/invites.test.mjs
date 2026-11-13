import test from "node:test";import assert from "node:assert/strict";import { readFile } from "node:fs/promises";
test("invites have expiration and usage bound",async()=>{
 const sql=await readFile(new URL("../database/schema.sql",import.meta.url),"utf8");
 assert.match(sql,/expires_at timestamptz NOT NULL/);
 assert.match(sql,/CHECK\(max_uses BETWEEN 1 AND 100\)/);
});
test("invites are hashed and consumed inside a locked transaction",async()=>{
 const api=await readFile(new URL("../apps/api/src/index.ts",import.meta.url),"utf8");
 assert.match(api,/hashToken\(code\)/);
 assert.match(api,/FOR UPDATE/);
 assert.match(api,/ON CONFLICT DO NOTHING RETURNING user_id/);
});
