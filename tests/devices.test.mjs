import test from "node:test";import assert from "node:assert/strict";import {readFile} from "node:fs/promises";
test("device schema contains public keys and revocation, not private keys",async()=>{
 const schema=await readFile(new URL("../database/schema.sql",import.meta.url),"utf8");
 const table=schema.slice(schema.indexOf("CREATE TABLE IF NOT EXISTS user_devices"));
 assert.match(table,/identity_key text NOT NULL/);assert.match(table,/revoked_at timestamptz/);assert.doesNotMatch(table,/private_key/);
});
test("device deletion limited to authenticated record owner",async()=>{
 const api=await readFile(new URL("../apps/api/src/index.ts",import.meta.url),"utf8");
 assert.match(api,/UPDATE user_devices SET revoked_at=now\(\) WHERE id=\$1 AND user_id=\$2/);
});
