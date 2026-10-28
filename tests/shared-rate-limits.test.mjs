import test from "node:test";import assert from "node:assert/strict";import {readFile} from "node:fs/promises";
test("auth quotas use atomic shared PostgreSQL counters",async()=>{
 const api=await readFile(new URL("../apps/api/src/index.ts",import.meta.url),"utf8");
 const schema=await readFile(new URL("../database/schema.sql",import.meta.url),"utf8");
 assert.match(api,/ON CONFLICT\(key_hash\) DO UPDATE/);
 assert.match(api,/takeQuota\("registration:"\+request.ip,5,3600\)/);
 assert.match(api,/takeQuota\("login:"\+request.ip/);
 assert.match(schema,/CREATE TABLE IF NOT EXISTS auth_rate_limits/);
});

test("IP-wide shared login budget and bounded scrypt admission are present",async()=>{
 const api=await readFile(new URL("../apps/api/src/index.ts",import.meta.url),"utf8");
 assert.match(api,/takeQuota\("login-ip:"\+request.ip,60,900\)/);
 assert.match(api,/activeKdf>=MAX_ACTIVE_KDF/);
 assert.match(api,/finally\{activeKdf--\}/);
});
