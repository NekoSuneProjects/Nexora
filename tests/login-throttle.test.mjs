import test from "node:test";import assert from "node:assert/strict";import {readFile} from "node:fs/promises";
test("login requests use shared PostgreSQL quotas keyed by Fastify IP and username",async()=>{
 const api=await readFile(new URL("../apps/api/src/index.ts",import.meta.url),"utf8");
 assert.match(api,/takeQuota\("login:"\+request.ip\+":"\+username.toLowerCase\(\),7,900\)/);
 assert.match(api,/ON CONFLICT\(key_hash\) DO UPDATE/);
 assert.match(api,/reply.code\(429\)/);
});
