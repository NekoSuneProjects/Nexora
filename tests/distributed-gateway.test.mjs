import test from "node:test";import assert from "node:assert/strict";import{readFile}from"node:fs/promises";
test("distributed Gateway uses PG notifications and checks authorization on delivery",async()=>{
 const api=await readFile(new URL("../apps/api/src/index.ts",import.meta.url),"utf8");
 assert.match(api,/LISTEN nexora_security/);
 assert.match(api,/pg_notify\('nexora_security'/);
 assert.match(api,/s.token_hash=\$1 AND s.user_id=\$2 AND s.expires_at>now\(\) AND c.id=\$3/);
 for(const kind of ["session","bot","member","message"])assert.ok(api.includes('kind:"'+kind+'"'));
});
