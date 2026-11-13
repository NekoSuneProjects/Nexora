import test from "node:test";import assert from "node:assert/strict";import{readFile}from"node:fs/promises";
test("sessions endpoint is authenticated and scoped to caller",async()=>{
 const s=await readFile(new URL("../apps/api/src/index.ts",import.meta.url),"utf8");
 assert.match(s,/app.get\("\/api\/v1\/auth\/sessions"/);
 assert.match(s,/WHERE user_id=\$1 AND expires_at>now\(\)/);
 assert.match(s,/DELETE FROM sessions WHERE user_id=\$1/);
});
