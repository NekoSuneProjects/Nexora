import test from "node:test";import assert from "node:assert/strict";import{readFile}from"node:fs/promises";
test("API establishes Origin policy, baseline browser security headers and sensitive log redaction",async()=>{
 const s=await readFile(new URL("../apps/api/src/index.ts",import.meta.url),"utf8");
 assert.match(s,/Cross-origin requests are disabled/);
 assert.match(s,/PUBLIC_BASE_URL/);
 for(const header of ["Content-Security-Policy","X-Content-Type-Options","Referrer-Policy","X-Frame-Options"])assert.ok(s.includes(header));
 assert.match(s,/req.headers.authorization/);
 assert.match(s,/req.body.password/);
});
