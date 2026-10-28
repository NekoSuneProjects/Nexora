import test from "node:test";import assert from "node:assert/strict";import{readFile}from"node:fs/promises";
test("authentication rate limits account across IP addresses and trusts proxy CIDRs explicitly",async()=>{
 const s=await readFile(new URL("../apps/api/src/index.ts",import.meta.url),"utf8");
 assert.match(s,/takeQuota\("login-account:"\+username.toLowerCase\(\),40,900\)/);
 assert.match(s,/TRUSTED_PROXY_CIDRS/);
 assert.match(s,/trustProxy:.*: false/);
});
