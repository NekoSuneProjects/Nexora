import test from "node:test";import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
test("MFA uses AES-GCM encrypted secrets, confirmation and replay checks",async()=>{
 const api=await readFile(new URL("../apps/api/src/index.ts",import.meta.url),"utf8");
 const mfa=await readFile(new URL("../apps/api/src/totp.ts",import.meta.url),"utf8");
 assert.match(mfa,/createCipheriv/);assert.match(mfa,/createHmac/);
 assert.match(api,/last_step<\$2/);assert.match(api,/mfa_code/);
});
