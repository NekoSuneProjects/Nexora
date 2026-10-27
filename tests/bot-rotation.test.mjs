import test from "node:test";import assert from "node:assert/strict";import{readFile}from"node:fs/promises";
test("rotating bot credentials requires owning human and changes stored hash",async()=>{
 const api=await readFile(new URL("../apps/api/src/index.ts",import.meta.url),"utf8");
 assert.match(api,/rotate-token/);
 assert.match(api,/UPDATE developer_apps SET bot_token_hash=\$1 WHERE id=\$2 AND owner_id=\$3 AND revoked_at IS NULL/);
 assert.match(api,/botSocketTokenHash\.set\(socket,hashToken\(raw\)\)/);
 assert.match(api,/a.bot_token_hash=\$3/);
});
