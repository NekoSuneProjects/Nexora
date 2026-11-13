import test from "node:test";import assert from "node:assert/strict";import {readFile} from "node:fs/promises";
test("bot Gateway closes revoked credentials and rechecks subscription token hash",async()=>{
 const s=await readFile(new URL("../apps/api/src/index.ts",import.meta.url),"utf8");
 const bot=s.slice(s.indexOf('app.get("/bot-gateway"'),s.indexOf('app.get("/gateway"'));
 assert.match(bot,/Bot token revoked/);
 assert.match(bot,/SELECT 1 FROM developer_apps WHERE id=\$1 AND bot_token_hash=\$2 AND revoked_at IS NULL/);
 assert.match(bot,/AND a.bot_token_hash=\$3/);
 assert.match(bot,/checkingCredential=true/);
});
