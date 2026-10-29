import test from "node:test";import assert from "node:assert/strict";import{readFile}from"node:fs/promises";
test("bot gateway emits only message metadata with per-event authorization",async()=>{
 const api=await readFile(new URL("../apps/api/src/index.ts",import.meta.url),"utf8");
 const start=api.indexOf("async function broadcastBotMetadata");const end=api.indexOf("const botSocketApplication",start);
 const slice=api.slice(start,end);
 assert.match(slice,/b.can_read_events=true AND a.revoked_at IS NULL/);
 assert.match(slice,/MESSAGE_METADATA_CREATE/);
 assert.doesNotMatch(slice,/ciphertext|algorithm/);
});
test("bot Gateway requires hashed token lookup",async()=>{
 const api=await readFile(new URL("../apps/api/src/index.ts",import.meta.url),"utf8");
 assert.match(api,/app.get\("\/bot-gateway"/);
 assert.match(api,/hashToken\(raw\)/);
});
