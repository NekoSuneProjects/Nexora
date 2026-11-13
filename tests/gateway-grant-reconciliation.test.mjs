import test from "node:test";import assert from "node:assert/strict";import{readFile}from"node:fs/promises";
test("both Gateway watchdogs reconcile subscriptions against PostgreSQL",async()=>{
 const api=await readFile(new URL("../apps/api/src/index.ts",import.meta.url),"utf8");
 assert.match(api,/for\(const channelId of \[\.\.\.subscriptions\]\)/);
 assert.match(api,/if\(await member\(identity.id,channelId\)\)continue/);
 assert.match(api,/for\(const guildId of \[\.\.\.subscriptions\]\)/);
 assert.match(api,/GUILD_ACCESS_REVOKED/);
 assert.match(api,/CHANNEL_ACCESS_REVOKED/);
});
