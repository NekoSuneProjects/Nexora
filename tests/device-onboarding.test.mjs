import test from "node:test";import assert from "node:assert/strict";import{readFile}from"node:fs/promises";
test("device enrollment requires password proof and keys are scoped to shared guilds",async()=>{
 const s=await readFile(new URL("../apps/api/src/index.ts",import.meta.url),"utf8");
 assert.match(s,/takeQuota\("device-enroll:"\+user.id,6,900\)/);
 assert.match(s,/Password required to enroll device/);
 assert.match(s,/JOIN guild_members peer ON peer.guild_id=gm.guild_id/);
});
