import test from "node:test";import assert from "node:assert/strict";import{readFile}from"node:fs/promises";
test("invite, membership and bot revocation hardening",async()=>{
 const s=await readFile(new URL("../apps/api/src/index.ts",import.meta.url),"utf8");
 assert.match(s,/takeQuota\("invite-ip:"\+request.ip,30,3600\)/);
 assert.match(s,/takeQuota\("invite-user:"\+user.id,30,3600\)/);
 assert.match(s,/DELETE FROM guild_members gm USING guilds g/);
 assert.match(s,/g.owner_id<>gm.user_id/);
 assert.match(s,/kind:"bot_uninstall"/);
 assert.match(s,/GUILD_ACCESS_REVOKED/);
});
