import test from "node:test";import assert from "node:assert/strict";import{readFile}from"node:fs/promises";
test("bot channel discovery uses explicit install permission and excludes revoked app",async()=>{
 const api=await readFile(new URL("../apps/api/src/index.ts",import.meta.url),"utf8");
 assert.match(api,/b.can_read_events=true/);
 assert.match(api,/a.revoked_at IS NULL AND b.guild_id=\$2/);
 assert.match(api,/SELECT id,name,kind FROM channels WHERE guild_id=\$1/);
});
