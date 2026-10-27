import test from "node:test";import assert from "node:assert/strict";import{readFile}from"node:fs/promises";
test("bot event history is scoped, cursor checked, and metadata only",async()=>{
 const api=await readFile(new URL("../apps/api/src/index.ts",import.meta.url),"utf8");
 const part=api.slice(api.indexOf('app.get("/api/v1/bots/guilds/:id/events"'),api.indexOf('app.get("/api/v10/users/@me"'));
 assert.match(part,/b.can_read_events=true/);
 assert.match(part,/c.guild_id=\$2/);
 assert.match(part,/LIMIT 100/);
 assert.match(part,/next_after/);
 assert.doesNotMatch(part,/ciphertext|password_hash/);
});
