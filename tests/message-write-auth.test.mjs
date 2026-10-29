import test from "node:test";import assert from "node:assert/strict";import {readFile} from "node:fs/promises";
test("message insertion rechecks current membership in the same SQL statement",async()=>{
 const api=await readFile(new URL("../apps/api/src/index.ts",import.meta.url),"utf8");
 assert.match(api,/INSERT INTO messages\(id,channel_id,author_id,ciphertext,algorithm\) SELECT/);
 assert.match(api,/JOIN guild_members gm ON gm.guild_id=c.guild_id/);
 assert.match(api,/if\(!r.rowCount\)return reply.code\(403\)/);
});
