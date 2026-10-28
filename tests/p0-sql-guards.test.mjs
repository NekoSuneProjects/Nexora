import test from "node:test";import assert from "node:assert/strict";import{readFile}from"node:fs/promises";
test("SQL stays parameterized and nonmember message writes remain authorization-bound",async()=>{
 const s=await readFile(new URL("../apps/api/src/index.ts",import.meta.url),"utf8");
 assert.match(s,/INSERT INTO messages\(id,channel_id,author_id,ciphertext,algorithm\) SELECT/);
 assert.match(s,/JOIN guild_members gm ON gm.guild_id=c.guild_id WHERE c.id=\$2 AND gm.user_id=\$3/);
 assert.match(s,/DELETE FROM guild_members gm USING guilds g/);
});
