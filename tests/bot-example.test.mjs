import test from "node:test";import assert from "node:assert/strict";import {readFile} from "node:fs/promises";
test("bot example authenticates subscribes and heartbeats",async()=>{
 const s=await readFile(new URL("../examples/metadata-bot.mjs",import.meta.url),"utf8");
 assert.match(s,/op:2,d:\{token\}/);assert.match(s,/op:42,d:\{guild_id:guildId\}/);assert.match(s,/op:1,d:null/);
 assert.doesNotMatch(s,/ciphertext/);
});
