import test from "node:test";import assert from "node:assert/strict";import {readFile} from "node:fs/promises";
test("example bot pages through REST metadata history after connecting",async()=>{
 const source=await readFile(new URL("../examples/metadata-bot.mjs",import.meta.url),"utf8");
 assert.match(source,/NEXORA_API_URL/);
 assert.match(source,/NEXORA_EVENT_CURSOR/);
 assert.match(source,/\/api\/v1\/bots\/guilds\//);
 assert.match(source,/void catchUp\(\)/);
 assert.match(source,/data\.next_after/);
});
