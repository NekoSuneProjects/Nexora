import test from "node:test";import assert from "node:assert/strict";import {readFile} from "node:fs/promises";
test("bot deduplicates live and historical metadata with bounded memory",async()=>{
 const source=await readFile(new URL("../examples/metadata-bot.mjs",import.meta.url),"utf8");
 assert.match(source,/const MAX_SEEN=10000/);
 assert.match(source,/recentlySeen\.has\(event.message_id\)/);
 assert.match(source,/recentlySeen\.delete\(recentlySeen\.values\(\)\.next\(\)\.value\)/);
 assert.match(source,/reportMetadata\(event,true\)/);
 assert.match(source,/reportMetadata\(packet.d\)/);
});
