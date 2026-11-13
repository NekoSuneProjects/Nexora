import test from "node:test";import assert from "node:assert/strict";import{readFile}from"node:fs/promises";
test("example bot reconnects with a bounded retry and resubscribes",async()=>{
 const s=await readFile(new URL("../examples/metadata-bot.mjs",import.meta.url),"utf8");
 assert.match(s,/Math\.min\(30000,1000\*2\*\*Math\.min\(attempt\+\+,5\)\)/);
 assert.match(s,/retryTimer=setTimeout/);
 assert.match(s,/op:42,d:\{guild_id:guildId\}/);
 assert.match(s,/event.code===4004\|\|event.code===4005/);
 assert.match(s,/process.on\("SIGTERM",stop\)/);
});
