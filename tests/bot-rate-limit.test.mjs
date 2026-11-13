import test from "node:test";import assert from "node:assert/strict";import {readFile} from "node:fs/promises";
test("bot Gateway enforces bounded inbound message volume and subscriptions",async()=>{
 const source=await readFile(new URL("../apps/api/src/index.ts",import.meta.url),"utf8");
 const bot=source.slice(source.indexOf('app.get("/bot-gateway"'),source.indexOf('app.get("/gateway"'));
 assert.match(bot,/now-windowStart>=10000/);
 assert.match(bot,/\+\+windowMessages>100/);
 assert.match(bot,/subscriptions.size>=25/);
 assert.match(bot,/socket.close\(4008/);
});
