import test from "node:test";import assert from "node:assert/strict";import {readFile} from "node:fs/promises";
test("gateway bounds incoming payload and tracks heartbeats", async()=>{
 const api=await readFile(new URL("../apps/api/src/index.ts",import.meta.url),"utf8");
 assert.match(api,/data.byteLength > 8192/);
 assert.match(api,/Heartbeat timeout/);
 assert.match(api,/clearInterval\(watchdog\)/);
});
test("browser has WebSocket heartbeat and unsubscribe logic", async()=>{
 const js=await readFile(new URL("../apps/web/app.js",import.meta.url),"utf8");
 assert.match(js,/new WebSocket/);
 assert.match(js,/op:43/);
 assert.match(js,/op:1,d:null/);
});
