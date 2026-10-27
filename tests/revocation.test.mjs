import test from "node:test";import assert from "node:assert/strict";import {readFile} from "node:fs/promises";
test("removed members are evicted from in-process gateway subscriptions", async()=>{
 const api=await readFile(new URL("../apps/api/src/index.ts",import.meta.url),"utf8");
 assert.match(api,/function evictMemberSockets/);
 assert.match(api,/socketIdentity\.get\(socket\)!==userId/);
 assert.match(api,/socketSubscriptions\.get\(socket\)\?\.delete\(id\)/);
 assert.match(api,/evictMemberSockets\(userId,channels\.rows/);
});
