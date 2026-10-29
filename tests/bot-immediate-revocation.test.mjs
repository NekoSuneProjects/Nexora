import test from "node:test";import assert from "node:assert/strict";import {readFile} from "node:fs/promises";
test("rotating and revoking an application close its local Gateway sockets",async()=>{
 const src=await readFile(new URL("../apps/api/src/index.ts",import.meta.url),"utf8");
 assert.match(src,/function closeBotConnections\(appId:string\)/);
 assert.match(src,/socket.close\(4004,"Bot credential revoked"\)/);
 assert.match(src,/closeBotConnections\(id\)/);
 assert.match(src,/botConnections.get\(authenticatedId\)!\.add\(socket\)/);
});
