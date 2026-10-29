import test from "node:test";import assert from "node:assert/strict";import{readFile}from"node:fs/promises";
test("web client provides usable testing navigation, gateway state and locked composer",async()=>{
 const html=await readFile(new URL("../apps/web/index.html",import.meta.url),"utf8");
 const script=await readFile(new URL("../apps/web/app.js",import.meta.url),"utf8");
 for(const id of ["gateway-state","refresh-workspace","send-encrypted-button","device-enroll-form","device-unlock-form"])assert.ok(html.includes('id="'+id+'"'));
 assert.match(script,/function updateComposer/);assert.match(script,/connectionState\("Connected",true\)/);
 assert.match(script,/CHANNEL_ACCESS_REVOKED/);assert.match(script,/MESSAGE_DELETE/);
});
