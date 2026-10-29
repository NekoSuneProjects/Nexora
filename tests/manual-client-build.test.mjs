import test from "node:test";import assert from "node:assert/strict";import{readFile}from"node:fs/promises";
test("manual frontend builds are dispatch-only and desktop bridge is local-only",async()=>{
 const wf=await readFile(new URL("../.github/workflows/manual-client-build.yml",import.meta.url),"utf8");
 const conf=await readFile(new URL("../apps/desktop/main.cjs",import.meta.url),"utf8");
 const preload=await readFile(new URL("../apps/desktop/preload.cjs",import.meta.url),"utf8");
 const nginx=await readFile(new URL("../docker/frontend/default.conf.template",import.meta.url),"utf8");
 assert.match(wf,/workflow_dispatch:/);
 assert.doesNotMatch(wf,/^  push:/m);
 assert.match(conf,/senderFrame\?\.url\.startsWith\("file:"\)/);
 assert.match(preload,/location.protocol==="file:"/);
 assert.match(nginx,/proxy_pass \$\{API_UPSTREAM\}/);
});
