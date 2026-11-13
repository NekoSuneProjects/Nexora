import test from "node:test";import assert from "node:assert/strict";import {readFile} from "node:fs/promises";
test("manual GitHub Docker workflow builds API and web without desktop",async()=>{
 const y=await readFile(new URL("../.github/workflows/manual-client-build.yml",import.meta.url),"utf8");
 assert.match(y,/workflow_dispatch:/);
 assert.match(y,/component: api/);
 assert.match(y,/component: web/);
 assert.match(y,/linux\/amd64,linux\/arm64/);
 assert.match(y,/docker\/build-push-action@v6/);
 assert.match(y,/packages: write/);
 assert.doesNotMatch(y,/desktop-linux|desktop-windows/);
 assert.doesNotMatch(y,/^    if:.*matrix\.component/m);
 assert.match(y,/if:.*inputs\.build_target.*matrix\.component/);
});
