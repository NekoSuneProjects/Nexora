import test from "node:test";import assert from "node:assert/strict";import {readFile} from "node:fs/promises";
test("nginx channel route regex with quantifier is quoted",async()=>{
 const conf=await readFile(new URL("../docker/frontend/default.conf.template",import.meta.url),"utf8");
 assert.match(conf,/location ~ "\^\/app\/channels\/\[a-fA-F0-9-\]\{36\}\/\[a-fA-F0-9-\]\{36\}\$"/);
});
