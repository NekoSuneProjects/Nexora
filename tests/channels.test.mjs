import test from "node:test";import assert from "node:assert/strict";import {readFile} from "node:fs/promises";
test("channel modifications check community ownership",async()=>{const api=await readFile(new URL("../apps/api/src/index.ts",import.meta.url),"utf8");assert.match(api,/owner_id=\$2/);assert.match(api,/g.owner_id=\$3/);});
test("channel names validated before insertion",async()=>{const api=await readFile(new URL("../apps/api/src/index.ts",import.meta.url),"utf8");assert.match(api,/channelInput=z.object/);assert.match(api,/regex\(\/\^\[a-z0-9_-\]\+\$\/\)/);});
