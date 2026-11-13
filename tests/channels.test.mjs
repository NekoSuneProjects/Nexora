import test from "node:test";import assert from "node:assert/strict";import {readFile} from "node:fs/promises";
test("channel modifications require MANAGE_CHANNELS and stay guild-scoped",async()=>{
 const api=await readFile(new URL("../apps/api/src/index.ts",import.meta.url),"utf8");
 assert.match(api,/has\(access.perms,Permissions.MANAGE_CHANNELS\)/);
 // The rename UPDATE re-checks the channel belongs to the authorized community.
 assert.match(api,/WHERE c.id=\$2 AND g.id=c.guild_id AND g.id=\$3 AND g.kind='community'/);
 // Parent categories are verified inside the INSERT.
 assert.match(api,/EXISTS\(SELECT 1 FROM channels WHERE id=\$7 AND guild_id=\$2 AND kind='category'\)/);
});
test("channel names validated before insertion",async()=>{const api=await readFile(new URL("../apps/api/src/index.ts",import.meta.url),"utf8");assert.match(api,/channelInput=z.object/);assert.match(api,/regex\(\/\^\[a-z0-9_-\]\+\$\/\)/);});
