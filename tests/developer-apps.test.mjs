import test from "node:test";import assert from "node:assert/strict";import {readFile} from "node:fs/promises";
test("developer app credentials are stored as hashes",async()=>{
 const s=await readFile(new URL("../database/schema.sql",import.meta.url),"utf8");
 assert.match(s,/bot_token_hash text NOT NULL UNIQUE/);
});
test("bot token authentication uses a distinct authorization scheme",async()=>{
 const s=await readFile(new URL("../apps/api/src/index.ts",import.meta.url),"utf8");
 assert.match(s,/Bot \(\[a-f0-9\]\{64\}\)/);
 assert.match(s,/hashToken\(match\[1\]\)/);
});
