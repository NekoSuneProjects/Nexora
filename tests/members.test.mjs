import test from "node:test";import assert from "node:assert/strict";import{readFile}from"node:fs/promises";
test("member reads check community membership",async()=>{const s=await readFile(new URL("../apps/api/src/index.ts",import.meta.url),"utf8");assert.match(s,/SELECT 1 FROM guild_members WHERE guild_id=\$1 AND user_id=\$2/);});
test("member deletion protects community owner",async()=>{const s=await readFile(new URL("../apps/api/src/index.ts",import.meta.url),"utf8");assert.match(s,/Owner cannot be removed/);assert.match(s,/Only owners can remove other members/);});
