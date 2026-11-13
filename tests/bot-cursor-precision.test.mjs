import test from "node:test";import assert from "node:assert/strict";import {readFile} from "node:fs/promises";
test("event cursor comparison stays inside PostgreSQL to preserve timestamp precision",async()=>{
 const source=await readFile(new URL("../apps/api/src/index.ts",import.meta.url),"utf8");
 const block=source.slice(source.indexOf('app.get("/api/v1/bots/guilds/:id/events"'),source.indexOf('app.get("/api/v10/users/@me"'));
 assert.match(block,/SELECT previous.created_at,previous.id FROM messages previous/);
 assert.doesNotMatch(block,/afterCreated|\$2::timestamptz/);
});
