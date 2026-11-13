import test from "node:test";import assert from "node:assert/strict";import{readFile}from"node:fs/promises";
test("committed authorization changes are added to an event backlog",async()=>{
 const m=await readFile(new URL("../database/migrations/0005_security_outbox.sql",import.meta.url),"utf8");
 const api=await readFile(new URL("../apps/api/src/index.ts",import.meta.url),"utf8");
 assert.match(m,/CREATE TABLE IF NOT EXISTS security_events/);
 assert.match(m,/INSERT INTO security_events\(payload\)/);
 assert.match(api,/catchUpSecurityEvents/);
});
