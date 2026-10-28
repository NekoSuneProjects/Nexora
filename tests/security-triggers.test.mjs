import test from "node:test";import assert from "node:assert/strict";import {readFile} from "node:fs/promises";
test("database commit-time invalidation covers all critical credential and membership events",async()=>{
 const sql=await readFile(new URL("../database/migrations/0003_security_notifications.sql",import.meta.url),"utf8");
 for(const table of ["sessions","developer_apps","guild_members","guild_bots"])assert.match(sql,new RegExp("ON "+table+" FOR EACH ROW"));
 for(const kind of ["session","bot","member","bot_uninstall"])assert.ok(sql.includes("'"+kind+"'"));
 assert.match(sql,/OLD\.can_read_events = true AND NEW\.can_read_events = false/);
});
