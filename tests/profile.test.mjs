import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

test("profile schema explicitly defaults social links to unverified", async()=>{
 const sql=await readFile(new URL("../database/schema.sql",import.meta.url),"utf8");
 assert.match(sql,/verified boolean NOT NULL DEFAULT false/);
});
test("web client labels social links as unverified",async()=>{
 const js=await readFile(new URL("../apps/web/app.js",import.meta.url),"utf8");
 assert.match(js,/unverified/);
});
