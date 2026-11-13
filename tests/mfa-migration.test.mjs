import test from "node:test";import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
test("the MFA migration is available to existing database deployments",async()=>{
const sql=await readFile(new URL("../database/migrations/0004_mfa.sql",import.meta.url),"utf8");
assert.match(sql,/CREATE TABLE IF NOT EXISTS user_mfa/);
assert.match(sql,/REFERENCES users\(id\) ON DELETE CASCADE/);
});
