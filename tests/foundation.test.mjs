import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

test("developer client warns that E2EE is not implemented", async () => {
  const html = await readFile(new URL("../apps/web/index.html", import.meta.url), "utf8");
  assert.match(html, /Cryptographic chat is an unreviewed single-device prototype/);
  assert.match(html, /Do not transmit confidential messages/);
});
test("the frontend never sends plaintext message content", async () => {
  const js = await readFile(new URL("../apps/web/app.js", import.meta.url), "utf8");
  assert.match(js, /encryptMessage\(/);
  assert.match(js, /ciphertext:JSON.stringify\(envelope\)/);
  assert.match(js, /auth\/logout/);
});
test("schema stores opaque envelopes and assigns channel membership", async () => {
  const sql = await readFile(new URL("../database/schema.sql", import.meta.url), "utf8");
  assert.match(sql, /ciphertext text NOT NULL/);
  assert.match(sql, /PRIMARY KEY \(guild_id,user_id\)/);
});
