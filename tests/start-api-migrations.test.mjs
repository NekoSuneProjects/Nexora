import test from "node:test";
import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
// Regression: an over-escaped regex (/^\\d{4}.../) once made the container skip every migration.
test("container start-up migration filter matches every migration file", async () => {
  const runner = await readFile(new URL("../scripts/start-api.mjs", import.meta.url), "utf8");
  const literal = /filter\(f=>\/(.+?)\/\.test\(f\)\)/.exec(runner);
  assert.ok(literal, "migration filter not found");
  const pattern = new RegExp(literal[1]);
  const files = (await readdir(new URL("../database/migrations/", import.meta.url))).filter((f) => f.endsWith(".sql"));
  assert.ok(files.length >= 7);
  for (const file of files) assert.ok(pattern.test(file), file + " would be skipped at start-up");
  assert.equal(pattern.test("../evil.sql"), false);
});
