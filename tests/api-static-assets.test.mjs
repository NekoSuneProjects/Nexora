import test from "node:test";
import assert from "node:assert/strict";
import { readFile, access } from "node:fs/promises";
// Regression: paths once resolved one directory too high, so every API-served page returned 500.
test("every frontend file served by the API resolves to an existing file", async () => {
  const source = await readFile(new URL("../apps/api/src/index.ts", import.meta.url), "utf8");
  const apiDir = new URL("../apps/api/src/", import.meta.url);
  const paths = [...source.matchAll(/["'](\.\.\/[^"']*web\/[^"']+)["']/g)].map((m) => m[1]);
  assert.ok(paths.length >= 8, "expected the web assets to be listed");
  for (const p of paths) await access(new URL(p, apiDir)).catch(() => assert.fail(p + " does not exist"));
  for (const asset of ["index.html", "home.html", "app.js", "app.css", "home.css", "crypto.mjs", "e2ee.mjs", "private-key-vault.mjs"]) {
    assert.ok(paths.some((p) => p.endsWith("/" + asset)), asset + " must be served by the API");
  }
});
test("nginx serves the same client assets", async () => {
  const conf = await readFile(new URL("../docker/frontend/default.conf.template", import.meta.url), "utf8");
  for (const asset of ["app\\.js", "crypto\\.mjs", "private-key-vault\\.mjs", "e2ee\\.mjs", "app\\.css", "home\\.css"]) assert.ok(conf.includes(asset), asset);
  assert.match(conf, /application\/javascript js mjs/);
  assert.match(conf, /Content-Security-Policy "default-src 'none'; script-src 'self'; style-src 'self'/);
});
