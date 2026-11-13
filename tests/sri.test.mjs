import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
const { render } = await import("../scripts/sri.mjs");
// Every client asset is pinned with Subresource Integrity. Run `npm run sri` after edits.
test("Subresource Integrity hashes match the current client assets", async () => {
  const expected = await render();
  const app = await readFile(new URL("../apps/web/index.html", import.meta.url), "utf8");
  const home = await readFile(new URL("../apps/web/home.html", import.meta.url), "utf8");
  assert.equal(app, expected.app, "apps/web/index.html integrity is stale: run npm run sri");
  assert.equal(home, expected.home, "apps/web/home.html integrity is stale: run npm run sri");
  for (const asset of ["app.css", "crypto.mjs", "private-key-vault.mjs", "e2ee.mjs"]) assert.match(app, new RegExp(`href="/${asset.replace(".", "\\.")}" integrity="sha384-`));
  assert.match(app, /<script type="module" src="\/app\.js" integrity="sha384-/);
  assert.match(home, /href="\/home\.css" integrity="sha384-/);
});
test("web assets are pinned to LF line endings so hashes are identical on every OS", async () => {
  const attributes = await readFile(new URL("../.gitattributes", import.meta.url), "utf8");
  assert.match(attributes, /apps\/web\/\*\* text eol=lf/);
});
