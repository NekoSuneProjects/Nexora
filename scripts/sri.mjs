#!/usr/bin/env node
// Writes Subresource Integrity hashes for the web client into apps/web/*.html.
// Run `npm run sri` after editing any file under apps/web; `npm test` fails if hashes drift.
// The ES modules imported by app.js are pinned through <link rel="modulepreload" integrity>,
// which the browser verifies before the module graph can use them.
import { readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";

const web = new URL("../apps/web/", import.meta.url);
export async function integrity(file) {
  return "sha384-" + createHash("sha384").update(await readFile(new URL(file, web))).digest("base64");
}
const MODULES = ["crypto.mjs", "private-key-vault.mjs", "e2ee.mjs"];
export async function render() {
  let app = await readFile(new URL("index.html", web), "utf8");
  const block = [
    `<link rel="stylesheet" href="/app.css" integrity="${await integrity("app.css")}">`,
    ...(await Promise.all(MODULES.map(async (m) => `<link rel="modulepreload" href="/${m}" integrity="${await integrity(m)}">`))),
  ].join("\n");
  app = app.replace(/<!-- sri:head -->[\s\S]*?<!-- \/sri:head -->/, `<!-- sri:head -->\n${block}\n<!-- /sri:head -->`);
  app = app.replace(/<script type="module" src="\/app\.js"[^>]*><\/script>/, `<script type="module" src="/app.js" integrity="${await integrity("app.js")}"></script>`);
  let home = await readFile(new URL("home.html", web), "utf8");
  home = home.replace(/<link rel="stylesheet" href="\/home\.css"[^>]*>/, `<link rel="stylesheet" href="/home.css" integrity="${await integrity("home.css")}">`);
  return { app, home };
}
if (process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, "/").split("/").pop())) {
  const { app, home } = await render();
  await writeFile(new URL("index.html", web), app);
  await writeFile(new URL("home.html", web), home);
  console.log("SRI hashes updated.");
}
