import test from "node:test";import assert from "node:assert/strict";import{readFile}from"node:fs/promises";
test("homepage and channel URLs are served in both web and API deployments",async()=>{
 const h=await readFile(new URL("../apps/web/home.html",import.meta.url),"utf8");
 const page=await readFile(new URL("../apps/web/index.html",import.meta.url),"utf8");
 const server=await readFile(new URL("../apps/api/src/index.ts",import.meta.url),"utf8");
 const nginx=await readFile(new URL("../docker/frontend/default.conf.template",import.meta.url),"utf8");
 assert.match(h,/href="\/app"/);assert.match(page,/server-rail/);
 assert.match(server,/app\.get\("\/app\/channels\/:guildId\/:channelId"/);
 assert.match(nginx,/location = \/app/);
 assert.match(nginx,/home\.html/);
});
test("API image runs a schema migration before starting",async()=>{
 const docker=await readFile(new URL("../Dockerfile",import.meta.url),"utf8");
 const runner=await readFile(new URL("../scripts/start-api.mjs",import.meta.url),"utf8");
 assert.match(docker,/COPY database \.\/database/);
 assert.match(docker,/scripts\/start-api\.mjs/);
 assert.match(runner,/pg_advisory_lock/);
 assert.match(runner,/schema_migrations/);
});
