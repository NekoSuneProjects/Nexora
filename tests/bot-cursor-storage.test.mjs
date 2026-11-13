import test from "node:test";import assert from "node:assert/strict";import {readFile} from "node:fs/promises";
test("example bot restores and atomically persists catch-up cursor",async()=>{
 const s=await readFile(new URL("../examples/metadata-bot.mjs",import.meta.url),"utf8");
 assert.match(s,/NEXORA_CURSOR_FILE/);
 assert.match(s,/saved.guild_id===guildId/);
 assert.match(s,/writeFile\(tmp,/);
 assert.match(s,/rename\(tmp,cursorFile\)/);
 assert.match(s,/await saveCursor\(data.next_after\)/);
 assert.match(s,/loadCursor\(\)\.then\(connect\)/);
});
