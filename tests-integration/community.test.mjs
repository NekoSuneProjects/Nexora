import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";
import { randomBytes, randomUUID, scryptSync } from "node:crypto";
import pg from "pg";
const { createDevice, publicBundle, fingerprint } = await import("../apps/web/crypto.mjs");

// Separate port so this suite can run alongside api.test.mjs.
const base = "http://127.0.0.1:3102";
const api = spawn(process.execPath, ["node_modules/tsx/dist/cli.mjs", "apps/api/src/index.ts"], { env: { ...process.env, PORT: "3102", HOST: "127.0.0.1", NODE_ENV: "test" }, stdio: "pipe" });
let log = "";
api.stdout.on("data", (d) => (log += d));
api.stderr.on("data", (d) => (log += d));
async function ready() {
  for (let i = 0; i < 60; i++) {
    if (api.exitCode !== null) throw Error("API exited: " + log);
    try { if ((await fetch(base + "/health")).ok) return; } catch {}
    await sleep(500);
  }
  throw Error("API not ready: " + log);
}
async function call(path, method = "GET", body, token) {
  const res = await fetch(base + path, { method, headers: { ...(body !== undefined ? { "content-type": "application/json" } : {}), ...(token ? { authorization: "Bearer " + token } : {}) }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
  let data = null;
  try { data = await res.json(); } catch {}
  return { status: res.status, data };
}
// Seed accounts directly so this suite does not consume the shared registration quota.
async function seedUser(pool, username, password) {
  const id = randomUUID(), salt = randomBytes(16).toString("hex");
  await pool.query("INSERT INTO users(id,username,password_salt,password_hash) VALUES($1,$2,$3,$4)", [id, username, salt, scryptSync(password, salt, 64).toString("hex")]);
  const login = await call("/api/v1/auth/login", "POST", { username, password });
  assert.equal(login.status, 200, "login " + username);
  return { id, username, token: login.data.token };
}
function gateway(token) {
  const ws = new WebSocket(base.replace("http", "ws") + "/gateway");
  const packets = [];
  let beat = null;
  ws.addEventListener("message", (e) => {
    const p = JSON.parse(e.data);
    if (p.op === 10) beat = setInterval(() => ws.readyState === 1 && ws.send(JSON.stringify({ op: 1, d: null })), p.d.heartbeat_interval);
    if (p.op !== 11) packets.push(p);
  });
  let closed = "";
  ws.addEventListener("close", (e) => { closed = e.code + " " + e.reason; clearInterval(beat); });
  const wait = async (type, match = () => true) => {
    for (let n = 0; n < 100; n++) {
      const i = packets.findIndex((p) => (p.t === type || p.op === type) && match(p));
      if (i >= 0) return packets.splice(i, 1)[0];
      await sleep(30);
    }
    throw Error("Timed out waiting for " + type + " closed=" + closed + " got=" + JSON.stringify(packets.map((p) => p.t ?? p.op)));
  };
  return { ws, packets, wait, send: (p) => ws.send(JSON.stringify(p)), async ready() { await wait(10); ws.send(JSON.stringify({ op: 2, d: { token } })); await wait("READY"); } };
}
const enc = (s) => encodeURIComponent(s);

test("roles, moderation, channels, message extras, social graph, DMs and key distribution", async () => {
  const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
  const sockets = [];
  try {
    await ready();
    const sfx = Math.random().toString(36).slice(2, 8);
    const pw = "community suite password 42";
    const A = await seedUser(pool, "owner_" + sfx, pw), B = await seedUser(pool, "mod_" + sfx, pw), C = await seedUser(pool, "member_" + sfx, pw);

    // --- community and joining
    const guild = await call("/api/v10/guilds", "POST", { name: "Roles HQ" }, A.token);
    assert.equal(guild.status, 201);
    const gid = guild.data.id, general = guild.data.channels[0].id;
    const invite = await call(`/api/v1/guilds/${gid}/invites`, "POST", { max_uses: 10, expires_hours: 1 }, A.token);
    assert.equal(invite.status, 201);
    const preview = await call(`/api/v1/invites/${invite.data.code}`, "GET", undefined, B.token);
    assert.equal(preview.status, 200);
    assert.equal(preview.data.guild.name, "Roles HQ");
    assert.equal(preview.data.already_member, false);
    const cGateway = gateway(C.token);
    sockets.push(cGateway.ws);
    await cGateway.ready();
    assert.equal((await call(`/api/v1/invites/${invite.data.code}/join`, "POST", undefined, B.token)).status, 200);
    assert.equal((await call(`/api/v1/invites/${invite.data.code}/join`, "POST", undefined, C.token)).status, 200);
    assert.equal((await cGateway.wait("GUILD_CREATE")).d.id, gid);

    // Default @everyone can invite; invite management lists hints, never full codes.
    assert.equal((await call(`/api/v1/guilds/${gid}/invites`, "POST", { max_uses: 1, expires_hours: 1 }, C.token)).status, 201);
    const invites = await call(`/api/v1/guilds/${gid}/invites`, "GET", undefined, A.token);
    assert.equal(invites.status, 200);
    assert.ok(invites.data.every((i) => i.code_hint.length === 4 && !("code" in i) && !("code_hash" in i)));
    assert.equal((await call(`/api/v1/guilds/${gid}/invites`, "GET", undefined, C.token)).status, 403);

    // --- roles and hierarchy
    assert.equal((await call(`/api/v1/guilds/${gid}/channels`, "POST", { name: "nope" }, B.token)).status, 403);
    assert.equal((await call(`/api/v1/guilds/${gid}/roles`, "POST", { name: "mod", permissions: "1" }, B.token)).status, 403);
    const KICK = 1n << 4n, MANAGE_MESSAGES = 1n << 9n, MANAGE_CHANNELS = 1n << 3n, VIEW_AUDIT = 1n << 12n, MANAGE_ROLES = 1n << 2n;
    const mod = await call(`/api/v1/guilds/${gid}/roles`, "POST", { name: "mod", color: 0x55aaff, hoist: true, permissions: String(KICK | MANAGE_MESSAGES | MANAGE_CHANNELS | VIEW_AUDIT | MANAGE_ROLES) }, A.token);
    assert.equal(mod.status, 201);
    assert.equal((await call(`/api/v1/guilds/${gid}/roles`, "POST", { name: "bad", permissions: "999999999999999999" }, A.token)).status, 400);
    assert.equal((await call(`/api/v1/guilds/${gid}/members/${B.id}/roles/${mod.data.id}`, "PUT", undefined, A.token)).status, 204);
    const members = await call(`/api/v1/guilds/${gid}/members`, "GET", undefined, C.token);
    assert.deepEqual(members.data.find((m) => m.id === B.id).roles, [mod.data.id]);
    const info = await call(`/api/v1/guilds/${gid}`, "GET", undefined, B.token);
    assert.equal(BigInt(info.data.permissions) & KICK, KICK);
    // B cannot edit a role at their own top position, nor escalate to ADMINISTRATOR.
    assert.equal((await call(`/api/v1/guilds/${gid}/roles/${mod.data.id}`, "PATCH", { name: "supreme" }, B.token)).status, 403);
    assert.equal((await call(`/api/v1/guilds/${gid}/roles`, "POST", { name: "admin", permissions: "1" }, B.token)).status, 403);
    // Moderator kicks a regular member but never the owner.
    assert.equal((await call(`/api/v1/guilds/${gid}/members/${A.id}`, "DELETE", undefined, B.token)).status, 403);
    assert.equal((await call(`/api/v1/guilds/${gid}/members/${C.id}`, "DELETE", undefined, B.token)).status, 204);
    assert.equal((await cGateway.wait("GUILD_DELETE")).d.id, gid);
    assert.equal((await call(`/api/v1/guilds/${gid}/members/${B.id}`, "DELETE", undefined, C.token)).status, 403);
    assert.equal((await call(`/api/v1/invites/${invite.data.code}/join`, "POST", undefined, C.token)).status, 200);
    // Nicknames
    assert.equal((await call(`/api/v1/guilds/${gid}/members/@me`, "PATCH", { nickname: "Cee" }, C.token)).status, 200);
    assert.equal((await call(`/api/v1/guilds/${gid}/members/${A.id}`, "PATCH", { nickname: "boss" }, C.token)).status, 403);

    // --- channel structure
    const category = await call(`/api/v1/guilds/${gid}/channels`, "POST", { name: "lounge", kind: "category" }, B.token);
    assert.equal(category.status, 201);
    const child = await call(`/api/v1/guilds/${gid}/channels`, "POST", { name: "chill", topic: "relax", parent_id: category.data.id }, B.token);
    assert.equal(child.status, 201);
    assert.equal(child.data.parent_id, category.data.id);
    assert.equal((await call(`/api/v1/guilds/${gid}/channels`, "POST", { name: "orphan", parent_id: general }, B.token)).status, 400);
    const news = await call(`/api/v1/guilds/${gid}/channels`, "POST", { name: "news", kind: "announcement" }, A.token);
    assert.equal((await call(`/api/v1/channels/${child.data.id}`, "PATCH", { topic: "new topic" }, B.token)).data.topic, "new topic");
    assert.equal((await call(`/api/v1/channels/${child.data.id}`, "PATCH", { topic: "x" }, C.token)).status, 403);
    assert.equal((await call(`/api/v10/channels/${news.data.id}/messages`, "POST", { ciphertext: "opaque", algorithm: "client-encrypted-v1" }, C.token)).status, 403);
    assert.equal((await call(`/api/v10/channels/${category.data.id}/messages`, "POST", { ciphertext: "opaque", algorithm: "client-encrypted-v1" }, A.token)).status, 400);
    assert.equal((await call(`/api/v1/guilds/${gid}/channels/order`, "PUT", [{ id: news.data.id, position: 0, parent_id: category.data.id }], B.token)).status, 204);
    const listed = await call(`/api/v10/guilds/${gid}/channels`, "GET", undefined, C.token);
    const movedNews = listed.data.find((c) => c.id === news.data.id);
    assert.equal(movedNews.parent_id, category.data.id);
    assert.equal(movedNews.position, 0);
    assert.equal((await call(`/api/v1/channels/${child.data.id}`, "DELETE", undefined, C.token)).status, 403);
    assert.equal((await call(`/api/v1/channels/${child.data.id}`, "DELETE", undefined, B.token)).status, 204);

    // --- messages: replies, edits, reactions, pins, moderation, pagination, typing
    const bGateway = gateway(B.token);
    sockets.push(bGateway.ws);
    await bGateway.ready();
    for (const g of [bGateway, cGateway]) { g.send({ op: 42, d: { channel_id: general } }); await g.wait("CHANNEL_SUBSCRIBED"); }
    const first = await call(`/api/v10/channels/${general}/messages`, "POST", { ciphertext: "opaque-1", algorithm: "client-encrypted-v1" }, A.token);
    assert.equal(first.status, 201);
    const created = await cGateway.wait("MESSAGE_CREATE", (p) => p.d.id === first.data.id);
    assert.equal(created.d.author_username, A.username);
    await sleep(5600); // past one catch-up interval: the event must not be redelivered
    assert.equal(cGateway.packets.some((p) => p.t === "MESSAGE_CREATE" && p.d.id === first.data.id), false, "catch-up must not redeliver notified events");
    const reply = await call(`/api/v10/channels/${general}/messages`, "POST", { ciphertext: "opaque-2", algorithm: "client-encrypted-v1", reply_to: first.data.id }, C.token);
    assert.equal(reply.data.reply_to, first.data.id);
    assert.equal((await call(`/api/v10/channels/${general}/messages/${first.data.id}`, "PATCH", { ciphertext: "edited", algorithm: "client-encrypted-v1" }, C.token)).status, 404);
    assert.equal((await call(`/api/v10/channels/${general}/messages/${first.data.id}`, "PATCH", { ciphertext: "edited", algorithm: "client-encrypted-v1" }, A.token)).status, 200);
    assert.equal((await cGateway.wait("MESSAGE_UPDATE")).d.ciphertext, "edited");
    const heart = enc("❤️");
    assert.equal((await call(`/api/v10/channels/${general}/messages/${first.data.id}/reactions/${heart}/@me`, "PUT", undefined, C.token)).status, 204);
    assert.equal((await bGateway.wait("MESSAGE_REACTION_ADD")).d.emoji, "❤️");
    assert.equal((await call(`/api/v10/channels/${general}/messages/${first.data.id}/reactions/${enc("bad emoji")}/@me`, "PUT", undefined, C.token)).status, 400);
    const who = await call(`/api/v10/channels/${general}/messages/${first.data.id}/reactions/${heart}`, "GET", undefined, A.token);
    assert.deepEqual(who.data.map((u) => u.id), [C.id]);
    assert.equal((await call(`/api/v10/channels/${general}/pins/${first.data.id}`, "PUT", undefined, C.token)).status, 403);
    assert.equal((await call(`/api/v10/channels/${general}/pins/${first.data.id}`, "PUT", undefined, B.token)).status, 204);
    assert.equal((await call(`/api/v10/channels/${general}/pins`, "GET", undefined, C.token)).data[0].id, first.data.id);
    const history = await call(`/api/v10/channels/${general}/messages`, "GET", undefined, C.token);
    const firstRow = history.data.find((m) => m.id === first.data.id);
    assert.equal(firstRow.pinned, true);
    assert.ok(firstRow.edited_at);
    assert.deepEqual(firstRow.reactions, [{ emoji: "❤️", count: 1, me: true }]);
    const older = await call(`/api/v10/channels/${general}/messages?before=${reply.data.id}&limit=1`, "GET", undefined, C.token);
    assert.deepEqual(older.data.map((m) => m.id), [first.data.id]);
    assert.equal((await call(`/api/v10/channels/${general}/messages?before=${randomUUID()}`, "GET", undefined, C.token)).status, 400);
    bGateway.send({ op: 44, d: { channel_id: general } });
    assert.equal((await cGateway.wait("TYPING_START")).d.user_id, B.id);
    assert.equal((await call(`/api/v1/channels/${general}/ack`, "POST", { message_id: reply.data.id }, C.token)).status, 204);
    assert.ok((await call("/api/v1/users/@me/read-states", "GET", undefined, C.token)).data.some((r) => r.channel_id === general));
    // Moderator deletion of someone else's message is audited.
    assert.equal((await call(`/api/v10/channels/${general}/messages/${reply.data.id}`, "DELETE", undefined, B.token)).status, 204);
    const auditLog = await call(`/api/v1/guilds/${gid}/audit-log`, "GET", undefined, B.token);
    const actions = auditLog.data.map((e) => e.action);
    for (const action of ["message.delete", "member.kick", "role.create", "channel.create", "message.pin"]) assert.ok(actions.includes(action), action);
    assert.equal((await call(`/api/v1/guilds/${gid}/audit-log`, "GET", undefined, C.token)).status, 403);

    // --- bans
    assert.equal((await call(`/api/v1/guilds/${gid}/bans/${C.id}`, "PUT", { reason: "test" }, B.token)).status, 403);
    assert.equal((await call(`/api/v1/guilds/${gid}/bans/${C.id}`, "PUT", { reason: "test" }, A.token)).status, 204);
    assert.equal((await call(`/api/v1/invites/${invite.data.code}/join`, "POST", undefined, C.token)).status, 403);
    assert.equal((await call(`/api/v1/guilds/${gid}/bans`, "GET", undefined, A.token)).data[0].user_id, C.id);
    assert.equal((await call(`/api/v1/guilds/${gid}/bans/${C.id}`, "DELETE", undefined, A.token)).status, 204);
    assert.equal((await call(`/api/v1/invites/${invite.data.code}/join`, "POST", undefined, C.token)).status, 200);

    // --- relationships and direct messages
    assert.equal((await call("/api/v1/users/@me/relationships", "POST", { username: C.username }, B.token)).data.status, "outgoing");
    assert.equal((await call("/api/v1/users/@me/relationships", "GET", undefined, C.token)).data[0].status, "incoming");
    assert.equal((await call(`/api/v1/users/@me/relationships/${B.id}`, "PUT", { type: "friend" }, C.token)).status, 204);
    assert.equal((await call("/api/v1/users/@me/relationships", "GET", undefined, B.token)).data[0].status, "friend");
    const dm = await call("/api/v1/users/@me/channels", "POST", { recipient_ids: [C.id] }, B.token);
    assert.equal(dm.status, 201);
    assert.equal(dm.data.type, "dm");
    const again = await call("/api/v1/users/@me/channels", "POST", { recipient_ids: [B.id] }, C.token);
    assert.equal(again.data.guild_id, dm.data.guild_id, "1:1 conversations are canonical");
    assert.equal((await call("/api/v10/users/@me/guilds", "GET", undefined, B.token)).data.some((g) => g.id === dm.data.guild_id), false, "DMs are not servers");
    assert.equal((await call(`/api/v1/guilds/${dm.data.guild_id}/invites`, "POST", { max_uses: 1, expires_hours: 1 }, B.token)).status, 403);
    assert.equal((await call(`/api/v10/channels/${dm.data.id}/messages`, "POST", { ciphertext: "dm-opaque", algorithm: "client-encrypted-v1" }, B.token)).status, 201);
    const profile = await call(`/api/v1/users/${C.id}/profile`, "GET", undefined, B.token);
    assert.equal(profile.data.relationship, "friend");
    assert.ok(profile.data.mutual_guilds.some((g) => g.id === gid));
    assert.equal((await call(`/api/v1/users/@me/relationships/${B.id}`, "PUT", { type: "blocked" }, C.token)).status, 204);
    assert.equal((await call(`/api/v10/channels/${dm.data.id}/messages`, "POST", { ciphertext: "dm-opaque", algorithm: "client-encrypted-v1" }, B.token)).status, 403);
    assert.equal((await call("/api/v1/users/@me/relationships", "POST", { username: C.username }, B.token)).status, 404, "blocked users look absent");
    const group = await call("/api/v1/users/@me/channels", "POST", { recipient_ids: [A.id, B.id], name: "trio" }, C.token);
    assert.equal(group.status, 403, "cannot add someone you blocked... or who cannot be messaged");
    const group2 = await call("/api/v1/users/@me/channels", "POST", { recipient_ids: [A.id], name: "duo-group" }, B.token);
    assert.equal(group2.status, 201);
    assert.equal((await call("/api/v1/users/@me/settings", "PATCH", { status: "dnd", custom_status: "testing" }, B.token)).data.status, "dnd");

    // --- multi-device key distribution
    const device = await createDevice(), bundle = await publicBundle(device), fp = await fingerprint(bundle);
    const otherBundle = await publicBundle(await createDevice());
    assert.equal((await call("/api/v1/devices", "POST", { name: "mismatch", identity_key: fp, public_bundle: otherBundle, password: pw }, A.token)).status, 400);
    const enrolled = await call("/api/v1/devices", "POST", { name: "laptop", identity_key: fp, public_bundle: bundle, password: pw }, A.token);
    assert.equal(enrolled.status, 201);
    const state = await call(`/api/v1/channels/${general}/keys`, "GET", undefined, B.token);
    const recipient = state.data.recipients.find((r) => r.id === enrolled.data.id);
    assert.equal(recipient.public_bundle.signing.x, bundle.signing.x);
    assert.equal(state.data.claim, null);
    const commitment = "c".repeat(43);
    const claimed = await call(`/api/v1/channels/${general}/keys/claim`, "POST", { epoch: state.data.epoch, device_id: enrolled.data.id, key_commitment: commitment }, A.token);
    assert.equal(claimed.status, 201);
    const second = await call(`/api/v1/channels/${general}/keys/claim`, "POST", { epoch: state.data.epoch, device_id: enrolled.data.id, key_commitment: "d".repeat(43) }, A.token);
    assert.equal(second.status, 409);
    assert.equal(second.data.key_commitment, commitment);
    assert.equal((await call(`/api/v1/channels/${general}/keys/claim`, "POST", { epoch: state.data.epoch, device_id: enrolled.data.id, key_commitment: commitment }, B.token)).status, 409, "cannot claim with another user's device");

    // --- password change revokes other sessions only
    const otherSession = await call("/api/v1/auth/login", "POST", { username: C.username, password: pw });
    assert.equal((await call("/api/v1/auth/password", "POST", { current_password: "wrong password here", new_password: "brand new password 99" }, C.token)).status, 401);
    assert.equal((await call("/api/v1/auth/password", "POST", { current_password: pw, new_password: "brand new password 99" }, C.token)).status, 204);
    assert.equal((await call("/api/v10/users/@me", "GET", undefined, C.token)).status, 200, "current session survives");
    assert.equal((await call("/api/v10/users/@me", "GET", undefined, otherSession.data.token)).status, 401, "other sessions are revoked");
    assert.equal((await call("/api/v1/auth/login", "POST", { username: C.username, password: pw })).status, 401);
    assert.equal((await call("/api/v1/auth/login", "POST", { username: C.username, password: "brand new password 99" })).status, 200);

    // --- deletion and ownership
    assert.equal((await call(`/api/v1/guilds/${gid}`, "DELETE", undefined, B.token)).status, 403);
    assert.equal((await call(`/api/v1/guilds/${gid}/transfer`, "POST", { user_id: B.id }, A.token)).status, 200);
    assert.equal((await call(`/api/v1/guilds/${gid}`, "DELETE", undefined, A.token)).status, 403);
    assert.equal((await call(`/api/v1/guilds/${gid}`, "DELETE", undefined, B.token)).status, 204);
    assert.equal((await call("/api/v10/users/@me/guilds", "GET", undefined, C.token)).data.some((g) => g.id === gid), false);
  } finally {
    // Set SHOW_API_LOG=1 to print API warnings/errors when debugging a failure.
    if (process.env.SHOW_API_LOG) console.error(log.split(/\r?\n/).filter((l) => /"level":(50|40)|statusCode":500|rror/.test(l)).join("\n"));
    for (const ws of sockets) ws.close();
    await pool.end();
    api.kill("SIGTERM");
    await Promise.race([new Promise((r) => api.once("exit", r)), sleep(3000)]);
  }
}, { timeout: 60000 });
