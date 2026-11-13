import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";
import { randomBytes, randomUUID, scryptSync, createHash, generateKeyPairSync, sign } from "node:crypto";
import pg from "pg";
const { createDevice, publicBundle, fingerprint } = await import("../apps/web/crypto.mjs");
const { attestDevice } = await import("../apps/web/e2ee.mjs");

const port = 3103, base = "http://127.0.0.1:" + port;
const api = spawn(process.execPath, ["node_modules/tsx/dist/cli.mjs", "apps/api/src/index.ts"], { env: { ...process.env, PORT: String(port), HOST: "127.0.0.1", NODE_ENV: "test" }, stdio: "pipe" });
let log = "";
api.stdout.on("data", (d) => (log += d)); api.stderr.on("data", (d) => (log += d));
async function ready() {
  for (let i = 0; i < 60; i++) { if (api.exitCode !== null) throw Error("API exited: " + log); try { if ((await fetch(base + "/health")).ok) return; } catch {} await sleep(500); }
  throw Error("API not ready: " + log);
}
async function call(path, method = "GET", body, token) {
  const res = await fetch(base + path, { method, headers: { ...(body !== undefined ? { "content-type": "application/json" } : {}), ...(token ? { authorization: "Bearer " + token } : {}) }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
  let data = null; try { data = await res.json(); } catch {}
  return { status: res.status, data };
}
const pw = "security suite password 7";
async function seed(pool, name) {
  const id = randomUUID(), salt = randomBytes(16).toString("hex");
  await pool.query("INSERT INTO users(id,username,password_salt,password_hash) VALUES($1,$2,$3,$4)", [id, name, salt, scryptSync(pw, salt, 64).toString("hex")]);
  const login = await call("/api/v1/auth/login", "POST", { username: name, password: pw });
  assert.equal(login.status, 200, "login " + name);
  return { id, name, token: login.data.token };
}

// --- a tiny CBOR encoder and a software authenticator (ES256, "none" attestation)
function cbor(v) {
  const head = (major, n) => n < 24 ? Buffer.from([(major << 5) | n]) : n < 256 ? Buffer.from([(major << 5) | 24, n]) : Buffer.from([(major << 5) | 25, n >> 8, n & 255]);
  if (typeof v === "number") return v >= 0 ? head(0, v) : head(1, -1 - v);
  if (typeof v === "string") { const b = Buffer.from(v); return Buffer.concat([head(3, b.length), b]); }
  if (v instanceof Uint8Array) return Buffer.concat([head(2, v.length), Buffer.from(v)]);
  if (v instanceof Map) return Buffer.concat([head(5, v.size), ...[...v].flatMap(([k, x]) => [cbor(k), cbor(x)])]);
  if (typeof v === "object") return cbor(new Map(Object.entries(v)));
  throw Error("cbor");
}
function authenticator(origin, rpId) {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = publicKey.export({ format: "jwk" });
  const credId = randomBytes(32);
  let counter = 0;
  const rpHash = createHash("sha256").update(rpId).digest();
  const clientData = (type, challenge, o = origin) => Buffer.from(JSON.stringify({ type, challenge, origin: o }));
  return {
    id: credId.toString("base64url"),
    create(challenge, o) {
      const cose = cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, "base64url")], [-3, Buffer.from(jwk.y, "base64url")]]));
      const len = Buffer.alloc(2); len.writeUInt16BE(credId.length);
      const authData = Buffer.concat([rpHash, Buffer.from([0x45]), Buffer.alloc(4), Buffer.alloc(16), len, credId, cose]);
      return { id: credId.toString("base64url"), response: { clientDataJSON: clientData("webauthn.create", challenge, o).toString("base64url"), attestationObject: cbor({ fmt: "none", attStmt: new Map(), authData }).toString("base64url") } };
    },
    get(challenge, { replayCounter = false } = {}) {
      if (!replayCounter) counter++;
      const count = Buffer.alloc(4); count.writeUInt32BE(counter);
      const authData = Buffer.concat([rpHash, Buffer.from([0x05]), count]);
      const cd = clientData("webauthn.get", challenge);
      const signature = sign("sha256", Buffer.concat([authData, createHash("sha256").update(cd).digest()]), privateKey);
      return { id: credId.toString("base64url"), response: { clientDataJSON: cd.toString("base64url"), authenticatorData: authData.toString("base64url"), signature: signature.toString("base64url") } };
    },
  };
}

test("P0 security: passkeys, cross-signing, key backup, reports, admin tooling and the authorization matrix", async () => {
  const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
  try {
    await ready();
    const sfx = Math.random().toString(36).slice(2, 7);
    const owner = await seed(pool, "own_" + sfx), mod = await seed(pool, "mod_" + sfx), member = await seed(pool, "mem_" + sfx);
    const outsider = await seed(pool, "out_" + sfx), banned = await seed(pool, "ban_" + sfx), former = await seed(pool, "old_" + sfx);
    const admin = await seed(pool, "adm_" + sfx), victim = await seed(pool, "vic_" + sfx);
    await pool.query("UPDATE users SET is_admin=true WHERE id=$1", [admin.id]);
    assert.equal((await call("/api/v10/users/@me", "GET", undefined, admin.token)).data.is_admin, true);

    // ---------------------------------------------------------------- community fixture
    const g = (await call("/api/v10/guilds", "POST", { name: "Matrix" }, owner.token)).data;
    const G = g.id, C = g.channels[0].id;
    const invite = (await call(`/api/v1/guilds/${G}/invites`, "POST", { max_uses: 20, expires_hours: 1 }, owner.token)).data.code;
    for (const u of [mod, member, banned, former, victim]) assert.equal((await call(`/api/v1/invites/${invite}/join`, "POST", undefined, u.token)).status, 200);
    const MOD_PERMS = (1n << 1n) | (1n << 2n) | (1n << 3n) | (1n << 4n) | (1n << 5n) | (1n << 9n) | (1n << 12n);
    const role = (await call(`/api/v1/guilds/${G}/roles`, "POST", { name: "mods", permissions: MOD_PERMS.toString() }, owner.token)).data;
    assert.equal((await call(`/api/v1/guilds/${G}/members/${mod.id}/roles/${role.id}`, "PUT", undefined, owner.token)).status, 204);
    assert.equal((await call(`/api/v1/guilds/${G}/bans/${banned.id}`, "PUT", { reason: "matrix" }, owner.token)).status, 204);
    assert.equal((await call(`/api/v1/guilds/${G}/members/${former.id}`, "DELETE", undefined, former.token)).status, 204);
    const M = (await call(`/api/v10/channels/${C}/messages`, "POST", { ciphertext: "opaque-matrix", algorithm: "client-encrypted-v1" }, owner.token)).data.id;

    // ---------------------------------------------------------------- authorization matrix
    // ok = 2xx, deny = 403/404, unauth = 401. Every actor is checked against every route.
    const actors = { anon: null, outsider, banned, former, member, mod, owner };
    const insiders = { member: "ok", mod: "ok", owner: "ok" };
    const modsOnly = { member: "deny", mod: "ok", owner: "ok" };
    const ownerOnly = { member: "deny", mod: "deny" }; // owner skipped: destructive
    let n = 0;
    const routes = [
      ["GET", `/api/v1/guilds/${G}`, undefined, insiders],
      ["GET", `/api/v10/guilds/${G}/channels`, undefined, insiders],
      ["GET", `/api/v1/guilds/${G}/members`, undefined, insiders],
      ["GET", `/api/v1/guilds/${G}/roles`, undefined, insiders],
      ["GET", `/api/v1/guilds/${G}/bots`, undefined, insiders],
      ["GET", `/api/v10/channels/${C}/messages`, undefined, insiders],
      ["GET", `/api/v10/channels/${C}/pins`, undefined, insiders],
      ["GET", `/api/v10/channels/${C}/deletions`, undefined, insiders],
      ["GET", `/api/v1/channels/${C}/keys`, undefined, insiders],
      ["GET", `/api/v1/guilds/${G}/audit-log`, undefined, modsOnly],
      ["GET", `/api/v1/guilds/${G}/bans`, undefined, modsOnly],
      ["GET", `/api/v1/guilds/${G}/invites`, undefined, modsOnly],
      ["PATCH", `/api/v1/guilds/${G}`, () => ({ description: "matrix " + n++ }), modsOnly],
      ["POST", `/api/v1/guilds/${G}/channels`, () => ({ name: "matrix-" + n++ }), modsOnly],
      ["PATCH", `/api/v1/channels/${C}`, () => ({ topic: "topic " + n++ }), modsOnly],
      ["POST", `/api/v1/guilds/${G}/roles`, () => ({ name: "r" + n++ }), modsOnly],
      ["PUT", `/api/v10/channels/${C}/pins/${M}`, undefined, modsOnly],
      ["POST", `/api/v1/guilds/${G}/invites`, () => ({ max_uses: 1, expires_hours: 1 }), insiders],
      ["POST", `/api/v10/channels/${C}/messages`, () => ({ ciphertext: "opaque-" + n++, algorithm: "client-encrypted-v1" }), insiders],
      ["PUT", `/api/v10/channels/${C}/messages/${M}/reactions/${encodeURIComponent("👍")}/@me`, undefined, insiders],
      ["PATCH", `/api/v10/channels/${C}/messages/${M}`, () => ({ ciphertext: "edited", algorithm: "client-encrypted-v1" }), { member: "deny", mod: "deny", owner: "ok" }],
      ["POST", `/api/v1/channels/${C}/ack`, () => ({}), insiders],
      ["POST", `/api/v1/channels/${C}/keys/request`, undefined, insiders],
      ["DELETE", `/api/v1/guilds/${G}`, undefined, ownerOnly],
      ["POST", `/api/v1/guilds/${G}/transfer`, () => ({ user_id: member.id }), ownerOnly],
      ["POST", `/api/v1/guilds/${G}/bots`, () => ({ app_id: randomUUID() }), { member: "deny", mod: "deny" }],
      ["GET", "/api/v1/admin/stats", undefined, { member: "deny", mod: "deny", owner: "deny" }],
      ["GET", "/api/v1/admin/reports", undefined, { member: "deny", mod: "deny", owner: "deny" }],
    ];
    const failures = [];
    let checks = 0;
    for (const [method, path, body, expectations] of routes) {
      for (const [name, actor] of Object.entries(actors)) {
        const expected = name === "anon" ? "unauth" : ["outsider", "banned", "former"].includes(name) ? (path.startsWith("/api/v1/admin") ? "deny" : "deny") : expectations[name];
        if (!expected) continue;
        checks++;
        const res = await call(path, method, typeof body === "function" ? body() : body, actor?.token);
        const got = res.status === 401 ? "unauth" : res.status >= 200 && res.status < 300 ? "ok" : (res.status === 403 || res.status === 404) ? "deny" : "status " + res.status;
        if (got !== expected) failures.push(`${name} ${method} ${path} → ${res.status} (expected ${expected})`);
      }
    }
    assert.deepEqual(failures, [], "authorization matrix violations:\n" + failures.join("\n"));
    assert.ok(checks >= 180, "matrix ran only " + checks + " checks");
    // Hierarchy: a moderator cannot kick/ban/edit the owner or their own top role.
    assert.equal((await call(`/api/v1/guilds/${G}/members/${owner.id}`, "DELETE", undefined, mod.token)).status, 403);
    assert.equal((await call(`/api/v1/guilds/${G}/bans/${owner.id}`, "PUT", {}, mod.token)).status, 403);
    assert.equal((await call(`/api/v1/guilds/${G}/roles/${role.id}`, "PATCH", { name: "x" }, mod.token)).status, 403);
    assert.equal((await call(`/api/v1/guilds/${G}/roles`, "POST", { name: "admin", permissions: "1" }, mod.token)).status, 403);

    // ---------------------------------------------------------------- passkeys
    const origin = base, auth = authenticator(origin, "127.0.0.1");
    assert.equal((await call("/api/v1/auth/passkeys/register/options", "POST", { password: "wrong password here" }, member.token)).status, 401);
    let opts = (await call("/api/v1/auth/passkeys/register/options", "POST", { password: pw }, member.token)).data;
    assert.equal(opts.rp.id, "127.0.0.1");
    assert.equal((await call("/api/v1/auth/passkeys/register", "POST", { credential: auth.create(opts.challenge, "https://evil.example") }, member.token)).status, 400, "wrong origin");
    opts = (await call("/api/v1/auth/passkeys/register/options", "POST", { password: pw }, member.token)).data;
    const reg = await call("/api/v1/auth/passkeys/register", "POST", { name: "Test key", credential: auth.create(opts.challenge) }, member.token);
    assert.equal(reg.status, 201);
    assert.equal((await call("/api/v1/auth/passkeys/register", "POST", { credential: auth.create(opts.challenge) }, member.token)).status, 400, "challenge is single-use");
    let login = (await call("/api/v1/auth/passkeys/login/options", "POST", {})).data;
    assert.deepEqual(login.allowCredentials, [], "no credential enumeration");
    const signedIn = await call("/api/v1/auth/passkeys/login", "POST", { credential: auth.get(login.challenge) });
    assert.equal(signedIn.status, 200);
    assert.equal((await call("/api/v10/users/@me", "GET", undefined, signedIn.data.token)).data.id, member.id);
    login = (await call("/api/v1/auth/passkeys/login/options", "POST", {})).data;
    assert.equal((await call("/api/v1/auth/passkeys/login", "POST", { credential: auth.get(login.challenge, { replayCounter: true }) })).status, 401, "cloned authenticator counter");
    assert.equal((await call("/api/v1/auth/passkeys/login", "POST", { credential: auth.get("never-issued-challenge") })).status, 401);
    assert.equal((await call("/api/v1/auth/passkeys", "GET", undefined, member.token)).data.length, 1);

    // ---------------------------------------------------------------- device cross-signing
    const enroll = async (who, name) => {
      const device = await createDevice(), bundle = await publicBundle(device), fp = await fingerprint(bundle);
      const r = await call("/api/v1/devices", "POST", { name, identity_key: fp, public_bundle: bundle, password: pw }, who.token);
      assert.equal(r.status, 201);
      return { device, fp, id: r.data.id };
    };
    const d1 = await enroll(member, "phone"), d2 = await enroll(member, "laptop"), other = await enroll(mod, "mod-phone");
    const att = await attestDevice(d1.device, member.id, d2.id, d2.fp);
    assert.equal((await call(`/api/v1/devices/${d2.id}/attestation`, "PUT", { signer_device_id: d1.id, signature: att.slice(0, -4) + "AAAA" }, member.token)).status, 400, "bad signature");
    assert.equal((await call(`/api/v1/devices/${d2.id}/attestation`, "PUT", { signer_device_id: other.id, signature: att }, member.token)).status, 404, "signer must be own device");
    const forged = await attestDevice(other.device, member.id, d2.id, d2.fp);
    assert.equal((await call(`/api/v1/devices/${d2.id}/attestation`, "PUT", { signer_device_id: d1.id, signature: forged }, member.token)).status, 400, "signature must come from the named signer");
    assert.equal((await call(`/api/v1/devices/${d2.id}/attestation`, "PUT", { signer_device_id: d1.id, signature: att }, member.token)).status, 204);
    const keyState = (await call(`/api/v1/channels/${C}/keys`, "GET", undefined, mod.token)).data;
    assert.equal(keyState.recipients.find((r) => r.id === d2.id).attestation.signer_device_id, d1.id);

    // ---------------------------------------------------------------- key backup
    assert.equal((await call("/api/v1/users/@me/key-backup", "GET", undefined, member.token)).data.version, 0);
    assert.equal((await call("/api/v1/users/@me/key-backup", "PUT", { version: 2, ciphertext: "x" }, member.token)).status, 409);
    assert.equal((await call("/api/v1/users/@me/key-backup", "PUT", { version: 1, ciphertext: "blob-1" }, member.token)).status, 200);
    assert.equal((await call("/api/v1/users/@me/key-backup", "PUT", { version: 1, ciphertext: "stale" }, member.token)).status, 409, "no lost updates");
    assert.equal((await call("/api/v1/users/@me/key-backup", "PUT", { version: 2, ciphertext: "blob-2" }, member.token)).status, 200);
    assert.equal((await call("/api/v1/users/@me/key-backup", "GET", undefined, member.token)).data.ciphertext, "blob-2");
    assert.equal((await call("/api/v1/users/@me/key-backup", "GET", undefined, mod.token)).data.ciphertext, null, "backups are per account");

    // ---------------------------------------------------------------- reports and administration
    assert.equal((await call("/api/v1/reports", "POST", { target_type: "message", target_id: M, reason: "spam" }, outsider.token)).status, 404, "cannot report what you cannot see");
    const report = await call("/api/v1/reports", "POST", { target_type: "message", target_id: M, reason: "spam", evidence: "buy now" }, member.token);
    assert.equal(report.status, 201);
    assert.equal((await call("/api/v1/reports", "POST", { target_type: "user", target_id: victim.id, reason: "abuse" }, member.token)).status, 201);
    const open = (await call("/api/v1/admin/reports", "GET", undefined, admin.token)).data;
    const mine = open.find((r) => r.id === report.data.id);
    assert.equal(mine.evidence, "buy now");
    assert.equal(mine.target_user, owner.name);
    assert.equal((await call(`/api/v1/admin/reports/${report.data.id}`, "POST", { status: "resolved", note: "handled" }, admin.token)).status, 204);
    assert.ok((await call("/api/v1/admin/reports?status=resolved", "GET", undefined, admin.token)).data.some((r) => r.id === report.data.id));
    assert.ok((await call("/api/v1/admin/users?q=" + sfx, "GET", undefined, admin.token)).data.length >= 8);
    assert.equal((await call(`/api/v1/admin/messages/${M}`, "DELETE", undefined, admin.token)).status, 204);
    // Suspension: sessions revoked immediately, login refused (only after a correct password), then restored.
    assert.equal((await call(`/api/v1/admin/users/${admin.id}/suspend`, "POST", {}, admin.token)).status, 400);
    assert.equal((await call(`/api/v1/admin/users/${victim.id}/suspend`, "POST", { reason: "test" }, member.token)).status, 403);
    assert.equal((await call(`/api/v1/admin/users/${victim.id}/suspend`, "POST", { reason: "test" }, admin.token)).status, 204);
    assert.equal((await call("/api/v10/users/@me", "GET", undefined, victim.token)).status, 401);
    assert.equal((await call("/api/v1/auth/login", "POST", { username: victim.name, password: "not the password" })).status, 401);
    assert.equal((await call("/api/v1/auth/login", "POST", { username: victim.name, password: pw })).status, 403);
    assert.equal((await call(`/api/v1/admin/users/${victim.id}/unsuspend`, "POST", undefined, admin.token)).status, 204);
    const back = await call("/api/v1/auth/login", "POST", { username: victim.name, password: pw });
    assert.equal(back.status, 200);
    // Self-service deletion: owners must hand over servers first; members can leave for good.
    assert.equal((await call("/api/v1/users/@me", "DELETE", { password: pw }, owner.token)).status, 409);
    assert.equal((await call("/api/v1/users/@me", "DELETE", { password: "not the password" }, back.data.token)).status, 401);
    await call(`/api/v10/channels/${C}/messages`, "POST", { ciphertext: "victim-says", algorithm: "client-encrypted-v1" }, back.data.token);
    assert.equal((await call("/api/v1/users/@me", "DELETE", { password: pw }, back.data.token)).status, 204);
    assert.equal((await pool.query("SELECT count(*)::int AS n FROM users WHERE id=$1", [victim.id])).rows[0].n, 0);
    // Admin deletion removes owned communities too; takedown removes a community for everyone.
    const doomed = await seed(pool, "doom_" + sfx);
    const doomedGuild = (await call("/api/v10/guilds", "POST", { name: "Doomed" }, doomed.token)).data.id;
    assert.equal((await call(`/api/v1/admin/users/${doomed.id}`, "DELETE", undefined, admin.token)).status, 204);
    assert.equal((await pool.query("SELECT count(*)::int AS n FROM guilds WHERE id=$1", [doomedGuild])).rows[0].n, 0);
    assert.equal((await call(`/api/v1/admin/guilds/${G}`, "DELETE", undefined, member.token)).status, 403);
    assert.equal((await call(`/api/v1/admin/guilds/${G}`, "DELETE", undefined, admin.token)).status, 204);
    assert.equal((await call(`/api/v1/guilds/${G}`, "GET", undefined, owner.token)).status, 403);
  } finally {
    if (process.env.SHOW_API_LOG) console.error(log.split(/\r?\n/).filter((l) => /"level":(50|40)/.test(l)).join("\n"));
    await pool.end();
    api.kill("SIGTERM");
    await Promise.race([new Promise((r) => api.once("exit", r)), sleep(3000)]);
  }
}, { timeout: 90000 });
