import test from "node:test";
import assert from "node:assert/strict";
const { createDevice, publicBundle, fingerprint, encryptMessage, decryptMessage } = await import("../apps/web/crypto.mjs");
const { createKeyring, TrustStore, keyCommitment, safetyNumber, signEnvelope, attestDevice, evaluateDevices, generateRecoveryKey, normalizeRecoveryKey, encryptBackup, decryptBackup, sealForDevice, openForDevice } = await import("../apps/web/e2ee.mjs");

// PostgreSQL jsonb re-orders object keys; the fake server stores grants the same way.
function jsonbRoundTrip(value) {
  if (Array.isArray(value)) return value.map(jsonbRoundTrip);
  if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort((a, b) => a.length - b.length || (a < b ? -1 : 1)).map((k) => [k, jsonbRoundTrip(value[k])]));
  return value;
}
// Minimal in-memory model of the /api/v1/channels/:id/keys endpoints.
function fakeServer() {
  const s = { epoch: 1, devices: [], grants: new Map(), claims: new Map() };
  s.handler = (userId) => async (path, method = "GET", body) => {
    const m = /^\/api\/v1\/channels\/([^/]+)\/keys(?:\/(claim|request|[^/]+))?$/.exec(path);
    if (!m) throw Error("unexpected " + path);
    const [, channel, sub] = m;
    const key = (e, d) => `${channel}|${e}|${d}`;
    if (method === "GET") {
      const mineIds = s.devices.filter((d) => d.user_id === userId).map((d) => d.id);
      return {
        epoch: s.epoch,
        recipients: s.devices,
        wrapped: [...s.grants.entries()].filter(([k]) => k.startsWith(`${channel}|${s.epoch}|`) && mineIds.includes(k.split("|")[2])).map(([k, v]) => ({ device_id: k.split("|")[2], wrapped_key: v })),
        granted_device_ids: [...s.grants.keys()].filter((k) => k.startsWith(`${channel}|${s.epoch}|`)).map((k) => k.split("|")[2]),
        claim: s.claims.get(`${channel}|${s.epoch}`) ?? null,
        history: [...s.grants.entries()].filter(([k]) => { const [, e, d] = k.split("|"); return Number(e) < s.epoch && mineIds.includes(d); }).map(([k, v]) => ({ epoch: Number(k.split("|")[1]), device_id: k.split("|")[2], wrapped_key: v, key_commitment: s.claims.get(`${channel}|${k.split("|")[1]}`)?.key_commitment })),
      };
    }
    if (sub === "claim") {
      const id = `${channel}|${body.epoch}`;
      if (s.claims.has(id) || body.epoch !== s.epoch) throw Error("409");
      s.claims.set(id, { creator_device_id: body.device_id, key_commitment: body.key_commitment });
      return { claimed: true };
    }
    if (method === "PUT") {
      const k = key(body.epoch, sub);
      if (s.grants.has(k)) throw Error("409");
      s.grants.set(k, jsonbRoundTrip(JSON.parse(JSON.stringify(body.wrapped_key))));
      return {};
    }
    return null;
  };
  return s;
}
let clock = 0;
async function member(server, userId, name, deviceId = name + "-device") {
  const device = await createDevice(), bundle = await publicBundle(device);
  server.devices.push({ id: deviceId, user_id: userId, username: name, identity_key: await fingerprint(bundle), public_bundle: bundle, created_at: String(++clock).padStart(6, "0") });
  const memory = new Map();
  const storage = { getItem: (k) => memory.get(k) ?? null, setItem: (k, v) => memory.set(k, v) };
  const warnings = [];
  const keyring = createKeyring({ request: server.handler(userId), getDevice: () => device, selfId: () => userId, trust: new TrustStore(storage), onWarning: (w) => warnings.push(w) });
  return { device, keyring, warnings };
}

test("first member claims an epoch key and shares it with every verified member device", async () => {
  const server = fakeServer();
  const alice = await member(server, "u-alice", "alice"), bob = await member(server, "u-bob", "bob");
  assert.equal((await alice.keyring.sync("room")).status, "ready");
  assert.equal(server.claims.size, 1);
  assert.equal(server.grants.size, 2, "alice wraps for herself and bob");
  assert.equal((await bob.keyring.sync("room")).status, "ready");
  const context = { room: "room", sender: "u-alice", epoch: 1 };
  const envelope = await encryptMessage(alice.keyring.key("room", 1), "hello bob", context);
  assert.equal(await decryptMessage(bob.keyring.key("room", 1), envelope, context), "hello bob");
  // Commitment is deterministic for a key and bound to channel/epoch.
  const k = alice.keyring.key("room", 1);
  assert.equal(await keyCommitment(k, "room", 1), server.claims.get("room|1").key_commitment);
  assert.notEqual(await keyCommitment(k, "room", 2), server.claims.get("room|1").key_commitment);
});

test("new epochs get new keys; history remains readable; late joiners cannot read old epochs", async () => {
  const server = fakeServer();
  const alice = await member(server, "u-alice", "alice"), bob = await member(server, "u-bob", "bob");
  await alice.keyring.sync("room");
  await bob.keyring.sync("room");
  server.epoch = 2; // membership change
  const carol = await member(server, "u-carol", "carol");
  await bob.keyring.sync("room"); // bob creates epoch 2 and shares with alice + carol
  await alice.keyring.sync("room");
  assert.ok(alice.keyring.key("room", 1) && alice.keyring.key("room", 2));
  await carol.keyring.sync("room");
  assert.ok(carol.keyring.key("room", 2));
  assert.equal(carol.keyring.key("room", 1), null, "joiners do not receive keys for earlier epochs");
});

test("forked keys and substituted device identities are rejected", async () => {
  const server = fakeServer();
  const alice = await member(server, "u-alice", "alice"), bob = await member(server, "u-bob", "bob");
  await alice.keyring.sync("room");
  await bob.keyring.sync("room"); // bob pins alice's device
  // A malicious server publishes a different commitment for epoch 2 than the key it delivers.
  server.epoch = 2;
  await alice.keyring.sync("room");
  server.claims.set("room|2", { creator_device_id: "alice-device", key_commitment: "x".repeat(43) });
  await bob.keyring.sync("room");
  assert.equal(bob.keyring.key("room", 2), null);
  assert.ok(bob.warnings.some((w) => /commitment/.test(w)));
  // The server swaps alice's device key: bob refuses to share future keys with it.
  server.epoch = 3;
  const impostor = await publicBundle(await createDevice());
  const record = server.devices.find((d) => d.id === "alice-device");
  record.public_bundle = impostor;
  record.identity_key = await fingerprint(impostor);
  await bob.keyring.sync("room");
  assert.equal(server.grants.has("room|3|alice-device"), false);
  assert.ok(bob.warnings.some((w) => /changed its identity key/.test(w)));
  assert.match(await safetyNumber(record.identity_key), /^(\d{5} ){9}\d{5}$/);
});

test("messages are signed by the sender device and verified against the author", async () => {
  const server = fakeServer();
  const alice = await member(server, "u-alice", "alice"), bob = await member(server, "u-bob", "bob");
  await alice.keyring.sync("room"); await bob.keyring.sync("room");
  const context = { room: "room", sender: "u-alice", epoch: 1 };
  const signed = await signEnvelope(await encryptMessage(alice.keyring.key("room", 1), "signed hello", context), alice.device, "alice-device");
  assert.equal(await bob.keyring.verifyMessage(signed, "u-alice"), "verified");
  assert.equal(await bob.keyring.verifyMessage(signed, "u-bob"), "invalid", "signer must belong to the author");
  assert.equal(await bob.keyring.verifyMessage({ ...signed, ciphertext: signed.ciphertext.slice(0, -2) + "AA" }, "u-alice"), "invalid");
  const { sig, ...unsigned } = signed;
  assert.equal(await bob.keyring.verifyMessage(unsigned, "u-alice"), "unsigned");
  assert.equal(await bob.keyring.verifyMessage({ ...signed, sig: { ...sig, device: "nope" } }, "u-alice"), "unknown-device");
});

test("cross-signing: a new device gets keys only after an existing device of the same account approves it", async () => {
  const server = fakeServer();
  const alice = await member(server, "u-alice", "alice"), bob = await member(server, "u-bob", "bob");
  await alice.keyring.sync("room"); await bob.keyring.sync("room");
  // Alice adds a laptop; a malicious server also injects a device for Bob.
  const laptop = await member(server, "u-alice", "alice", "alice-laptop");
  const fake = await member(server, "u-bob", "bob", "bob-fake");
  server.epoch = 2;
  await bob.keyring.sync("room");
  assert.equal(server.grants.has("room|2|alice-laptop"), false, "unapproved devices receive no keys");
  assert.equal(server.grants.has("room|2|bob-fake"), false, "injected devices receive no keys, even from their own account");
  // Alice's original device approves the laptop.
  const laptopRecord = server.devices.find((d) => d.id === "alice-laptop");
  laptopRecord.attestation = { signer_device_id: "alice-device", signature: await attestDevice(alice.device, "u-alice", "alice-laptop", laptopRecord.identity_key) };
  // A forged attestation (signed by Bob's device for Bob's fake device) is rejected: wrong account chain.
  const fakeRecord = server.devices.find((d) => d.id === "bob-fake");
  fakeRecord.attestation = { signer_device_id: "alice-device", signature: await attestDevice(bob.device, "u-bob", "bob-fake", fakeRecord.identity_key) };
  server.epoch = 3;
  await bob.keyring.sync("room");
  assert.ok(server.grants.has("room|3|alice-laptop"), "approved device receives the key");
  assert.equal(server.grants.has("room|3|bob-fake"), false);
  assert.equal((await laptop.keyring.sync("room")).status, "ready");
  const statuses = await evaluateDevices(server.devices, new TrustStore(null), "nobody");
  assert.equal(statuses.get("alice-laptop"), "attested");
  assert.equal(statuses.get("bob-fake"), "unattested");
  void fake;
});

test("recovery-key backups restore room keys on a fresh device", async () => {
  const server = fakeServer();
  const alice = await member(server, "u-alice", "alice");
  await alice.keyring.sync("room");
  const recovery = generateRecoveryKey();
  assert.match(recovery, /^([A-Z2-9]{4}-){7}[A-Z2-9]{4}$/);
  assert.equal(normalizeRecoveryKey(recovery.toLowerCase().replace(/-/g, " ")), recovery);
  assert.throws(() => normalizeRecoveryKey("short"));
  const blob = await encryptBackup(await alice.keyring.exportKeys(), recovery, "u-alice");
  await assert.rejects(decryptBackup(blob, generateRecoveryKey(), "u-alice"), /Wrong recovery key/);
  await assert.rejects(decryptBackup(blob, recovery, "u-mallory"), /Wrong recovery key/, "bound to the account");
  const restored = createKeyring({ request: server.handler("u-alice"), getDevice: () => null, selfId: () => "u-alice", trust: new TrustStore(null) });
  assert.equal(await restored.importKeys(await decryptBackup(blob, recovery, "u-alice")), 1);
  const context = { room: "room", sender: "u-alice", epoch: 1 };
  const envelope = await encryptMessage(alice.keyring.key("room", 1), "from the past", context);
  assert.equal(await decryptMessage(restored.key("room", 1), envelope, context), "from the past");
  const sealed = await sealForDevice(alice.device, recovery);
  assert.equal(await openForDevice(alice.device, sealed), recovery);
  await assert.rejects(openForDevice(await createDevice(), sealed));
});
