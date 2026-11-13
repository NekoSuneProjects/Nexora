// Multi-member room-key orchestration on top of crypto.mjs primitives.
// PROTOTYPE: per-epoch room keys, signed grants, signed messages, device cross-signing
// (a new device must be attested by an existing device of the same account), TOFU for an
// account's first device, and recovery-key backups. NOT an audited protocol and NOT MLS.
import { publicBundle, fingerprint, createRoomKey, wrapRoomKey, unwrapRoomKey, canonicalJson } from "./crypto.mjs";

const encoder = new TextEncoder(), decoder = new TextDecoder();
const subtle = globalThis.crypto.subtle;
const b64 = (bytes) => { let s = ""; for (const x of new Uint8Array(bytes)) s += String.fromCharCode(x); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, ""); };
const un64 = (text) => { if (typeof text !== "string" || !/^[A-Za-z0-9_-]*$/.test(text)) throw Error("Invalid base64url"); const s = atob(text.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - text.length % 4) % 4)); return Uint8Array.from(s, (c) => c.charCodeAt(0)); };
const importVerifyKey = (jwk) => subtle.importKey("jwk", { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y }, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
const ECDSA = { name: "ECDSA", hash: "SHA-256" };

/** HMAC commitment to a room key, published with the epoch claim so members detect forks. */
export async function keyCommitment(key, channelId, epoch) {
  const raw = await subtle.exportKey("raw", key);
  const mac = await subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64(await subtle.sign("HMAC", mac, encoder.encode("nexora-key-commitment-v1|" + channelId + "|" + epoch)));
}

// ------------------------------------------------------------------ message signatures
const messageStatement = (envelope) => encoder.encode(canonicalJson({ type: "nexora-message-v1", v: envelope.v, nonce: envelope.nonce, ciphertext: envelope.ciphertext, context: envelope.context }));
/** Adds the sender device's ECDSA signature over the whole envelope (binds room, sender, epoch). */
export async function signEnvelope(envelope, device, deviceId) {
  const signature = await subtle.sign(ECDSA, device.signing.privateKey, messageStatement(envelope));
  return { ...envelope, sig: { device: deviceId, signature: b64(signature) } };
}
/** True when `bundle` signed this envelope. */
export async function verifyEnvelopeSignature(envelope, bundle) {
  try { return await subtle.verify(ECDSA, await importVerifyKey(bundle.signing), un64(envelope.sig.signature), messageStatement(envelope)); }
  catch { return false; }
}

// ------------------------------------------------------------------ device cross-signing
/** Identical to apps/api/src/security.ts attestationStatement. */
const attestationStatement = (userId, deviceId, fp) => encoder.encode(canonicalJson({ type: "nexora-device-attestation-v1", user_id: userId, device_id: deviceId, fingerprint: fp }));
export async function attestDevice(device, userId, targetDeviceId, targetFingerprint) {
  return b64(await subtle.sign(ECDSA, device.signing.privateKey, attestationStatement(userId, targetDeviceId, targetFingerprint)));
}
export async function verifyAttestation(signerBundle, userId, deviceId, fp, signature) {
  try { return await subtle.verify(ECDSA, await importVerifyKey(signerBundle.signing), un64(signature), attestationStatement(userId, deviceId, fp)); }
  catch { return false; }
}

/** Trust-on-first-use pins: device ID -> fingerprint, plus manual verification marks. */
export class TrustStore {
  constructor(storage, key = "nexora-device-trust-v1") {
    this.storage = storage; this.key = key;
    try { this.data = JSON.parse(storage?.getItem(key) ?? "{}"); } catch { this.data = {}; }
  }
  save() { try { this.storage?.setItem(this.key, JSON.stringify(this.data)); } catch {} }
  /** Returns "new" (now pinned), "pinned", "verified" or "changed" (key substitution!). */
  observe(deviceId, fp) {
    const entry = this.data[deviceId];
    if (!entry) { this.data[deviceId] = { fp, verified: false, first_seen: Date.now() }; this.save(); return "new"; }
    if (entry.fp !== fp) return "changed";
    return entry.verified ? "verified" : "pinned";
  }
  status(deviceId, fp) {
    const entry = this.data[deviceId];
    if (!entry) return "unknown";
    if (entry.fp !== fp) return "changed";
    return entry.verified ? "verified" : "pinned";
  }
  knowsFingerprint(fp) { return Object.values(this.data).some((e) => e.fp === fp); }
  verify(deviceId, fp) { this.data[deviceId] = { fp, verified: true, first_seen: this.data[deviceId]?.first_seen ?? Date.now() }; this.save(); }
  forget(deviceId) { delete this.data[deviceId]; this.save(); }
}
/** Statuses that may receive room keys and whose signatures are accepted. */
export const TRUSTED = new Set(["self", "verified", "pinned", "attested"]);

/**
 * Decides which devices to trust. Per account: previously pinned/verified devices stay trusted;
 * on first sight of an account its root device (earliest, unattested) is trusted on first use;
 * every other device must carry a valid attestation from an already-trusted device of the
 * SAME account. A server that silently adds a device for someone therefore cannot get keys.
 * Returns Map(deviceId -> "self"|"verified"|"pinned"|"attested"|"unattested"|"changed"|"invalid").
 */
export async function evaluateDevices(records, trust, ownFingerprint) {
  const result = new Map(), byUser = new Map();
  for (const r of records) { if (!byUser.has(r.user_id)) byUser.set(r.user_id, []); byUser.get(r.user_id).push(r); }
  for (const [userId, devices] of byUser) {
    devices.sort((a, b) => String(a.created_at ?? "").localeCompare(String(b.created_at ?? "")));
    const accepted = new Map();
    let othersAccepted = 0;
    for (const d of devices) {
      if (!d.public_bundle || (await fingerprint(d.public_bundle)) !== d.identity_key) { result.set(d.id, "invalid"); continue; }
      if (d.identity_key === ownFingerprint) { result.set(d.id, "self"); accepted.set(d.id, d); continue; }
      const s = trust.status(d.id, d.identity_key);
      if (s === "changed") result.set(d.id, "changed");
      else if (s === "pinned" || s === "verified") { result.set(d.id, s); accepted.set(d.id, d); othersAccepted++; }
    }
    if (!othersAccepted) {
      const root = devices.find((d) => !result.has(d.id) && !d.attestation);
      if (root && (accepted.size === 0 || devices[0] === root)) { trust.observe(root.id, root.identity_key); result.set(root.id, "pinned"); accepted.set(root.id, root); }
    }
    for (let progress = true; progress;) {
      progress = false;
      for (const d of devices) {
        if (result.has(d.id) || !d.attestation) continue;
        const signer = accepted.get(d.attestation.signer_device_id);
        if (signer && (await verifyAttestation(signer.public_bundle, userId, d.id, d.identity_key, d.attestation.signature))) {
          trust.observe(d.id, d.identity_key); result.set(d.id, "attested"); accepted.set(d.id, d); progress = true;
        }
      }
    }
    for (const d of devices) if (!result.has(d.id)) result.set(d.id, "unattested");
  }
  return result;
}

/** Human-comparable safety number for a fingerprint (groups of 5 digits). */
export async function safetyNumber(fp) {
  const digest = new Uint8Array(await subtle.digest("SHA-256", encoder.encode("nexora-safety-v1|" + fp)));
  let out = "";
  for (let i = 0; i < 30; i += 3) out += String(((digest[i] << 16) | (digest[i + 1] << 8) | digest[i + 2]) % 100000).padStart(5, "0") + " ";
  return out.trim();
}

// ------------------------------------------------------------------ recovery-key backups
const BASE32 = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no I, O, 0, 1
/** 160-bit recovery key formatted for humans: 8 groups of 4 characters. */
export function generateRecoveryKey() {
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  let bits = 0, acc = 0, out = "";
  for (const byte of bytes) { acc = (acc << 8) | byte; bits += 8; while (bits >= 5) { bits -= 5; out += BASE32[(acc >> bits) & 31]; } }
  return out.match(/.{4}/g).join("-");
}
export function normalizeRecoveryKey(text) {
  const clean = String(text).toUpperCase().replace(/[^A-Z0-9]/g, "");
  if (clean.length !== 32 || [...clean].some((c) => !BASE32.includes(c))) throw Error("That is not a valid recovery key");
  return clean.match(/.{4}/g).join("-");
}
async function backupKey(recoveryKey) {
  const base = await subtle.importKey("raw", encoder.encode(normalizeRecoveryKey(recoveryKey)), "HKDF", false, ["deriveKey"]);
  return subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: encoder.encode("nexora-key-backup-salt-v1"), info: encoder.encode("nexora-key-backup-v1") }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
/** keys: { channelId: { epoch: base64urlRawKey } } */
export async function encryptBackup(keys, recoveryKey, userId) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await subtle.encrypt({ name: "AES-GCM", iv, additionalData: encoder.encode("nexora-key-backup-v1|" + userId) }, await backupKey(recoveryKey), encoder.encode(JSON.stringify({ v: 1, keys })));
  return JSON.stringify({ v: 1, iv: b64(iv), ct: b64(ct) });
}
export async function decryptBackup(ciphertext, recoveryKey, userId) {
  const box = JSON.parse(ciphertext);
  if (box.v !== 1) throw Error("Unsupported backup");
  let raw;
  try { raw = await subtle.decrypt({ name: "AES-GCM", iv: un64(box.iv), additionalData: encoder.encode("nexora-key-backup-v1|" + userId) }, await backupKey(recoveryKey), un64(box.ct)); }
  catch { throw Error("Wrong recovery key, or the backup was tampered with"); }
  const data = JSON.parse(decoder.decode(raw));
  return data.keys ?? {};
}
/** A key only this device can derive (ECDH with itself), used to keep the recovery key at rest. */
async function deviceLocalKey(device) {
  const bits = await subtle.deriveBits({ name: "ECDH", public: device.agreement.publicKey }, device.agreement.privateKey, 256);
  const base = await subtle.importKey("raw", bits, "HKDF", false, ["deriveKey"]);
  return subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: encoder.encode("nexora-device-local-v1") }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
export async function sealForDevice(device, text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  return JSON.stringify({ iv: b64(iv), ct: b64(await subtle.encrypt({ name: "AES-GCM", iv }, await deviceLocalKey(device), encoder.encode(text))) });
}
export async function openForDevice(device, sealed) {
  const box = JSON.parse(sealed);
  return decoder.decode(await subtle.decrypt({ name: "AES-GCM", iv: un64(box.iv) }, await deviceLocalKey(device), un64(box.ct)));
}

/**
 * request(path, method, body) -> JSON (throws on non-2xx); getDevice() -> unlocked device or null;
 * selfId() -> current user ID; onWarning(message) for trust problems; onNewKey() after any key is learnt.
 */
export function createKeyring({ request, getDevice, selfId, trust, onWarning = () => {}, onNewKey = () => {} }) {
  const rooms = new Map();
  const inflight = new Map();
  const devices = new Map(); // deviceId -> { record, status } from the latest sync of any room
  const path = (id) => "/api/v1/channels/" + encodeURIComponent(id) + "/keys";
  const room = (id) => { if (!rooms.has(id)) rooms.set(id, { keys: new Map(), epoch: null, status: "unknown" }); return rooms.get(id); };
  const learn = (r, epoch, key) => { if (!r.keys.has(epoch)) { r.keys.set(epoch, key); onNewKey(); } };

  async function open(channelId, grant, epoch, commitment, device, own, statuses) {
    const r = room(channelId);
    if (r.keys.has(epoch)) return;
    const signer = grant.wrapped_key?.signer;
    if (!signer) throw Error("Unsigned key grant");
    const signerFp = await fingerprint(signer);
    if (signerFp !== own) {
      const record = [...statuses.keys()].map((id) => devices.get(id)?.record).find((x) => x?.identity_key === signerFp);
      const status = record ? statuses.get(record.id) : (trust.knowsFingerprint(signerFp) ? "pinned" : "unknown");
      if (status === "changed") { onWarning("A device that shared a room key changed its identity key. The key was rejected."); throw Error("Signer identity changed"); }
      if (!TRUSTED.has(status)) throw Error("Key granted by an untrusted device");
    }
    const key = await unwrapRoomKey(grant.wrapped_key, device, signerFp, { room: channelId, epoch, recipient: grant.device_id });
    if (commitment && (await keyCommitment(key, channelId, epoch)) !== commitment) {
      onWarning("A room key did not match its published commitment and was rejected.");
      throw Error("Key commitment mismatch");
    }
    learn(r, epoch, key);
  }

  async function distribute(channelId, state, device, mine, statuses) {
    const key = room(channelId).keys.get(state.epoch);
    if (!key) return 0;
    const granted = new Set(state.granted_device_ids ?? []);
    let shared = 0;
    for (const recipient of state.recipients) {
      if (granted.has(recipient.id)) continue;
      const status = statuses.get(recipient.id);
      if (status === "changed") { onWarning(`A device of ${recipient.username ?? "a member"} changed its identity key; not sharing keys with it.`); continue; }
      if (!TRUSTED.has(status)) continue; // unattested devices wait for approval by their owner
      const envelope = await wrapRoomKey(key, device, recipient.public_bundle, { room: channelId, epoch: state.epoch, recipient: recipient.id });
      try { await request(path(channelId) + "/" + encodeURIComponent(recipient.id), "PUT", { epoch: state.epoch, wrapped_key: envelope, granter_device_id: mine.id }); shared++; } catch {}
    }
    return shared;
  }

  async function syncNow(channelId) {
    const device = getDevice();
    const r = room(channelId);
    if (!device) { r.status = "locked"; return r; }
    const state = await request(path(channelId));
    const bundle = await publicBundle(device), own = await fingerprint(bundle);
    const mine = state.recipients.find((x) => x.user_id === selfId() && x.identity_key === own);
    r.epoch = state.epoch;
    if (!mine) { r.status = "unregistered"; return r; }
    if (!mine.public_bundle) {
      try { await request("/api/v1/devices/" + encodeURIComponent(mine.id) + "/bundle", "PUT", { public_bundle: bundle }); mine.public_bundle = bundle; } catch {}
    }
    const statuses = await evaluateDevices(state.recipients, trust, own);
    for (const rec of state.recipients) devices.set(rec.id, { record: rec, status: statuses.get(rec.id) });
    r.selfDeviceId = mine.id;
    for (const grant of state.history ?? []) { try { await open(channelId, grant, grant.epoch, grant.key_commitment, device, own, statuses); } catch {} }
    const current = state.wrapped.find((w) => w.device_id === mine.id);
    if (current) {
      try { await open(channelId, current, state.epoch, state.claim?.key_commitment, device, own, statuses); } catch {}
    } else if (!state.claim && !r.keys.has(state.epoch)) {
      // Nobody has created this epoch's key yet: claim it (first writer wins).
      const key = await createRoomKey();
      const commitment = await keyCommitment(key, channelId, state.epoch);
      try {
        await request(path(channelId) + "/claim", "POST", { epoch: state.epoch, device_id: mine.id, key_commitment: commitment });
        learn(r, state.epoch, key);
        state.granted_device_ids = [];
      } catch {}
    }
    if (r.keys.has(state.epoch)) { await distribute(channelId, state, device, mine, statuses); r.status = "ready"; }
    else r.status = "waiting";
    return r;
  }

  return {
    /** Fetches state, opens grants, creates/claims missing epoch keys and shares with trusted devices. */
    sync(channelId) {
      if (!inflight.has(channelId)) inflight.set(channelId, syncNow(channelId).finally(() => inflight.delete(channelId)));
      return inflight.get(channelId);
    },
    key(channelId, epoch) { return rooms.get(channelId)?.keys.get(epoch) ?? null; },
    current(channelId) { const r = rooms.get(channelId); return r && r.epoch !== null ? { epoch: r.epoch, key: r.keys.get(r.epoch) ?? null, status: r.status, deviceId: r.selfDeviceId } : null; },
    async requestKey(channelId) { await request(path(channelId) + "/request", "POST"); },
    /** Checks a message envelope's signature against the author's devices. */
    async verifyMessage(envelope, authorId) {
      if (!envelope?.sig?.device) return "unsigned";
      const entry = devices.get(envelope.sig.device);
      if (!entry) return "unknown-device";
      if (entry.record.user_id !== authorId) return "invalid";
      if (!(await verifyEnvelopeSignature(envelope, entry.record.public_bundle))) return "invalid";
      return TRUSTED.has(entry.status) ? "verified" : "untrusted-device";
    },
    /** Raw key material for backups: { channelId: { epoch: base64url } }. */
    async exportKeys() {
      const out = {};
      for (const [channel, r] of rooms) for (const [epoch, key] of r.keys) { (out[channel] ??= {})[epoch] = b64(await subtle.exportKey("raw", key)); }
      return out;
    },
    async importKeys(map) {
      let added = 0;
      for (const [channel, epochs] of Object.entries(map ?? {})) for (const [epoch, raw] of Object.entries(epochs)) {
        const r = room(channel);
        if (r.keys.has(Number(epoch))) continue;
        r.keys.set(Number(epoch), await subtle.importKey("raw", un64(raw), { name: "AES-GCM" }, true, ["encrypt", "decrypt"]));
        added++;
      }
      return added;
    },
    clear() { rooms.clear(); devices.clear(); },
  };
}
