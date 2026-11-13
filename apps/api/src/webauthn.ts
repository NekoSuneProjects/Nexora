// Minimal WebAuthn (passkey) verification: "none" attestation, ES256 and RS256 credentials.
// Note: browsers refuse IP addresses as relying-party IDs; serve Nexora on a hostname (or localhost).
// Implements only what Nexora needs; every check follows WebAuthn Level 2 §7.1/§7.2.
import { createHash, createPublicKey, verify as verifySignature, timingSafeEqual, type JsonWebKey } from "node:crypto";

/** Decodes a single CBOR item (RFC 8949 subset: ints, byte/text strings, arrays, maps, simple values). */
export function decodeCbor(input: Uint8Array): { value: unknown; length: number } {
  let pos = 0;
  const view = new DataView(input.buffer, input.byteOffset, input.byteLength);
  const need = (n: number) => { if (pos + n > input.length) throw Error("Truncated CBOR"); };
  const readLength = (info: number): number => {
    if (info < 24) return info;
    if (info === 24) { need(1); return input[pos++]; }
    if (info === 25) { need(2); const v = view.getUint16(pos); pos += 2; return v; }
    if (info === 26) { need(4); const v = view.getUint32(pos); pos += 4; return v; }
    if (info === 27) { need(8); const v = view.getBigUint64(pos); pos += 8; if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw Error("CBOR integer too large"); return Number(v); }
    throw Error("Unsupported CBOR length");
  };
  const item = (depth: number): unknown => {
    if (depth > 16) throw Error("CBOR nesting too deep");
    need(1);
    const head = input[pos++], major = head >> 5, info = head & 31;
    switch (major) {
      case 0: return readLength(info);
      case 1: return -1 - readLength(info);
      case 2: { const n = readLength(info); need(n); const out = input.slice(pos, pos + n); pos += n; return out; }
      case 3: { const n = readLength(info); need(n); const out = new TextDecoder("utf-8", { fatal: true }).decode(input.subarray(pos, pos + n)); pos += n; return out; }
      case 4: { const n = readLength(info); if (n > 1000) throw Error("CBOR array too large"); return Array.from({ length: n }, () => item(depth + 1)); }
      case 5: {
        const n = readLength(info); if (n > 1000) throw Error("CBOR map too large");
        const map = new Map<unknown, unknown>();
        for (let i = 0; i < n; i++) { const k = item(depth + 1); map.set(k, item(depth + 1)); }
        return map;
      }
      case 7: if (info === 20) return false; if (info === 21) return true; if (info === 22) return null; throw Error("Unsupported CBOR simple value");
      default: throw Error("Unsupported CBOR type");
    }
  };
  const value = item(0);
  return { value, length: pos };
}

export type ParsedAuthData = { rpIdHash: Buffer; flags: number; signCount: number; credentialId?: Buffer; publicKey?: JsonWebKey };
export function parseAuthData(data: Buffer): ParsedAuthData {
  if (data.length < 37) throw Error("Authenticator data too short");
  const out: ParsedAuthData = { rpIdHash: data.subarray(0, 32), flags: data[32], signCount: data.readUInt32BE(33) };
  if (out.flags & 0x40) { // attested credential data present
    if (data.length < 55) throw Error("Missing attested credential data");
    const idLength = data.readUInt16BE(53);
    if (idLength < 16 || idLength > 1023 || data.length < 55 + idLength) throw Error("Invalid credential ID");
    out.credentialId = data.subarray(55, 55 + idLength);
    const cose = decodeCbor(data.subarray(55 + idLength)).value;
    out.publicKey = coseToJwk(cose);
  }
  return out;
}
/** COSE_Key → JWK. Accepts ES256 (EC2 P-256) and RS256 (RSA ≥ 2048, used by Windows Hello). */
export function coseToJwk(cose: unknown): JsonWebKey {
  if (!(cose instanceof Map)) throw Error("Invalid COSE key");
  if (cose.get(1) === 3 && cose.get(3) === -257) {
    const n = cose.get(-1), e = cose.get(-2);
    if (!(n instanceof Uint8Array) || !(e instanceof Uint8Array) || n.length < 256) throw Error("RSA passkeys must be at least 2048-bit");
    return { kty: "RSA", n: Buffer.from(n).toString("base64url"), e: Buffer.from(e).toString("base64url") };
  }
  const kty = cose.get(1), alg = cose.get(3), crv = cose.get(-1), x = cose.get(-2), y = cose.get(-3);
  if (kty !== 2 || alg !== -7 || crv !== 1 || !(x instanceof Uint8Array) || !(y instanceof Uint8Array) || x.length !== 32 || y.length !== 32) throw Error("Only ES256 and RS256 passkeys are supported");
  return { kty: "EC", crv: "P-256", x: Buffer.from(x).toString("base64url"), y: Buffer.from(y).toString("base64url") };
}
const b64 = (s: unknown) => { if (typeof s !== "string" || !/^[A-Za-z0-9_-]*$/.test(s)) throw Error("Expected base64url"); return Buffer.from(s, "base64url"); };
const sha256 = (data: Buffer | string) => createHash("sha256").update(data).digest();
function checkClientData(raw: Buffer, type: string, challenge: string, origin: string) {
  const client = JSON.parse(raw.toString("utf8"));
  if (client.type !== type) throw Error("Wrong ceremony type");
  if (typeof client.challenge !== "string" || client.challenge.length !== challenge.length || !timingSafeEqual(Buffer.from(client.challenge), Buffer.from(challenge))) throw Error("Challenge mismatch");
  if (client.origin !== origin) throw Error("Origin mismatch");
  if (client.crossOrigin === true) throw Error("Cross-origin ceremony rejected");
}
function checkRp(auth: ParsedAuthData, rpId: string, requireUv: boolean) {
  if (!timingSafeEqual(auth.rpIdHash, sha256(rpId))) throw Error("RP ID mismatch");
  if (!(auth.flags & 0x01)) throw Error("User presence required");
  if (requireUv && !(auth.flags & 0x04)) throw Error("User verification required");
}

export type RegistrationInput = { id: string; response: { clientDataJSON: string; attestationObject: string } };
export function verifyRegistration(credential: RegistrationInput, expected: { challenge: string; origin: string; rpId: string }) {
  const clientData = b64(credential.response?.clientDataJSON);
  checkClientData(clientData, "webauthn.create", expected.challenge, expected.origin);
  const attestation = decodeCbor(b64(credential.response?.attestationObject)).value;
  if (!(attestation instanceof Map)) throw Error("Invalid attestation object");
  // Nexora requests attestation "none": accept "none" only, ignore no statements.
  if (attestation.get("fmt") !== "none") throw Error("Unsupported attestation format");
  const authData = attestation.get("authData");
  if (!(authData instanceof Uint8Array)) throw Error("Missing authenticator data");
  const parsed = parseAuthData(Buffer.from(authData));
  checkRp(parsed, expected.rpId, true);
  if (!parsed.credentialId || !parsed.publicKey) throw Error("Missing credential");
  const id = parsed.credentialId.toString("base64url");
  if (id !== credential.id) throw Error("Credential ID mismatch");
  return { id, publicKey: parsed.publicKey, signCount: parsed.signCount };
}

export type AssertionInput = { id: string; response: { clientDataJSON: string; authenticatorData: string; signature: string; userHandle?: string | null } };
export function verifyAssertion(credential: AssertionInput, stored: { publicKey: JsonWebKey; signCount: number }, expected: { challenge: string; origin: string; rpId: string }) {
  const clientData = b64(credential.response?.clientDataJSON);
  checkClientData(clientData, "webauthn.get", expected.challenge, expected.origin);
  const authData = b64(credential.response?.authenticatorData);
  const parsed = parseAuthData(authData);
  checkRp(parsed, expected.rpId, true);
  const key = createPublicKey({ key: stored.publicKey, format: "jwk" });
  // ES256 signatures are DER-encoded; RS256 uses RSASSA-PKCS1-v1_5 (Node's RSA default).
  const ok = verifySignature("sha256", Buffer.concat([authData, sha256(clientData)]), stored.publicKey.kty === "RSA" ? key : { key, dsaEncoding: "der" }, b64(credential.response?.signature));
  if (!ok) throw Error("Invalid passkey signature");
  // Counter regression indicates a cloned authenticator (0 = authenticator does not count).
  if ((parsed.signCount !== 0 || stored.signCount !== 0) && parsed.signCount <= stored.signCount) throw Error("Signature counter did not increase");
  return { signCount: parsed.signCount };
}
