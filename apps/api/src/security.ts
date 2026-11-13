// P0 security features: instance administration and abuse reports, account suspension and
// deletion, device cross-signing (attestations), encrypted room-key backups, and passkeys.
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { Pool, PoolClient } from "pg";
import { randomBytes, randomUUID, createHash, createPublicKey, verify as verifySignature } from "node:crypto";
import { z } from "zod";
import { verifyRegistration, verifyAssertion } from "./webauthn.js";
import type { Identity } from "./community.js";

export type SecurityContext = {
  db: Pool;
  auth: (header?: string) => Promise<Identity | null>;
  publish: (payload: Record<string, unknown>) => Promise<void>;
  takeQuota: (key: string, limit: number, windowSeconds: number) => Promise<boolean>;
  verifyPassword: (userId: string, password: string) => Promise<boolean>;
};
const uuid = z.string().uuid();
const hashToken = (token: string) => createHash("sha256").update(token).digest("hex");

/** Canonical JSON identical to apps/web/crypto.mjs canonicalJson. */
export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return "[" + value.map(canonicalJson).join(",") + "]";
  if (value && typeof value === "object") return "{" + Object.keys(value).sort().map((k) => JSON.stringify(k) + ":" + canonicalJson((value as Record<string, unknown>)[k])).join(",") + "}";
  return JSON.stringify(value);
}
/** The exact statement a device signs to vouch for another device of the same account. */
export const attestationStatement = (userId: string, deviceId: string, fingerprint: string) =>
  canonicalJson({ type: "nexora-device-attestation-v1", user_id: userId, device_id: deviceId, fingerprint });
/** Verifies a WebCrypto (IEEE P1363) ECDSA P-256/SHA-256 signature with a JWK from a public bundle. */
export function verifyDeviceSignature(signingJwk: unknown, statement: string, signature: string) {
  try {
    const jwk = z.object({ kty: z.literal("EC"), crv: z.literal("P-256"), x: z.string(), y: z.string() }).parse(signingJwk);
    const key = createPublicKey({ key: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }, format: "jwk" });
    return verifySignature("sha256", Buffer.from(statement), { key, dsaEncoding: "ieee-p1363" }, Buffer.from(signature, "base64url"));
  } catch { return false; }
}

/** Removes an account and everything that cannot outlive it. Owned communities are deleted. */
export async function deleteAccount(client: PoolClient, userId: string) {
  const owned = await client.query("SELECT g.id,(SELECT array_agg(user_id) FROM guild_members WHERE guild_id=g.id) AS members FROM guilds g WHERE g.owner_id=$1 AND g.kind='community'", [userId]);
  // Group conversations pass to their longest-standing remaining member.
  await client.query("UPDATE guilds g SET owner_id=(SELECT user_id FROM guild_members WHERE guild_id=g.id AND user_id<>$1 ORDER BY joined_at LIMIT 1) WHERE g.owner_id=$1 AND g.kind='dm' AND EXISTS(SELECT 1 FROM guild_members WHERE guild_id=g.id AND user_id<>$1)", [userId]);
  await client.query("DELETE FROM guilds WHERE owner_id=$1", [userId]);
  await client.query("INSERT INTO message_tombstones(id,channel_id,deleted_by) SELECT id,channel_id,NULL FROM messages WHERE author_id=$1 ON CONFLICT DO NOTHING", [userId]);
  await client.query("DELETE FROM messages WHERE author_id=$1", [userId]);
  await client.query("DELETE FROM guild_invites WHERE created_by=$1", [userId]);
  await client.query("DELETE FROM guild_bots WHERE installed_by=$1", [userId]);
  await client.query("DELETE FROM users WHERE id=$1", [userId]);
  return owned.rows as { id: string; members: string[] | null }[];
}

export function registerSecurity(app: FastifyInstance, ctx: SecurityContext) {
  const { db } = ctx;
  type Handler = (request: FastifyRequest, reply: FastifyReply, user: Identity) => Promise<unknown>;
  const authed = (handler: Handler) => async (request: FastifyRequest, reply: FastifyReply) => {
    const user = await ctx.auth(request.headers.authorization);
    if (!user) return reply.code(401).send({ message: "Unauthorized" });
    return handler(request, reply, user);
  };
  const admin = (handler: Handler) => authed(async (request, reply, user) => {
    const r = await db.query("SELECT is_admin FROM users WHERE id=$1", [user.id]);
    if (!r.rows[0]?.is_admin) return reply.code(403).send({ message: "Instance administrators only" });
    return handler(request, reply, user);
  });
  const fail = (reply: FastifyReply, code: number, message: string) => reply.code(code).send({ message });
  const params = (request: FastifyRequest) => request.params as Record<string, string>;
  const transaction = async <T>(fn: (client: PoolClient) => Promise<T>) => {
    const client = await db.connect();
    try { await client.query("BEGIN"); const out = await fn(client); await client.query("COMMIT"); return out; }
    catch (error) { await client.query("ROLLBACK"); throw error; }
    finally { client.release(); }
  };
  const notifyDeleted = async (guilds: { id: string; members: string[] | null }[]) => {
    for (const g of guilds) if (g.members?.length) await ctx.publish({ kind: "dispatch", users: g.members.slice(0, 50), t: "GUILD_DELETE", d: { id: g.id } });
  };

  // ------------------------------------------------------------ abuse reports
  const reportInput = z.object({
    target_type: z.enum(["message", "user", "guild"]), target_id: z.string().uuid(),
    reason: z.string().trim().min(1).max(1000), evidence: z.string().max(4000).default(""),
  });
  app.post("/api/v1/reports", authed(async (request, reply, user) => {
    const data = reportInput.safeParse(request.body);
    if (!data.success) return fail(reply, 400, "Invalid report");
    if (!(await ctx.takeQuota("report:" + user.id, 20, 3600))) return fail(reply, 429, "Too many reports");
    const { target_type, target_id } = data.data;
    // Reporters may only report things they can actually see.
    let guildId: string | null = null;
    if (target_type === "message") {
      const r = await db.query("SELECT c.guild_id FROM messages m JOIN channels c ON c.id=m.channel_id JOIN guild_members gm ON gm.guild_id=c.guild_id AND gm.user_id=$2 WHERE m.id=$1", [target_id, user.id]);
      if (!r.rowCount) return fail(reply, 404, "Message not found");
      guildId = r.rows[0].guild_id;
    } else if (target_type === "guild") {
      const r = await db.query("SELECT 1 FROM guild_members WHERE guild_id=$1 AND user_id=$2", [target_id, user.id]);
      if (!r.rowCount) return fail(reply, 404, "Community not found");
      guildId = target_id;
    } else {
      const r = await db.query("SELECT 1 FROM users WHERE id=$1 AND id<>$2", [target_id, user.id]);
      if (!r.rowCount) return fail(reply, 404, "User not found");
    }
    const id = randomUUID();
    await db.query("INSERT INTO abuse_reports(id,reporter_id,target_type,target_id,guild_id,reason,evidence) VALUES($1,$2,$3,$4,$5,$6,$7)", [id, user.id, target_type, target_id, guildId, data.data.reason, data.data.evidence]);
    return reply.code(201).send({ id });
  }));

  // ------------------------------------------------------------ instance administration
  app.get("/api/v1/admin/stats", admin(async () => {
    const r = await db.query(`SELECT (SELECT count(*)::int FROM users) AS users,(SELECT count(*)::int FROM users WHERE suspended_at IS NOT NULL) AS suspended,
      (SELECT count(*)::int FROM guilds WHERE kind='community') AS communities,(SELECT count(*)::int FROM messages) AS messages,
      (SELECT count(*)::int FROM abuse_reports WHERE status='open') AS open_reports,(SELECT count(DISTINCT user_id)::int FROM sessions WHERE expires_at>now()) AS active_users`);
    return r.rows[0];
  }));
  app.get("/api/v1/admin/users", admin(async (request) => {
    const q = z.object({ q: z.string().max(32).default("") }).safeParse(request.query);
    const term = q.success ? q.data.q.replace(/[%_\\]/g, "") : "";
    const r = await db.query("SELECT u.id,u.username,u.created_at,u.is_admin,u.suspended_at,u.suspension_reason,(SELECT count(*)::int FROM guild_members WHERE user_id=u.id) AS memberships FROM users u WHERE u.username ILIKE $1 ORDER BY u.created_at DESC LIMIT 100", ["%" + term + "%"]);
    return r.rows;
  }));
  app.post("/api/v1/admin/users/:id/suspend", admin(async (request, reply, actor) => {
    const { id } = params(request);
    const body = z.object({ reason: z.string().trim().max(500).default("") }).safeParse(request.body ?? {});
    if (!uuid.safeParse(id).success || !body.success) return fail(reply, 400, "Invalid request");
    if (id === actor.id) return fail(reply, 400, "You cannot suspend yourself");
    const r = await db.query("UPDATE users SET suspended_at=now(),suspension_reason=$2 WHERE id=$1 RETURNING id", [id, body.data.reason]);
    if (!r.rowCount) return fail(reply, 404, "User not found");
    // Deleting sessions fires the invalidation trigger: sockets close on every instance.
    await db.query("DELETE FROM sessions WHERE user_id=$1", [id]);
    return reply.code(204).send();
  }));
  app.post("/api/v1/admin/users/:id/unsuspend", admin(async (request, reply) => {
    const { id } = params(request);
    if (!uuid.safeParse(id).success) return fail(reply, 400, "Invalid user ID");
    const r = await db.query("UPDATE users SET suspended_at=NULL,suspension_reason='' WHERE id=$1 RETURNING id", [id]);
    return r.rowCount ? reply.code(204).send() : fail(reply, 404, "User not found");
  }));
  app.delete("/api/v1/admin/users/:id", admin(async (request, reply, actor) => {
    const { id } = params(request);
    if (!uuid.safeParse(id).success) return fail(reply, 400, "Invalid user ID");
    if (id === actor.id) return fail(reply, 400, "Use account deletion for your own account");
    const exists = await db.query("SELECT 1 FROM users WHERE id=$1", [id]);
    if (!exists.rowCount) return fail(reply, 404, "User not found");
    const deleted = await transaction((client) => deleteAccount(client, id));
    await notifyDeleted(deleted);
    return reply.code(204).send();
  }));
  app.get("/api/v1/admin/guilds", admin(async (request) => {
    const q = z.object({ q: z.string().max(100).default("") }).safeParse(request.query);
    const term = q.success ? q.data.q.replace(/[%_\\]/g, "") : "";
    const r = await db.query("SELECT g.id,g.name,g.created_at,u.username AS owner,(SELECT count(*)::int FROM guild_members WHERE guild_id=g.id) AS members,(SELECT count(*)::int FROM abuse_reports WHERE guild_id=g.id AND status='open') AS open_reports FROM guilds g JOIN users u ON u.id=g.owner_id WHERE g.kind='community' AND g.name ILIKE $1 ORDER BY g.created_at DESC LIMIT 100", ["%" + term + "%"]);
    return r.rows;
  }));
  app.delete("/api/v1/admin/guilds/:id", admin(async (request, reply) => {
    const { id } = params(request);
    if (!uuid.safeParse(id).success) return fail(reply, 400, "Invalid community ID");
    const members = (await db.query("SELECT user_id FROM guild_members WHERE guild_id=$1", [id])).rows.map((r: { user_id: string }) => r.user_id);
    const r = await db.query("DELETE FROM guilds WHERE id=$1 AND kind='community' RETURNING id", [id]);
    if (!r.rowCount) return fail(reply, 404, "Community not found");
    await notifyDeleted([{ id, members }]);
    return reply.code(204).send();
  }));
  app.get("/api/v1/admin/reports", admin(async (request) => {
    const q = z.object({ status: z.enum(["open", "resolved", "dismissed"]).default("open") }).safeParse(request.query);
    const r = await db.query(
      `SELECT r.id,r.target_type,r.target_id,r.guild_id,g.name AS guild_name,r.reason,r.evidence,r.status,r.resolution_note,r.created_at,r.resolved_at,
        rep.username AS reporter,res.username AS resolved_by,
        CASE r.target_type WHEN 'user' THEN (SELECT username FROM users WHERE id=r.target_id)
          WHEN 'message' THEN (SELECT u.username FROM messages m JOIN users u ON u.id=m.author_id WHERE m.id=r.target_id) END AS target_user,
        CASE WHEN r.target_type='message' THEN (SELECT m.author_id FROM messages m WHERE m.id=r.target_id) WHEN r.target_type='user' THEN r.target_id END AS target_user_id
       FROM abuse_reports r LEFT JOIN users rep ON rep.id=r.reporter_id LEFT JOIN users res ON res.id=r.resolved_by LEFT JOIN guilds g ON g.id=r.guild_id
       WHERE r.status=$1 ORDER BY r.created_at DESC LIMIT 200`, [q.success ? q.data.status : "open"]);
    return r.rows;
  }));
  app.post("/api/v1/admin/reports/:id", admin(async (request, reply, actor) => {
    const { id } = params(request);
    const body = z.object({ status: z.enum(["resolved", "dismissed", "open"]), note: z.string().max(1000).default("") }).safeParse(request.body);
    if (!uuid.safeParse(id).success || !body.success) return fail(reply, 400, "Invalid request");
    const r = await db.query("UPDATE abuse_reports SET status=$2,resolution_note=$3,resolved_by=CASE WHEN $2='open' THEN NULL ELSE $4::uuid END,resolved_at=CASE WHEN $2='open' THEN NULL ELSE now() END WHERE id=$1 RETURNING id", [id, body.data.status, body.data.note, actor.id]);
    return r.rowCount ? reply.code(204).send() : fail(reply, 404, "Report not found");
  }));
  // Deleting a reported message is a moderation action available to instance admins.
  app.delete("/api/v1/admin/messages/:id", admin(async (request, reply, actor) => {
    const { id } = params(request);
    if (!uuid.safeParse(id).success) return fail(reply, 400, "Invalid message ID");
    const r = await transaction(async (client) => {
      const m = await client.query("DELETE FROM messages WHERE id=$1 RETURNING channel_id", [id]);
      if (m.rowCount) await client.query("INSERT INTO message_tombstones(id,channel_id,deleted_by) VALUES($1,$2,$3) ON CONFLICT DO NOTHING", [id, m.rows[0].channel_id, actor.id]);
      return m.rows[0];
    });
    if (!r) return fail(reply, 404, "Message not found");
    await ctx.publish({ kind: "message_deleted", channel: r.channel_id, message: id });
    return reply.code(204).send();
  }));

  // ------------------------------------------------------------ self-service account deletion
  app.delete("/api/v1/users/@me", authed(async (request, reply, user) => {
    const body = z.object({ password: z.string().min(12).max(256) }).safeParse(request.body);
    if (!body.success) return fail(reply, 400, "Password required");
    if (!(await ctx.takeQuota("account-delete:" + user.id, 5, 900))) return fail(reply, 429, "Too many attempts");
    if (!(await ctx.verifyPassword(user.id, body.data.password))) return fail(reply, 401, "Incorrect password");
    const owns = await db.query("SELECT count(*)::int AS n FROM guilds WHERE owner_id=$1 AND kind='community'", [user.id]);
    if (owns.rows[0].n > 0) return fail(reply, 409, "Transfer or delete the servers you own first");
    await transaction((client) => deleteAccount(client, user.id));
    return reply.code(204).send();
  }));

  // ------------------------------------------------------------ device cross-signing
  app.put("/api/v1/devices/:id/attestation", authed(async (request, reply, user) => {
    const { id } = params(request);
    const body = z.object({ signer_device_id: z.string().uuid(), signature: z.string().regex(/^[A-Za-z0-9_-]{80,100}$/) }).safeParse(request.body);
    if (!uuid.safeParse(id).success || !body.success || body.data.signer_device_id === id) return fail(reply, 400, "Invalid attestation");
    const rows = await db.query("SELECT id,identity_key,public_bundle FROM user_devices WHERE user_id=$1 AND revoked_at IS NULL AND id IN ($2,$3)", [user.id, id, body.data.signer_device_id]);
    const target = rows.rows.find((r: any) => r.id === id), signer = rows.rows.find((r: any) => r.id === body.data.signer_device_id);
    if (!target || !signer?.public_bundle) return fail(reply, 404, "Both devices must be active devices of your account");
    // Verified server-side too, so the stored attestation is never garbage; clients re-verify.
    if (!verifyDeviceSignature(signer.public_bundle.signing, attestationStatement(user.id, id, target.identity_key), body.data.signature)) return fail(reply, 400, "Attestation signature is invalid");
    await db.query("UPDATE user_devices SET attestation=$2::jsonb WHERE id=$1", [id, JSON.stringify({ signer_device_id: body.data.signer_device_id, signature: body.data.signature })]);
    await ctx.publish({ kind: "dispatch", users: [user.id], t: "DEVICE_UPDATE", d: { device_id: id } });
    return reply.code(204).send();
  }));

  // ------------------------------------------------------------ encrypted key backup
  app.get("/api/v1/users/@me/key-backup", authed(async (_request, reply, user) => {
    const r = await db.query("SELECT version,ciphertext,updated_at FROM user_key_backups WHERE user_id=$1", [user.id]);
    // version 0 = no backup yet (a 200, so clients need no special error path).
    return r.rowCount ? r.rows[0] : { version: 0, ciphertext: null, updated_at: null };
  }));
  app.put("/api/v1/users/@me/key-backup", authed(async (request, reply, user) => {
    const body = z.object({ version: z.number().int().positive(), ciphertext: z.string().min(1).max(4000000) }).safeParse(request.body);
    if (!body.success) return fail(reply, 400, "Invalid backup");
    if (!(await ctx.takeQuota("key-backup:" + user.id, 120, 3600))) return fail(reply, 429, "Too many backup updates");
    // Optimistic concurrency: version must be exactly current+1, so devices never clobber each other.
    const r = await db.query(
      "INSERT INTO user_key_backups(user_id,version,ciphertext) SELECT $1,$2,$3 WHERE $2=1 AND NOT EXISTS(SELECT 1 FROM user_key_backups WHERE user_id=$1) ON CONFLICT(user_id) DO NOTHING RETURNING version",
      [user.id, body.data.version, body.data.ciphertext]);
    if (r.rowCount) return { version: body.data.version };
    const u = await db.query("UPDATE user_key_backups SET version=$2,ciphertext=$3,updated_at=now() WHERE user_id=$1 AND version=$2-1 RETURNING version", [user.id, body.data.version, body.data.ciphertext]);
    if (u.rowCount) return { version: body.data.version };
    const current = await db.query("SELECT version FROM user_key_backups WHERE user_id=$1", [user.id]);
    return reply.code(409).send({ message: "Backup version conflict", version: current.rows[0]?.version ?? 0 });
  }));
  app.delete("/api/v1/users/@me/key-backup", authed(async (_request, reply, user) => {
    await db.query("DELETE FROM user_key_backups WHERE user_id=$1", [user.id]);
    return reply.code(204).send();
  }));

  // ------------------------------------------------------------ passkeys (WebAuthn)
  const relyingParty = (request: FastifyRequest) => {
    const origin = process.env.PUBLIC_BASE_URL ? new URL(process.env.PUBLIC_BASE_URL).origin : request.protocol + "://" + request.headers.host;
    return { origin, rpId: new URL(origin).hostname };
  };
  const newChallenge = async (kind: "register" | "login", userId: string | null) => {
    const challenge = randomBytes(32).toString("base64url");
    await db.query("DELETE FROM webauthn_challenges WHERE expires_at<now()");
    await db.query("INSERT INTO webauthn_challenges(challenge,user_id,kind,expires_at) VALUES($1,$2,$3,now()+interval '5 minutes')", [challenge, userId, kind]);
    return challenge;
  };
  const consumeChallenge = async (clientDataJSON: unknown, kind: string, userId: string | null) => {
    try {
      const challenge = JSON.parse(Buffer.from(String(clientDataJSON), "base64url").toString("utf8")).challenge;
      if (typeof challenge !== "string") return null;
      const r = await db.query("DELETE FROM webauthn_challenges WHERE challenge=$1 AND kind=$2 AND expires_at>now() AND user_id IS NOT DISTINCT FROM $3 RETURNING challenge", [challenge, kind, userId]);
      return r.rows[0]?.challenge ?? null;
    } catch { return null; }
  };
  app.post("/api/v1/auth/passkeys/register/options", authed(async (request, reply, user) => {
    const body = z.object({ password: z.string().min(12).max(256) }).safeParse(request.body);
    if (!body.success) return fail(reply, 400, "Password required to add a passkey");
    if (!(await ctx.takeQuota("passkey-register:" + user.id, 10, 900))) return fail(reply, 429, "Too many attempts");
    if (!(await ctx.verifyPassword(user.id, body.data.password))) return fail(reply, 401, "Incorrect password");
    const { rpId } = relyingParty(request);
    const existing = await db.query("SELECT id FROM webauthn_credentials WHERE user_id=$1", [user.id]);
    return {
      challenge: await newChallenge("register", user.id),
      rp: { id: rpId, name: "Nexora" },
      user: { id: Buffer.from(user.id).toString("base64url"), name: user.username, displayName: user.username },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
      authenticatorSelection: { residentKey: "required", userVerification: "required" },
      attestation: "none", timeout: 300000,
      excludeCredentials: existing.rows.map((r: { id: string }) => ({ type: "public-key", id: r.id })),
    };
  }));
  app.post("/api/v1/auth/passkeys/register", authed(async (request, reply, user) => {
    const body = z.object({ name: z.string().trim().min(1).max(60).default("Passkey"), credential: z.object({ id: z.string().max(1400), response: z.object({ clientDataJSON: z.string(), attestationObject: z.string() }) }) }).safeParse(request.body);
    if (!body.success) return fail(reply, 400, "Invalid passkey");
    const challenge = await consumeChallenge(body.data.credential.response.clientDataJSON, "register", user.id);
    if (!challenge) return fail(reply, 400, "Passkey challenge expired or invalid");
    let result;
    try { result = verifyRegistration(body.data.credential, { challenge, ...relyingParty(request) }); }
    catch (error: any) { return fail(reply, 400, "Passkey rejected: " + error.message); }
    try {
      await db.query("INSERT INTO webauthn_credentials(id,user_id,name,public_key,sign_count) VALUES($1,$2,$3,$4::jsonb,$5)", [result.id, user.id, body.data.name, JSON.stringify(result.publicKey), result.signCount]);
    } catch (error: any) { if (error.code === "23505") return fail(reply, 409, "Passkey already registered"); throw error; }
    return reply.code(201).send({ id: result.id, name: body.data.name });
  }));
  app.get("/api/v1/auth/passkeys", authed(async (_request, _reply, user) =>
    (await db.query("SELECT id,name,created_at,last_used_at FROM webauthn_credentials WHERE user_id=$1 ORDER BY created_at", [user.id])).rows));
  app.delete("/api/v1/auth/passkeys/:id", authed(async (request, reply, user) => {
    const r = await db.query("DELETE FROM webauthn_credentials WHERE id=$1 AND user_id=$2 RETURNING id", [params(request).id, user.id]);
    return r.rowCount ? reply.code(204).send() : fail(reply, 404, "Passkey not found");
  }));
  app.post("/api/v1/auth/passkeys/login/options", async (request, reply) => {
    if (!(await ctx.takeQuota("passkey-options:" + request.ip, 60, 900))) return fail(reply, 429, "Too many attempts");
    // Discoverable credentials only: never reveal which credentials belong to a username.
    return { challenge: await newChallenge("login", null), rpId: relyingParty(request).rpId, userVerification: "required", timeout: 300000, allowCredentials: [] };
  });
  app.post("/api/v1/auth/passkeys/login", async (request, reply) => {
    if (!(await ctx.takeQuota("login-ip:" + request.ip, 60, 900))) return reply.code(429).header("Retry-After", "900").send({ error: "Too many login attempts; try again later" });
    const body = z.object({ credential: z.object({ id: z.string().max(1400), response: z.object({ clientDataJSON: z.string(), authenticatorData: z.string(), signature: z.string(), userHandle: z.string().nullable().optional() }) }) }).safeParse(request.body);
    if (!body.success) return fail(reply, 400, "Invalid passkey assertion");
    const challenge = await consumeChallenge(body.data.credential.response.clientDataJSON, "login", null);
    if (!challenge) return fail(reply, 401, "Passkey challenge expired or invalid");
    const stored = (await db.query("SELECT c.user_id,c.public_key,c.sign_count,u.suspended_at FROM webauthn_credentials c JOIN users u ON u.id=c.user_id WHERE c.id=$1", [body.data.credential.id])).rows[0];
    if (!stored) return fail(reply, 401, "Unknown passkey");
    let result;
    try { result = verifyAssertion(body.data.credential, { publicKey: stored.public_key, signCount: Number(stored.sign_count) }, { challenge, ...relyingParty(request) }); }
    catch (error: any) { return fail(reply, 401, "Passkey rejected: " + error.message); }
    if (stored.suspended_at) return fail(reply, 403, "Account suspended");
    await db.query("UPDATE webauthn_credentials SET sign_count=$2,last_used_at=now() WHERE id=$1", [body.data.credential.id, result.signCount]);
    const token = randomBytes(32).toString("hex");
    await db.query("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES($1,$2,now()+interval '7 days')", [hashToken(token), stored.user_id]);
    return { token, token_type: "Bearer", expires_in: 604800 };
  });
}
