// Community core: roles/permissions, moderation, channel structure, message extras,
// social graph, direct messages, profiles/presence and multi-device key distribution.
// Every route re-derives authorization from PostgreSQL; nothing is trusted from the client.
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { Pool, PoolClient } from "pg";
import { randomUUID, createHash } from "node:crypto";
import { z } from "zod";
import { Permissions, ALL_PERMISSIONS, DEFAULT_PERMISSIONS, has, parsePermissionInput } from "./permissions.js";

export type Identity = { id: string; username: string };
export type CommunityContext = {
  db: Pool;
  auth: (header?: string) => Promise<Identity | null>;
  publish: (payload: Record<string, unknown>) => Promise<void>;
  publishEphemeral: (payload: Record<string, unknown>) => Promise<void>;
  takeQuota: (key: string, limit: number, windowSeconds: number) => Promise<boolean>;
};
export type Access = { guildId: string; kind: "community" | "dm"; ownerId: string; owner: boolean; perms: bigint; top: number };

const uuid = z.string().uuid();
const DM_PERMISSIONS = Permissions.SEND_MESSAGES | Permissions.ADD_REACTIONS | Permissions.CHANGE_NICKNAME;
// Presence is derived from Gateway heartbeats so it is consistent across API instances.
export const PRESENCE_SQL =
  "CASE WHEN pr.last_seen>now()-interval '90 seconds' AND COALESCE(up.status,'online')<>'invisible' THEN COALESCE(up.status,'online') ELSE 'offline' END";

/** Effective guild permissions for a user, or null when the user is not a member. */
export async function guildAccess(db: Pool | PoolClient, guildId: string, userId: string): Promise<Access | null> {
  const r = await db.query(
    `SELECT g.owner_id,g.kind,
      COALESCE((SELECT permissions FROM guild_roles WHERE guild_id=g.id AND is_default),$3::bigint)::text AS base,
      COALESCE((SELECT bit_or(r.permissions) FROM guild_member_roles mr JOIN guild_roles r ON r.id=mr.role_id WHERE mr.guild_id=g.id AND mr.user_id=$2),0)::text AS extra,
      COALESCE((SELECT max(r.position) FROM guild_member_roles mr JOIN guild_roles r ON r.id=mr.role_id WHERE mr.guild_id=g.id AND mr.user_id=$2),0) AS top
     FROM guilds g JOIN guild_members gm ON gm.guild_id=g.id AND gm.user_id=$2 WHERE g.id=$1`,
    [guildId, userId, DEFAULT_PERMISSIONS.toString()]
  );
  const row = r.rows[0];
  if (!row) return null;
  const owner = row.owner_id === userId;
  let perms = BigInt(row.base) | BigInt(row.extra);
  if (row.kind === "dm") perms = DM_PERMISSIONS;
  if (owner || perms & Permissions.ADMINISTRATOR) perms = ALL_PERMISSIONS;
  return { guildId, kind: row.kind, ownerId: row.owner_id, owner, perms, top: owner ? Number.MAX_SAFE_INTEGER : Number(row.top) };
}
export async function channelAccess(db: Pool | PoolClient, channelId: string, userId: string) {
  const c = await db.query("SELECT id,guild_id,kind,name FROM channels WHERE id=$1", [channelId]);
  if (!c.rowCount) return null;
  const access = await guildAccess(db, c.rows[0].guild_id, userId);
  return access ? { ...access, channel: c.rows[0] as { id: string; guild_id: string; kind: string; name: string } } : null;
}
/** Highest role position of a member (owner is above everyone). */
async function memberTop(db: Pool, guildId: string, userId: string) {
  const r = await db.query(
    "SELECT g.owner_id,COALESCE((SELECT max(r.position) FROM guild_member_roles mr JOIN guild_roles r ON r.id=mr.role_id WHERE mr.guild_id=g.id AND mr.user_id=$2),0) AS top,EXISTS(SELECT 1 FROM guild_members WHERE guild_id=g.id AND user_id=$2) AS member FROM guilds g WHERE g.id=$1",
    [guildId, userId]
  );
  const row = r.rows[0];
  if (!row) return null;
  return { member: row.member as boolean, owner: row.owner_id === userId, top: row.owner_id === userId ? Number.MAX_SAFE_INTEGER : Number(row.top) };
}
/** Server-side recomputation of the browser fingerprint (apps/web/crypto.mjs). */
export function bundleFingerprint(bundle: any): string | null {
  const jwk = z.object({ kty: z.literal("EC"), crv: z.literal("P-256"), x: z.string().regex(/^[A-Za-z0-9_-]{43}$/), y: z.string().regex(/^[A-Za-z0-9_-]{43}$/) }).passthrough();
  const parsed = z.object({ version: z.literal(1), agreement: jwk, signing: jwk }).safeParse(bundle);
  if (!parsed.success) return null;
  if ("d" in parsed.data.agreement || "d" in parsed.data.signing) return null; // never accept private material
  const b = parsed.data;
  const canonical = JSON.stringify([b.version, b.agreement.x, b.agreement.y, b.signing.x, b.signing.y]);
  return createHash("sha256").update(canonical).digest("base64url");
}
const emojiPattern = /^[^\s\u0000-\u001f\u007f<>]{1,32}$/u;

export function registerCommunity(app: FastifyInstance, ctx: CommunityContext) {
  const { db } = ctx;
  type Handler = (request: FastifyRequest, reply: FastifyReply, user: Identity) => Promise<unknown>;
  const authed = (handler: Handler) => async (request: FastifyRequest, reply: FastifyReply) => {
    const user = await ctx.auth(request.headers.authorization);
    if (!user) return reply.code(401).send({ message: "Unauthorized" });
    return handler(request, reply, user);
  };
  const fail = (reply: FastifyReply, code: number, message: string) => reply.code(code).send({ message });
  const params = (request: FastifyRequest) => request.params as Record<string, string>;
  const ids = (...values: (string | undefined)[]) => values.every((v) => uuid.safeParse(v).success);
  async function audit(guildId: string, actorId: string, action: string, targetId: string | null, details: Record<string, unknown> = {}) {
    await db.query("INSERT INTO guild_audit_log(guild_id,actor_id,action,target_id,details) VALUES($1,$2,$3,$4,$5::jsonb)", [guildId, actorId, action, targetId, JSON.stringify(details)]);
  }
  const dispatchGuild = (guild: string, t: string, d: Record<string, unknown>) => ctx.publish({ kind: "dispatch", guild, t, d });
  const dispatchUsers = (users: string[], t: string, d: Record<string, unknown>) => ctx.publish({ kind: "dispatch", users: [...new Set(users)].slice(0, 50), t, d });
  const dispatchChannel = (channel: string, t: string, d: Record<string, unknown>) => ctx.publish({ kind: "dispatch", channel, t, d });
  async function memberIds(guildId: string) {
    return (await db.query("SELECT user_id FROM guild_members WHERE guild_id=$1", [guildId])).rows.map((r: { user_id: string }) => r.user_id);
  }
  const roleRow = (r: any) => ({ id: r.id, name: r.name, color: r.color, permissions: String(r.permissions), position: r.position, hoist: r.hoist, is_default: r.is_default });

  // ---------------------------------------------------------------- guilds
  app.get("/api/v1/guilds/:id", authed(async (request, reply, user) => {
    const { id } = params(request);
    if (!ids(id)) return fail(reply, 400, "Invalid community ID");
    const access = await guildAccess(db, id, user.id);
    if (!access) return fail(reply, 403, "Not a member");
    const g = await db.query("SELECT g.id,g.name,g.description,g.owner_id,g.kind,g.created_at,(SELECT count(*)::int FROM guild_members WHERE guild_id=g.id) AS member_count FROM guilds g WHERE g.id=$1", [id]);
    const roles = await db.query("SELECT * FROM guild_roles WHERE guild_id=$1 ORDER BY position DESC,created_at", [id]);
    return { ...g.rows[0], permissions: access.perms.toString(), roles: roles.rows.map(roleRow) };
  }));
  const guildPatch = z.object({ name: z.string().trim().min(1).max(100).optional(), description: z.string().trim().max(1000).optional() });
  app.patch("/api/v1/guilds/:id", authed(async (request, reply, user) => {
    const { id } = params(request);
    if (!ids(id)) return fail(reply, 400, "Invalid community ID");
    const data = guildPatch.safeParse(request.body);
    if (!data.success) return fail(reply, 400, "Invalid community settings");
    const access = await guildAccess(db, id, user.id);
    if (!access || access.kind !== "community" || !has(access.perms, Permissions.MANAGE_GUILD)) return fail(reply, 403, "Missing MANAGE_GUILD permission");
    const r = await db.query("UPDATE guilds SET name=COALESCE($2,name),description=COALESCE($3,description),updated_at=now() WHERE id=$1 RETURNING id,name,description,owner_id", [id, data.data.name ?? null, data.data.description ?? null]);
    await audit(id, user.id, "guild.update", id, data.data);
    await dispatchGuild(id, "GUILD_UPDATE", r.rows[0]);
    return r.rows[0];
  }));
  app.delete("/api/v1/guilds/:id", authed(async (request, reply, user) => {
    const { id } = params(request);
    if (!ids(id)) return fail(reply, 400, "Invalid community ID");
    const members = await memberIds(id);
    const r = await db.query("DELETE FROM guilds WHERE id=$1 AND owner_id=$2 AND kind='community' RETURNING id", [id, user.id]);
    if (!r.rowCount) return fail(reply, 403, "Only the owner may delete this community");
    await dispatchUsers(members, "GUILD_DELETE", { id });
    return reply.code(204).send();
  }));
  app.post("/api/v1/guilds/:id/transfer", authed(async (request, reply, user) => {
    const { id } = params(request);
    const body = z.object({ user_id: z.string().uuid() }).safeParse(request.body);
    if (!ids(id) || !body.success) return fail(reply, 400, "Invalid transfer");
    const r = await db.query(
      "UPDATE guilds g SET owner_id=$3,updated_at=now() WHERE g.id=$1 AND g.owner_id=$2 AND g.kind='community' AND $3<>$2 AND EXISTS(SELECT 1 FROM guild_members WHERE guild_id=$1 AND user_id=$3) RETURNING id,name,description,owner_id",
      [id, user.id, body.data.user_id]
    );
    if (!r.rowCount) return fail(reply, 403, "Only the owner may transfer ownership to another member");
    await audit(id, user.id, "guild.transfer", body.data.user_id);
    await dispatchGuild(id, "GUILD_UPDATE", r.rows[0]);
    return r.rows[0];
  }));
  app.get("/api/v1/guilds/:id/audit-log", authed(async (request, reply, user) => {
    const { id } = params(request);
    const q = z.object({ before: z.coerce.number().int().positive().optional() }).safeParse(request.query);
    if (!ids(id) || !q.success) return fail(reply, 400, "Invalid request");
    const access = await guildAccess(db, id, user.id);
    if (!access || !has(access.perms, Permissions.VIEW_AUDIT_LOG)) return fail(reply, 403, "Missing VIEW_AUDIT_LOG permission");
    const r = await db.query(
      "SELECT a.id::text AS id,a.action,a.target_id,a.details,a.created_at,a.actor_id,u.username AS actor_username FROM guild_audit_log a LEFT JOIN users u ON u.id=a.actor_id WHERE a.guild_id=$1 AND ($2::bigint IS NULL OR a.id<$2) ORDER BY a.id DESC LIMIT 50",
      [id, q.data.before ?? null]
    );
    return r.rows;
  }));

  // ---------------------------------------------------------------- channels
  app.delete("/api/v1/channels/:id", authed(async (request, reply, user) => {
    const { id } = params(request);
    if (!ids(id)) return fail(reply, 400, "Invalid channel ID");
    const access = await channelAccess(db, id, user.id);
    if (!access || access.kind !== "community" || !has(access.perms, Permissions.MANAGE_CHANNELS)) return fail(reply, 403, "Missing MANAGE_CHANNELS permission");
    if (access.channel.kind !== "category") {
      const remaining = await db.query("SELECT count(*)::int AS n FROM channels WHERE guild_id=$1 AND kind<>'category' AND id<>$2", [access.guildId, id]);
      if (remaining.rows[0].n < 1) return fail(reply, 409, "A community must keep at least one text channel");
    }
    await db.query("DELETE FROM channels WHERE id=$1", [id]);
    await audit(access.guildId, user.id, "channel.delete", id, { name: access.channel.name });
    await dispatchGuild(access.guildId, "CHANNEL_DELETE", { id, guild_id: access.guildId });
    return reply.code(204).send();
  }));
  const orderInput = z.array(z.object({ id: z.string().uuid(), position: z.number().int().min(0).max(10000), parent_id: z.string().uuid().nullable().optional() })).min(1).max(200);
  app.put("/api/v1/guilds/:id/channels/order", authed(async (request, reply, user) => {
    const { id } = params(request);
    const data = orderInput.safeParse(request.body);
    if (!ids(id) || !data.success) return fail(reply, 400, "Invalid channel order");
    const access = await guildAccess(db, id, user.id);
    if (!access || access.kind !== "community" || !has(access.perms, Permissions.MANAGE_CHANNELS)) return fail(reply, 403, "Missing MANAGE_CHANNELS permission");
    const client = await db.connect();
    try {
      await client.query("BEGIN");
      for (const item of data.data) {
        // Parent must be a category in the same community; categories cannot nest.
        const r = await client.query(
          "UPDATE channels c SET position=$3,parent_id=CASE WHEN $4::boolean THEN c.parent_id ELSE $5::uuid END WHERE c.id=$1 AND c.guild_id=$2 AND ($5::uuid IS NULL OR (c.kind<>'category' AND EXISTS(SELECT 1 FROM channels p WHERE p.id=$5 AND p.guild_id=$2 AND p.kind='category'))) RETURNING c.id",
          [item.id, id, item.position, item.parent_id === undefined, item.parent_id ?? null]
        );
        if (!r.rowCount) { await client.query("ROLLBACK"); return fail(reply, 400, "Invalid channel or parent category"); }
      }
      await client.query("COMMIT");
    } catch (error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); }
    await dispatchGuild(id, "CHANNELS_REORDER", { guild_id: id });
    return reply.code(204).send();
  }));

  // ---------------------------------------------------------------- roles
  app.get("/api/v1/guilds/:id/roles", authed(async (request, reply, user) => {
    const { id } = params(request);
    if (!ids(id)) return fail(reply, 400, "Invalid community ID");
    if (!(await guildAccess(db, id, user.id))) return fail(reply, 403, "Not a member");
    const r = await db.query("SELECT * FROM guild_roles WHERE guild_id=$1 ORDER BY position DESC,created_at", [id]);
    return r.rows.map(roleRow);
  }));
  const roleInput = z.object({
    name: z.string().trim().min(1).max(100).optional(),
    color: z.number().int().min(0).max(0xffffff).optional(),
    permissions: z.union([z.string(), z.number()]).optional(),
    hoist: z.boolean().optional(),
    position: z.number().int().min(1).max(250).optional(),
  });
  async function ensureDefaultRole(guildId: string) {
    await db.query("INSERT INTO guild_roles(id,guild_id,name,permissions,position,is_default) SELECT $1,$1,'@everyone',$2::bigint,0,true WHERE NOT EXISTS(SELECT 1 FROM guild_roles WHERE guild_id=$1 AND is_default)", [guildId, DEFAULT_PERMISSIONS.toString()]);
  }
  app.post("/api/v1/guilds/:id/roles", authed(async (request, reply, user) => {
    const { id } = params(request);
    const data = roleInput.safeParse(request.body ?? {});
    if (!ids(id) || !data.success) return fail(reply, 400, "Invalid role");
    const access = await guildAccess(db, id, user.id);
    if (!access || access.kind !== "community" || !has(access.perms, Permissions.MANAGE_ROLES)) return fail(reply, 403, "Missing MANAGE_ROLES permission");
    const perms = data.data.permissions === undefined ? 0n : parsePermissionInput(data.data.permissions);
    if (perms === null) return fail(reply, 400, "Invalid permissions");
    if ((perms & ~access.perms) !== 0n) return fail(reply, 403, "You cannot grant permissions you do not have");
    const count = await db.query("SELECT count(*)::int AS n FROM guild_roles WHERE guild_id=$1", [id]);
    if (count.rows[0].n >= 250) return fail(reply, 409, "Role limit reached");
    await ensureDefaultRole(id);
    const roleId = randomUUID();
    // New roles enter at the bottom of the hierarchy (position 1) so they are always below the creator.
    await db.query("UPDATE guild_roles SET position=position+1 WHERE guild_id=$1 AND NOT is_default", [id]);
    const r = await db.query("INSERT INTO guild_roles(id,guild_id,name,color,permissions,position,hoist) VALUES($1,$2,$3,$4,$5::bigint,1,$6) RETURNING *", [roleId, id, data.data.name ?? "new role", data.data.color ?? 0, perms.toString(), data.data.hoist ?? false]);
    await audit(id, user.id, "role.create", roleId, { name: r.rows[0].name });
    await dispatchGuild(id, "GUILD_ROLES_UPDATE", { guild_id: id });
    return reply.code(201).send(roleRow(r.rows[0]));
  }));
  app.patch("/api/v1/guilds/:id/roles/:roleId", authed(async (request, reply, user) => {
    const { id, roleId } = params(request);
    const data = roleInput.safeParse(request.body ?? {});
    if (!ids(id, roleId) || !data.success) return fail(reply, 400, "Invalid role");
    const access = await guildAccess(db, id, user.id);
    if (!access || access.kind !== "community" || !has(access.perms, Permissions.MANAGE_ROLES)) return fail(reply, 403, "Missing MANAGE_ROLES permission");
    await ensureDefaultRole(id);
    const role = (await db.query("SELECT * FROM guild_roles WHERE id=$1 AND guild_id=$2", [roleId, id])).rows[0];
    if (!role) return fail(reply, 404, "Role not found");
    if (!access.owner && role.position >= access.top && !role.is_default) return fail(reply, 403, "Role is above your highest role");
    if (role.is_default && (data.data.name !== undefined || data.data.position !== undefined)) return fail(reply, 400, "@everyone cannot be renamed or moved");
    if (data.data.position !== undefined && !access.owner && data.data.position >= access.top) return fail(reply, 403, "Cannot move a role above your highest role");
    let perms: bigint | null = null;
    if (data.data.permissions !== undefined) {
      perms = parsePermissionInput(data.data.permissions);
      if (perms === null) return fail(reply, 400, "Invalid permissions");
      const changed = perms ^ BigInt(role.permissions);
      if ((changed & ~access.perms) !== 0n) return fail(reply, 403, "You cannot change permissions you do not have");
    }
    const r = await db.query(
      "UPDATE guild_roles SET name=COALESCE($3,name),color=COALESCE($4,color),permissions=COALESCE($5::bigint,permissions),hoist=COALESCE($6,hoist),position=COALESCE($7,position) WHERE id=$1 AND guild_id=$2 RETURNING *",
      [roleId, id, data.data.name ?? null, data.data.color ?? null, perms?.toString() ?? null, data.data.hoist ?? null, data.data.position ?? null]
    );
    await audit(id, user.id, "role.update", roleId, { ...data.data, permissions: perms?.toString() });
    await dispatchGuild(id, "GUILD_ROLES_UPDATE", { guild_id: id });
    return roleRow(r.rows[0]);
  }));
  app.delete("/api/v1/guilds/:id/roles/:roleId", authed(async (request, reply, user) => {
    const { id, roleId } = params(request);
    if (!ids(id, roleId)) return fail(reply, 400, "Invalid role");
    const access = await guildAccess(db, id, user.id);
    if (!access || access.kind !== "community" || !has(access.perms, Permissions.MANAGE_ROLES)) return fail(reply, 403, "Missing MANAGE_ROLES permission");
    const r = await db.query("DELETE FROM guild_roles WHERE id=$1 AND guild_id=$2 AND NOT is_default AND ($3::boolean OR position<$4) RETURNING name", [roleId, id, access.owner, access.top]);
    if (!r.rowCount) return fail(reply, 404, "Role not found or not manageable");
    await audit(id, user.id, "role.delete", roleId, { name: r.rows[0].name });
    await dispatchGuild(id, "GUILD_ROLES_UPDATE", { guild_id: id });
    return reply.code(204).send();
  }));
  async function changeMemberRole(request: FastifyRequest, reply: FastifyReply, user: Identity, add: boolean) {
    const { id, userId, roleId } = params(request);
    if (!ids(id, userId, roleId)) return fail(reply, 400, "Invalid ID");
    const access = await guildAccess(db, id, user.id);
    if (!access || access.kind !== "community" || !has(access.perms, Permissions.MANAGE_ROLES)) return fail(reply, 403, "Missing MANAGE_ROLES permission");
    const role = (await db.query("SELECT position,is_default,name FROM guild_roles WHERE id=$1 AND guild_id=$2", [roleId, id])).rows[0];
    if (!role || role.is_default) return fail(reply, 404, "Role not found");
    if (!access.owner && role.position >= access.top) return fail(reply, 403, "Role is above your highest role");
    if (add) {
      const r = await db.query("INSERT INTO guild_member_roles(guild_id,user_id,role_id) SELECT $1,$2,$3 WHERE EXISTS(SELECT 1 FROM guild_members WHERE guild_id=$1 AND user_id=$2) ON CONFLICT DO NOTHING RETURNING role_id", [id, userId, roleId]);
      if (!r.rowCount) {
        const member = await db.query("SELECT 1 FROM guild_members WHERE guild_id=$1 AND user_id=$2", [id, userId]);
        if (!member.rowCount) return fail(reply, 404, "Member not found");
      }
    } else {
      await db.query("DELETE FROM guild_member_roles WHERE guild_id=$1 AND user_id=$2 AND role_id=$3", [id, userId, roleId]);
    }
    await audit(id, user.id, add ? "member.role_add" : "member.role_remove", userId, { role: role.name });
    await dispatchGuild(id, "GUILD_MEMBER_UPDATE", { guild_id: id, user_id: userId });
    return reply.code(204).send();
  }
  app.put("/api/v1/guilds/:id/members/:userId/roles/:roleId", authed((q, r, u) => changeMemberRole(q, r, u, true)));
  app.delete("/api/v1/guilds/:id/members/:userId/roles/:roleId", authed((q, r, u) => changeMemberRole(q, r, u, false)));

  // ---------------------------------------------------------------- members
  app.patch("/api/v1/guilds/:id/members/:userId", authed(async (request, reply, user) => {
    const { id } = params(request);
    const target = params(request).userId === "@me" ? user.id : params(request).userId;
    const data = z.object({ nickname: z.string().trim().max(32).nullable() }).safeParse(request.body);
    if (!ids(id, target) || !data.success) return fail(reply, 400, "Invalid nickname");
    const access = await guildAccess(db, id, user.id);
    if (!access) return fail(reply, 403, "Not a member");
    if (target === user.id) {
      if (!has(access.perms, Permissions.CHANGE_NICKNAME)) return fail(reply, 403, "Missing CHANGE_NICKNAME permission");
    } else {
      const other = await memberTop(db, id, target);
      if (!has(access.perms, Permissions.MANAGE_NICKNAMES) || !other?.member || other.owner || (!access.owner && other.top >= access.top)) return fail(reply, 403, "Cannot change this member's nickname");
    }
    const nickname = data.data.nickname ? data.data.nickname : null;
    const r = await db.query("UPDATE guild_members SET nickname=$3 WHERE guild_id=$1 AND user_id=$2 RETURNING user_id", [id, target, nickname]);
    if (!r.rowCount) return fail(reply, 404, "Member not found");
    if (target !== user.id) await audit(id, user.id, "member.nickname", target, { nickname });
    await dispatchGuild(id, "GUILD_MEMBER_UPDATE", { guild_id: id, user_id: target });
    return { user_id: target, nickname };
  }));

  // ---------------------------------------------------------------- bans
  app.get("/api/v1/guilds/:id/bans", authed(async (request, reply, user) => {
    const { id } = params(request);
    if (!ids(id)) return fail(reply, 400, "Invalid community ID");
    const access = await guildAccess(db, id, user.id);
    if (!access || !has(access.perms, Permissions.BAN_MEMBERS)) return fail(reply, 403, "Missing BAN_MEMBERS permission");
    const r = await db.query("SELECT b.user_id,u.username,b.reason,b.created_at FROM guild_bans b JOIN users u ON u.id=b.user_id WHERE b.guild_id=$1 ORDER BY b.created_at DESC LIMIT 500", [id]);
    return r.rows;
  }));
  app.put("/api/v1/guilds/:id/bans/:userId", authed(async (request, reply, user) => {
    const { id, userId } = params(request);
    const data = z.object({ reason: z.string().trim().max(512).default("") }).safeParse(request.body ?? {});
    if (!ids(id, userId) || !data.success) return fail(reply, 400, "Invalid ban");
    const access = await guildAccess(db, id, user.id);
    if (!access || access.kind !== "community" || !has(access.perms, Permissions.BAN_MEMBERS)) return fail(reply, 403, "Missing BAN_MEMBERS permission");
    if (userId === user.id) return fail(reply, 400, "You cannot ban yourself");
    const other = await memberTop(db, id, userId);
    if (!other || other.owner || (other.member && !access.owner && other.top >= access.top)) return fail(reply, 403, "Cannot ban this user");
    const exists = await db.query("SELECT 1 FROM users WHERE id=$1", [userId]);
    if (!exists.rowCount) return fail(reply, 404, "User not found");
    const client = await db.connect();
    try {
      await client.query("BEGIN");
      await client.query("INSERT INTO guild_bans(guild_id,user_id,reason,banned_by) VALUES($1,$2,$3,$4) ON CONFLICT(guild_id,user_id) DO UPDATE SET reason=EXCLUDED.reason", [id, userId, data.data.reason, user.id]);
      // Deleting membership fires the 0005 trigger, which evicts Gateway subscriptions on every instance.
      await client.query("DELETE FROM guild_members gm USING guilds g WHERE gm.guild_id=$1 AND gm.user_id=$2 AND g.id=gm.guild_id AND g.owner_id<>gm.user_id", [id, userId]);
      await client.query("COMMIT");
    } catch (error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); }
    await audit(id, user.id, "member.ban", userId, { reason: data.data.reason });
    await dispatchGuild(id, "GUILD_MEMBER_REMOVE", { guild_id: id, user_id: userId });
    await dispatchUsers([userId], "GUILD_DELETE", { id });
    return reply.code(204).send();
  }));
  app.delete("/api/v1/guilds/:id/bans/:userId", authed(async (request, reply, user) => {
    const { id, userId } = params(request);
    if (!ids(id, userId)) return fail(reply, 400, "Invalid ID");
    const access = await guildAccess(db, id, user.id);
    if (!access || !has(access.perms, Permissions.BAN_MEMBERS)) return fail(reply, 403, "Missing BAN_MEMBERS permission");
    const r = await db.query("DELETE FROM guild_bans WHERE guild_id=$1 AND user_id=$2 RETURNING user_id", [id, userId]);
    if (!r.rowCount) return fail(reply, 404, "Ban not found");
    await audit(id, user.id, "member.unban", userId);
    return reply.code(204).send();
  }));

  // ---------------------------------------------------------------- invites
  app.get("/api/v1/guilds/:id/invites", authed(async (request, reply, user) => {
    const { id } = params(request);
    if (!ids(id)) return fail(reply, 400, "Invalid community ID");
    const access = await guildAccess(db, id, user.id);
    if (!access || !has(access.perms, Permissions.MANAGE_GUILD)) return fail(reply, 403, "Missing MANAGE_GUILD permission");
    // Invite codes are only stored as hashes; lists expose a short hint and a revocation ID.
    const r = await db.query("SELECT left(i.code_hash,16) AS id,i.code_hint,i.uses,i.max_uses,i.expires_at,i.created_at,u.username AS created_by FROM guild_invites i JOIN users u ON u.id=i.created_by WHERE i.guild_id=$1 AND i.expires_at>now() ORDER BY i.created_at DESC LIMIT 200", [id]);
    return r.rows;
  }));
  app.delete("/api/v1/guilds/:id/invites/:inviteId", authed(async (request, reply, user) => {
    const { id, inviteId } = params(request);
    if (!ids(id) || !/^[a-f0-9]{16}$/.test(inviteId ?? "")) return fail(reply, 400, "Invalid invite");
    const access = await guildAccess(db, id, user.id);
    if (!access) return fail(reply, 403, "Not a member");
    const r = await db.query("DELETE FROM guild_invites WHERE guild_id=$1 AND left(code_hash,16)=$2 AND ($3::boolean OR created_by=$4) RETURNING code_hint", [id, inviteId, has(access.perms, Permissions.MANAGE_GUILD), user.id]);
    if (!r.rowCount) return fail(reply, 404, "Invite not found or not permitted");
    await audit(id, user.id, "invite.delete", inviteId, { hint: r.rows[0].code_hint });
    return reply.code(204).send();
  }));
  app.get("/api/v1/invites/:code", authed(async (request, reply, user) => {
    const { code } = params(request);
    if (!(await ctx.takeQuota("invite-preview:" + user.id, 60, 3600))) return fail(reply, 429, "Too many invite lookups");
    if (!/^[A-Za-z0-9_-]{32}$/.test(code ?? "")) return fail(reply, 404, "Invite not found");
    const r = await db.query(
      "SELECT g.id,g.name,g.description,i.expires_at,(SELECT count(*)::int FROM guild_members WHERE guild_id=g.id) AS member_count,EXISTS(SELECT 1 FROM guild_members WHERE guild_id=g.id AND user_id=$2) AS already_member FROM guild_invites i JOIN guilds g ON g.id=i.guild_id WHERE i.code_hash=$1 AND i.expires_at>now() AND i.uses<i.max_uses",
      [createHash("sha256").update(code).digest("hex"), user.id]
    );
    if (!r.rowCount) return fail(reply, 404, "Invite expired or unavailable");
    const row = r.rows[0];
    return { guild: { id: row.id, name: row.name, description: row.description }, member_count: row.member_count, expires_at: row.expires_at, already_member: row.already_member };
  }));

  // ---------------------------------------------------------------- message extras
  const editInput = z.object({ ciphertext: z.string().min(1).max(800000), algorithm: z.literal("client-encrypted-v1") });
  app.patch("/api/v10/channels/:id/messages/:messageId", authed(async (request, reply, user) => {
    const { id, messageId } = params(request);
    const data = editInput.safeParse(request.body);
    if (!ids(id, messageId) || !data.success) return fail(reply, 400, "Only opaque ciphertext envelopes are accepted");
    // Author-only edit. Membership and the current key epoch are checked in the same statement.
    const r = await db.query(
      "UPDATE messages m SET ciphertext=$4,edited_at=now() FROM channels c JOIN guild_members gm ON gm.guild_id=c.guild_id LEFT JOIN guild_key_epochs e ON e.guild_id=c.guild_id WHERE m.id=$1 AND m.channel_id=$2 AND m.author_id=$3 AND c.id=m.channel_id AND gm.user_id=$3 AND (CASE WHEN left($4,1)='{' THEN COALESCE(($4::jsonb->'context'->>'epoch')::bigint,-1)=COALESCE(e.epoch,1) ELSE true END) RETURNING m.id,m.edited_at",
      [messageId, id, user.id, data.data.ciphertext]
    );
    if (!r.rowCount) return fail(reply, 404, "Message not found, not yours, or stale key epoch");
    await ctx.publish({ kind: "message_updated", channel: id, message: messageId });
    return r.rows[0];
  }));
  async function react(request: FastifyRequest, reply: FastifyReply, user: Identity, add: boolean) {
    const { id, messageId } = params(request);
    const target = params(request).userId ?? "@me";
    let emoji: string;
    try { emoji = decodeURIComponent(params(request).emoji ?? ""); } catch { return fail(reply, 400, "Invalid emoji"); }
    if (!ids(id, messageId) || !emojiPattern.test(emoji)) return fail(reply, 400, "Invalid emoji");
    const access = await channelAccess(db, id, user.id);
    if (!access) return fail(reply, 403, "Forbidden");
    const msg = await db.query("SELECT 1 FROM messages WHERE id=$1 AND channel_id=$2", [messageId, id]);
    if (!msg.rowCount) return fail(reply, 404, "Message not found");
    let userId = user.id;
    if (target !== "@me") {
      if (!uuid.safeParse(target).success || !has(access.perms, Permissions.MANAGE_MESSAGES)) return fail(reply, 403, "Missing MANAGE_MESSAGES permission");
      userId = target;
    }
    if (add) {
      if (!has(access.perms, Permissions.ADD_REACTIONS)) return fail(reply, 403, "Missing ADD_REACTIONS permission");
      const distinct = await db.query("SELECT count(DISTINCT emoji)::int AS n,bool_or(emoji=$2) AS present FROM message_reactions WHERE message_id=$1", [messageId, emoji]);
      if (distinct.rows[0].n >= 20 && !distinct.rows[0].present) return fail(reply, 409, "Reaction limit reached");
      const r = await db.query("INSERT INTO message_reactions(message_id,user_id,emoji) VALUES($1,$2,$3) ON CONFLICT DO NOTHING RETURNING emoji", [messageId, userId, emoji]);
      if (r.rowCount) await dispatchChannel(id, "MESSAGE_REACTION_ADD", { channel_id: id, message_id: messageId, user_id: userId, emoji });
    } else {
      const r = await db.query("DELETE FROM message_reactions WHERE message_id=$1 AND user_id=$2 AND emoji=$3 RETURNING emoji", [messageId, userId, emoji]);
      if (r.rowCount) await dispatchChannel(id, "MESSAGE_REACTION_REMOVE", { channel_id: id, message_id: messageId, user_id: userId, emoji });
    }
    return reply.code(204).send();
  }
  app.put("/api/v10/channels/:id/messages/:messageId/reactions/:emoji/@me", authed((q, r, u) => react(q, r, u, true)));
  app.delete("/api/v10/channels/:id/messages/:messageId/reactions/:emoji/@me", authed((q, r, u) => react(q, r, u, false)));
  app.delete("/api/v10/channels/:id/messages/:messageId/reactions/:emoji/:userId", authed((q, r, u) => react(q, r, u, false)));
  app.get("/api/v10/channels/:id/messages/:messageId/reactions/:emoji", authed(async (request, reply, user) => {
    const { id, messageId } = params(request);
    let emoji: string;
    try { emoji = decodeURIComponent(params(request).emoji ?? ""); } catch { return fail(reply, 400, "Invalid emoji"); }
    if (!ids(id, messageId) || !emojiPattern.test(emoji)) return fail(reply, 400, "Invalid emoji");
    if (!(await channelAccess(db, id, user.id))) return fail(reply, 403, "Forbidden");
    const r = await db.query("SELECT u.id,u.username FROM message_reactions x JOIN messages m ON m.id=x.message_id JOIN users u ON u.id=x.user_id WHERE x.message_id=$1 AND m.channel_id=$2 AND x.emoji=$3 ORDER BY x.created_at LIMIT 100", [messageId, id, emoji]);
    return r.rows;
  }));
  app.get("/api/v10/channels/:id/pins", authed(async (request, reply, user) => {
    const { id } = params(request);
    if (!ids(id)) return fail(reply, 400, "Invalid channel ID");
    if (!(await channelAccess(db, id, user.id))) return fail(reply, 403, "Forbidden");
    const r = await db.query("SELECT m.id,m.channel_id,m.author_id,u.username AS author_username,m.ciphertext,m.algorithm,m.created_at,m.edited_at,m.reply_to,p.pinned_at FROM message_pins p JOIN messages m ON m.id=p.message_id LEFT JOIN users u ON u.id=m.author_id WHERE p.channel_id=$1 ORDER BY p.pinned_at DESC LIMIT 50", [id]);
    return r.rows;
  }));
  async function pin(request: FastifyRequest, reply: FastifyReply, user: Identity, add: boolean) {
    const { id, messageId } = params(request);
    if (!ids(id, messageId)) return fail(reply, 400, "Invalid ID");
    const access = await channelAccess(db, id, user.id);
    if (!access || (access.kind === "community" && !has(access.perms, Permissions.MANAGE_MESSAGES))) return fail(reply, 403, "Missing MANAGE_MESSAGES permission");
    if (add) {
      const count = await db.query("SELECT count(*)::int AS n FROM message_pins WHERE channel_id=$1", [id]);
      if (count.rows[0].n >= 50) return fail(reply, 409, "Pin limit reached (50)");
      const r = await db.query("INSERT INTO message_pins(channel_id,message_id,pinned_by) SELECT $1,m.id,$3 FROM messages m WHERE m.id=$2 AND m.channel_id=$1 ON CONFLICT DO NOTHING RETURNING message_id", [id, messageId, user.id]);
      if (!r.rowCount) {
        const exists = await db.query("SELECT 1 FROM messages WHERE id=$1 AND channel_id=$2", [messageId, id]);
        if (!exists.rowCount) return fail(reply, 404, "Message not found");
      }
    } else {
      await db.query("DELETE FROM message_pins WHERE channel_id=$1 AND message_id=$2", [id, messageId]);
    }
    if (access.kind === "community") await audit(access.guildId, user.id, add ? "message.pin" : "message.unpin", messageId, { channel: id });
    await dispatchChannel(id, "CHANNEL_PINS_UPDATE", { channel_id: id, message_id: messageId, pinned: add });
    return reply.code(204).send();
  }
  app.put("/api/v10/channels/:id/pins/:messageId", authed((q, r, u) => pin(q, r, u, true)));
  app.delete("/api/v10/channels/:id/pins/:messageId", authed((q, r, u) => pin(q, r, u, false)));
  app.post("/api/v1/channels/:id/ack", authed(async (request, reply, user) => {
    const { id } = params(request);
    const data = z.object({ message_id: z.string().uuid().optional() }).safeParse(request.body ?? {});
    if (!ids(id) || !data.success) return fail(reply, 400, "Invalid acknowledgement");
    if (!(await channelAccess(db, id, user.id))) return fail(reply, 403, "Forbidden");
    await db.query("INSERT INTO channel_read_states(user_id,channel_id,last_read_at,last_message_id) VALUES($1,$2,now(),$3) ON CONFLICT(user_id,channel_id) DO UPDATE SET last_read_at=now(),last_message_id=COALESCE(EXCLUDED.last_message_id,channel_read_states.last_message_id)", [user.id, id, data.data.message_id ?? null]);
    return reply.code(204).send();
  }));
  app.get("/api/v1/users/@me/read-states", authed(async (_request, _reply, user) => {
    const r = await db.query("SELECT rs.channel_id,rs.last_read_at,rs.last_message_id FROM channel_read_states rs JOIN channels c ON c.id=rs.channel_id JOIN guild_members gm ON gm.guild_id=c.guild_id AND gm.user_id=rs.user_id WHERE rs.user_id=$1", [user.id]);
    return r.rows;
  }));

  // ---------------------------------------------------------------- relationships
  const relationshipList = async (userId: string) =>
    (await db.query(
      `SELECT r.status,r.created_at,u.id,u.username,COALESCE(up.display_name,'') AS display_name,${PRESENCE_SQL} AS presence
       FROM user_relationships r JOIN users u ON u.id=r.target_id LEFT JOIN user_profiles up ON up.user_id=u.id LEFT JOIN user_presence pr ON pr.user_id=u.id
       WHERE r.user_id=$1 ORDER BY u.username`, [userId])).rows;
  app.get("/api/v1/users/@me/relationships", authed(async (_request, _reply, user) => relationshipList(user.id)));
  app.post("/api/v1/users/@me/relationships", authed(async (request, reply, user) => {
    const data = z.object({ username: z.string().min(3).max(32).regex(/^[a-zA-Z0-9_]+$/) }).safeParse(request.body);
    if (!data.success) return fail(reply, 400, "Invalid username");
    if (!(await ctx.takeQuota("friend-request:" + user.id, 30, 3600))) return fail(reply, 429, "Too many friend requests");
    const target = (await db.query("SELECT id FROM users WHERE username=$1", [data.data.username])).rows[0];
    // Same response for unknown users and users who blocked you, to avoid disclosing blocks.
    if (!target || target.id === user.id) return fail(reply, 404, "User not found or not accepting requests");
    const rows = await db.query("SELECT user_id,status FROM user_relationships WHERE (user_id=$1 AND target_id=$2) OR (user_id=$2 AND target_id=$1)", [user.id, target.id]);
    const mine = rows.rows.find((r: any) => r.user_id === user.id)?.status, theirs = rows.rows.find((r: any) => r.user_id === target.id)?.status;
    if (theirs === "blocked") return fail(reply, 404, "User not found or not accepting requests");
    if (mine === "blocked") return fail(reply, 409, "Unblock this user first");
    if (mine === "friend") return fail(reply, 409, "Already friends");
    const client = await db.connect();
    let status: string;
    try {
      await client.query("BEGIN");
      if (mine === "incoming") {
        await client.query("UPDATE user_relationships SET status='friend' WHERE (user_id=$1 AND target_id=$2) OR (user_id=$2 AND target_id=$1)", [user.id, target.id]);
        status = "friend";
      } else {
        await client.query("INSERT INTO user_relationships(user_id,target_id,status) VALUES($1,$2,'outgoing') ON CONFLICT(user_id,target_id) DO NOTHING", [user.id, target.id]);
        await client.query("INSERT INTO user_relationships(user_id,target_id,status) VALUES($2,$1,'incoming') ON CONFLICT(user_id,target_id) DO NOTHING", [user.id, target.id]);
        status = "outgoing";
      }
      await client.query("COMMIT");
    } catch (error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); }
    await dispatchUsers([user.id, target.id], "RELATIONSHIP_UPDATE", {});
    return reply.code(201).send({ user_id: target.id, status });
  }));
  app.put("/api/v1/users/@me/relationships/:userId", authed(async (request, reply, user) => {
    const { userId } = params(request);
    const data = z.object({ type: z.enum(["friend", "blocked"]) }).safeParse(request.body);
    if (!ids(userId) || !data.success || userId === user.id) return fail(reply, 400, "Invalid relationship");
    const exists = await db.query("SELECT 1 FROM users WHERE id=$1", [userId]);
    if (!exists.rowCount) return fail(reply, 404, "User not found");
    const client = await db.connect();
    try {
      await client.query("BEGIN");
      if (data.data.type === "friend") {
        const r = await client.query("UPDATE user_relationships SET status='friend' WHERE user_id=$1 AND target_id=$2 AND status='incoming' RETURNING 1", [user.id, userId]);
        if (!r.rowCount) { await client.query("ROLLBACK"); return fail(reply, 409, "No pending friend request from this user"); }
        await client.query("UPDATE user_relationships SET status='friend' WHERE user_id=$2 AND target_id=$1", [user.id, userId]);
      } else {
        await client.query("INSERT INTO user_relationships(user_id,target_id,status) VALUES($1,$2,'blocked') ON CONFLICT(user_id,target_id) DO UPDATE SET status='blocked'", [user.id, userId]);
        await client.query("DELETE FROM user_relationships WHERE user_id=$2 AND target_id=$1 AND status<>'blocked'", [user.id, userId]);
      }
      await client.query("COMMIT");
    } catch (error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); }
    await dispatchUsers([user.id, userId], "RELATIONSHIP_UPDATE", {});
    return reply.code(204).send();
  }));
  app.delete("/api/v1/users/@me/relationships/:userId", authed(async (request, reply, user) => {
    const { userId } = params(request);
    if (!ids(userId)) return fail(reply, 400, "Invalid user");
    const mine = (await db.query("DELETE FROM user_relationships WHERE user_id=$1 AND target_id=$2 RETURNING status", [user.id, userId])).rows[0];
    if (!mine) return fail(reply, 404, "No relationship");
    // Removing a friend/request also removes the mirrored row; a block is one-directional.
    if (mine.status !== "blocked") await db.query("DELETE FROM user_relationships WHERE user_id=$2 AND target_id=$1 AND status<>'blocked'", [user.id, userId]);
    await dispatchUsers([user.id, userId], "RELATIONSHIP_UPDATE", {});
    return reply.code(204).send();
  }));

  // ---------------------------------------------------------------- direct messages
  async function dmList(userId: string) {
    const r = await db.query(
      `SELECT g.id AS guild_id,g.name,g.owner_id,c.id,
        (SELECT max(created_at) FROM messages WHERE channel_id=c.id) AS last_message_at,
        (SELECT json_agg(json_build_object('id',u.id,'username',u.username,'display_name',COALESCE(up.display_name,''),'presence',${PRESENCE_SQL}) ORDER BY u.username)
          FROM guild_members peer JOIN users u ON u.id=peer.user_id LEFT JOIN user_profiles up ON up.user_id=u.id LEFT JOIN user_presence pr ON pr.user_id=u.id
          WHERE peer.guild_id=g.id AND peer.user_id<>$1) AS recipients,
        g.dm_key IS NULL AS is_group
       FROM guilds g JOIN guild_members gm ON gm.guild_id=g.id AND gm.user_id=$1 JOIN channels c ON c.guild_id=g.id
       WHERE g.kind='dm' ORDER BY last_message_at DESC NULLS LAST,g.created_at DESC LIMIT 200`, [userId]);
    return r.rows.map((row: any) => ({ ...row, recipients: row.recipients ?? [], type: row.is_group ? "group_dm" : "dm" }));
  }
  app.get("/api/v1/users/@me/channels", authed(async (_request, _reply, user) => dmList(user.id)));
  /** A user may message someone who is a friend or shares a community, unless either side blocked the other. */
  async function canMessage(userId: string, targetId: string) {
    const r = await db.query(
      `SELECT NOT EXISTS(SELECT 1 FROM user_relationships WHERE status='blocked' AND ((user_id=$1 AND target_id=$2) OR (user_id=$2 AND target_id=$1)))
        AND (EXISTS(SELECT 1 FROM user_relationships WHERE user_id=$1 AND target_id=$2 AND status='friend')
          OR EXISTS(SELECT 1 FROM guild_members a JOIN guild_members b ON b.guild_id=a.guild_id JOIN guilds g ON g.id=a.guild_id AND g.kind='community' WHERE a.user_id=$1 AND b.user_id=$2)) AS ok`,
      [userId, targetId]);
    return r.rows[0].ok as boolean;
  }
  app.post("/api/v1/users/@me/channels", authed(async (request, reply, user) => {
    const data = z.object({ recipient_ids: z.array(z.string().uuid()).min(1).max(9), name: z.string().trim().max(100).optional() }).safeParse(request.body);
    if (!data.success) return fail(reply, 400, "Provide 1–9 recipient IDs");
    const recipients = [...new Set(data.data.recipient_ids)].filter((id) => id !== user.id);
    if (!recipients.length) return fail(reply, 400, "Provide at least one other recipient");
    if (!(await ctx.takeQuota("dm-create:" + user.id, 30, 3600))) return fail(reply, 429, "Too many conversations created");
    for (const target of recipients) if (!(await canMessage(user.id, target))) return fail(reply, 403, "You can only message friends or people who share a community with you");
    const dmKey = recipients.length === 1 ? [user.id, recipients[0]].sort().join(":") : null;
    if (dmKey) {
      const existing = await db.query("SELECT g.id FROM guilds g WHERE g.dm_key=$1", [dmKey]);
      if (existing.rowCount) return (await dmList(user.id)).find((d: any) => d.guild_id === existing.rows[0].id) ?? fail(reply, 409, "Conversation unavailable");
    }
    const guildId = randomUUID(), channelId = randomUUID();
    const client = await db.connect();
    try {
      await client.query("BEGIN");
      await client.query("INSERT INTO guilds(id,name,owner_id,kind,dm_key) VALUES($1,$2,$3,'dm',$4)", [guildId, data.data.name ?? "", user.id, dmKey]);
      for (const member of [user.id, ...recipients]) await client.query("INSERT INTO guild_members(guild_id,user_id) VALUES($1,$2)", [guildId, member]);
      await client.query("INSERT INTO channels(id,guild_id,name) VALUES($1,$2,'dm')", [channelId, guildId]);
      await client.query("COMMIT");
    } catch (error: any) {
      await client.query("ROLLBACK");
      if (error.code === "23505" && dmKey) {
        const existing = await db.query("SELECT id FROM guilds WHERE dm_key=$1", [dmKey]);
        return (await dmList(user.id)).find((d: any) => d.guild_id === existing.rows[0]?.id) ?? fail(reply, 409, "Conversation unavailable");
      }
      throw error;
    } finally { client.release(); }
    await dispatchUsers([user.id, ...recipients], "DM_CREATE", { guild_id: guildId, id: channelId });
    return reply.code(201).send((await dmList(user.id)).find((d: any) => d.guild_id === guildId));
  }));
  app.put("/api/v1/users/@me/channels/:guildId/recipients/:userId", authed(async (request, reply, user) => {
    const { guildId, userId } = params(request);
    if (!ids(guildId, userId)) return fail(reply, 400, "Invalid ID");
    const g = await db.query("SELECT g.dm_key,(SELECT count(*)::int FROM guild_members WHERE guild_id=g.id) AS n FROM guilds g JOIN guild_members gm ON gm.guild_id=g.id AND gm.user_id=$2 WHERE g.id=$1 AND g.kind='dm'", [guildId, user.id]);
    if (!g.rowCount || g.rows[0].dm_key) return fail(reply, 403, "Only group conversations accept new recipients");
    if (g.rows[0].n >= 10) return fail(reply, 409, "Group conversations are limited to 10 people");
    if (!(await canMessage(user.id, userId))) return fail(reply, 403, "You can only add friends or people who share a community with you");
    await db.query("INSERT INTO guild_members(guild_id,user_id) VALUES($1,$2) ON CONFLICT DO NOTHING", [guildId, userId]);
    await dispatchUsers(await memberIds(guildId), "DM_UPDATE", { guild_id: guildId });
    return reply.code(204).send();
  }));
  app.delete("/api/v1/users/@me/channels/:guildId", authed(async (request, reply, user) => {
    const { guildId } = params(request);
    if (!ids(guildId)) return fail(reply, 400, "Invalid ID");
    const g = (await db.query("SELECT g.owner_id,g.dm_key FROM guilds g JOIN guild_members gm ON gm.guild_id=g.id AND gm.user_id=$2 WHERE g.id=$1 AND g.kind='dm'", [guildId, user.id])).rows[0];
    if (!g) return fail(reply, 404, "Conversation not found");
    if (g.dm_key) return fail(reply, 400, "One-to-one conversations cannot be left; block the user instead");
    const client = await db.connect();
    try {
      await client.query("BEGIN");
      if (g.owner_id === user.id) {
        const heir = await client.query("SELECT user_id FROM guild_members WHERE guild_id=$1 AND user_id<>$2 ORDER BY joined_at LIMIT 1", [guildId, user.id]);
        if (heir.rowCount) await client.query("UPDATE guilds SET owner_id=$2 WHERE id=$1", [guildId, heir.rows[0].user_id]);
      }
      await client.query("DELETE FROM guild_members WHERE guild_id=$1 AND user_id=$2", [guildId, user.id]);
      const left = await client.query("SELECT count(*)::int AS n FROM guild_members WHERE guild_id=$1", [guildId]);
      if (left.rows[0].n === 0) await client.query("DELETE FROM guilds WHERE id=$1", [guildId]);
      await client.query("COMMIT");
    } catch (error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); }
    await dispatchUsers([user.id, ...(await memberIds(guildId))], "DM_UPDATE", { guild_id: guildId });
    return reply.code(204).send();
  }));

  // ---------------------------------------------------------------- profiles & presence
  app.get("/api/v1/users/:id/profile", authed(async (request, reply, user) => {
    const { id } = params(request);
    if (!ids(id)) return fail(reply, 400, "Invalid user ID");
    const visible = id === user.id || (await db.query(
      "SELECT 1 FROM guild_members a JOIN guild_members b ON b.guild_id=a.guild_id WHERE a.user_id=$1 AND b.user_id=$2 UNION SELECT 1 FROM user_relationships WHERE user_id=$1 AND target_id=$2 AND status IN ('friend','incoming','outgoing') LIMIT 1", [user.id, id])).rowCount;
    if (!visible) return fail(reply, 403, "No shared community or relationship");
    const r = await db.query(`SELECT u.id,u.username,u.created_at,COALESCE(up.display_name,'') AS display_name,COALESCE(up.bio,'') AS bio,COALESCE(up.custom_status,'') AS custom_status,COALESCE(up.accent_color,7331258) AS accent_color,${PRESENCE_SQL} AS presence FROM users u LEFT JOIN user_profiles up ON up.user_id=u.id LEFT JOIN user_presence pr ON pr.user_id=u.id WHERE u.id=$1`, [id]);
    if (!r.rowCount) return fail(reply, 404, "User not found");
    const links = await db.query("SELECT provider,url,verified FROM user_social_links WHERE user_id=$1 ORDER BY provider", [id]);
    const mutual = await db.query("SELECT g.id,g.name FROM guilds g JOIN guild_members a ON a.guild_id=g.id AND a.user_id=$1 JOIN guild_members b ON b.guild_id=g.id AND b.user_id=$2 WHERE g.kind='community' ORDER BY g.name LIMIT 50", [user.id, id]);
    const relationship = await db.query("SELECT status FROM user_relationships WHERE user_id=$1 AND target_id=$2", [user.id, id]);
    return { ...r.rows[0], social_links: links.rows, mutual_guilds: mutual.rows, relationship: relationship.rows[0]?.status ?? null };
  }));
  const settingsInput = z.object({
    status: z.enum(["online", "idle", "dnd", "invisible"]).optional(),
    custom_status: z.string().trim().max(128).optional(),
    accent_color: z.number().int().min(0).max(0xffffff).optional(),
  });
  app.patch("/api/v1/users/@me/settings", authed(async (request, reply, user) => {
    const data = settingsInput.safeParse(request.body);
    if (!data.success) return fail(reply, 400, "Invalid settings");
    const r = await db.query(
      "INSERT INTO user_profiles(user_id,status,custom_status,accent_color) VALUES($1,COALESCE($2,'online'),COALESCE($3,''),COALESCE($4,7331258)) ON CONFLICT(user_id) DO UPDATE SET status=COALESCE($2,user_profiles.status),custom_status=COALESCE($3,user_profiles.custom_status),accent_color=COALESCE($4,user_profiles.accent_color),updated_at=now() RETURNING status,custom_status,accent_color",
      [user.id, data.data.status ?? null, data.data.custom_status ?? null, data.data.accent_color ?? null]
    );
    await ctx.publishEphemeral({ kind: "presence", user: user.id });
    return r.rows[0];
  }));
  app.get("/api/v1/users/@me/settings", authed(async (_request, _reply, user) => {
    const r = await db.query("SELECT COALESCE(status,'online') AS status,COALESCE(custom_status,'') AS custom_status,COALESCE(accent_color,7331258) AS accent_color FROM user_profiles WHERE user_id=$1", [user.id]);
    return r.rows[0] ?? { status: "online", custom_status: "", accent_color: 7331258 };
  }));

  // ---------------------------------------------------------------- E2EE key distribution
  app.put("/api/v1/devices/:id/bundle", authed(async (request, reply, user) => {
    const { id } = params(request);
    if (!ids(id)) return fail(reply, 400, "Invalid device ID");
    const fp = bundleFingerprint((request.body as any)?.public_bundle);
    if (!fp) return fail(reply, 400, "Invalid public bundle");
    // The bundle must hash to the fingerprint registered at password-verified enrollment.
    const r = await db.query("UPDATE user_devices SET public_bundle=$4::jsonb WHERE id=$1 AND user_id=$2 AND identity_key=$3 AND revoked_at IS NULL AND public_bundle IS NULL RETURNING id", [id, user.id, fp, JSON.stringify((request.body as any).public_bundle)]);
    if (!r.rowCount) return fail(reply, 409, "Bundle does not match an active device without a bundle");
    return reply.code(204).send();
  }));
  // Ask online key holders to share the current room key (e.g. a newly enrolled device).
  // Carries identifiers only; holders still verify the requester's device before wrapping.
  app.post("/api/v1/channels/:id/keys/request", authed(async (request, reply, user) => {
    const { id } = params(request);
    if (!ids(id)) return fail(reply, 400, "Invalid channel ID");
    if (!(await channelAccess(db, id, user.id))) return fail(reply, 403, "Forbidden");
    if (!(await ctx.takeQuota("key-request:" + user.id, 60, 3600))) return fail(reply, 429, "Too many key requests");
    await ctx.publishEphemeral({ kind: "dispatch", channel: id, t: "KEY_REQUEST", d: { channel_id: id, user_id: user.id } });
    return reply.code(204).send();
  }));
  app.post("/api/v1/channels/:id/keys/claim", authed(async (request, reply, user) => {
    const { id } = params(request);
    const data = z.object({ epoch: z.number().int().positive(), device_id: z.string().uuid(), key_commitment: z.string().regex(/^[A-Za-z0-9_-]{43}$/) }).safeParse(request.body);
    if (!ids(id) || !data.success) return fail(reply, 400, "Invalid key claim");
    // First writer wins for an epoch; everyone else must obtain that key from a holder.
    const r = await db.query(
      "INSERT INTO channel_epoch_keys(channel_id,epoch,creator_device_id,key_commitment) SELECT c.id,$2,d.id,$4 FROM channels c JOIN guild_members gm ON gm.guild_id=c.guild_id AND gm.user_id=$5 JOIN user_devices d ON d.id=$3 AND d.user_id=$5 AND d.revoked_at IS NULL LEFT JOIN guild_key_epochs e ON e.guild_id=c.guild_id WHERE c.id=$1 AND COALESCE(e.epoch,1)=$2 ON CONFLICT(channel_id,epoch) DO NOTHING RETURNING creator_device_id,key_commitment",
      [id, data.data.epoch, data.data.device_id, data.data.key_commitment, user.id]
    );
    if (r.rowCount) return reply.code(201).send({ claimed: true, ...r.rows[0] });
    const existing = await db.query("SELECT creator_device_id,key_commitment FROM channel_epoch_keys WHERE channel_id=$1 AND epoch=$2", [id, data.data.epoch]);
    return reply.code(409).send({ claimed: false, message: "Epoch key already claimed or epoch is stale", ...(existing.rows[0] ?? {}) });
  }));
}
