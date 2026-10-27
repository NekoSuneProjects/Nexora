import Fastify from "fastify";
import websocket from "@fastify/websocket";
import { Pool } from "pg";
import { randomBytes, randomUUID, scrypt as scryptCallback, timingSafeEqual, createHash } from "node:crypto";
import { promisify } from "node:util";
import { z } from "zod";

const scrypt = promisify(scryptCallback);
const app = Fastify({ logger: true, bodyLimit: 1024 * 1024 });
const db = new Pool({ connectionString: process.env.DATABASE_URL });
const port = Number(process.env.PORT || 3000);
const hashToken = (token: string) => createHash("sha256").update(token).digest("hex");
const credentials = z.object({ username: z.string().min(3).max(32).regex(/^[a-zA-Z0-9_]+$/), password: z.string().min(12).max(256) });
const safeName = z.object({ name: z.string().trim().min(1).max(100) });
const encryptedEnvelope = z.object({
  ciphertext: z.string().min(1).max(800000),
  algorithm: z.literal("client-encrypted-v1")
});
const uuid = z.string().uuid();
type Identity = { id: string; username: string };
async function passwordHash(password: string, salt: string) {
  return (await scrypt(password, salt, 64) as Buffer).toString("hex");
}
async function auth(header?: string): Promise<Identity | null> {
  const match = /^Bearer ([a-f0-9]{64})$/.exec(header ?? "");
  if (!match) return null;
  const r = await db.query<Identity>(
    "SELECT u.id,u.username FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>now()",
    [hashToken(match[1])]
  );
  return r.rows[0] ?? null;
}
async function member(userId: string, channelId: string) {
  const r = await db.query("SELECT 1 FROM guild_members gm JOIN channels c ON c.guild_id=gm.guild_id WHERE gm.user_id=$1 AND c.id=$2", [userId,channelId]);
  return r.rowCount !== null && r.rowCount > 0;
}
const sockets = new Map<string, Set<any>>();
function broadcast(channelId: string, payload: unknown) {
  for (const socket of sockets.get(channelId) ?? []) {
    if (socket.readyState === 1) socket.send(JSON.stringify(payload));
  }
}
await app.register(websocket);
app.get("/health", async () => ({ status: "ok", service: "nexora" }));
app.get("/api/v10/gateway", async (request) => ({ url: `ws://${request.headers.host ?? "localhost:3000"}/gateway` }));
app.post("/api/v1/auth/register", async (request, reply) => {
  const parsed = credentials.safeParse(request.body);
  if (!parsed.success) return reply.code(400).send({ error: "Invalid username or password" });
  const { username, password } = parsed.data;
  const salt = randomBytes(16).toString("hex");
  const hashed = await passwordHash(password, salt);
  try {
    const id = randomUUID();
    await db.query("INSERT INTO users (id,username,password_salt,password_hash) VALUES ($1,$2,$3,$4)", [id,username,salt,hashed]);
    return reply.code(201).send({ id, username });
  } catch (e: any) {
    if (e.code === "23505") return reply.code(409).send({ error: "Username unavailable" });
    throw e;
  }
});
app.post("/api/v1/auth/login", async (request, reply) => {
  const parsed = credentials.safeParse(request.body);
  if (!parsed.success) return reply.code(401).send({ error: "Invalid credentials" });
  const { username, password } = parsed.data;
  const r = await db.query("SELECT id,password_hash,password_salt FROM users WHERE username=$1", [username]);
  const record = r.rows[0];
  // Avoid a fast unknown-user path and never leak which usernames exist.
  const hash = await passwordHash(password, record?.password_salt ?? "00000000000000000000000000000000");
  const a = Buffer.from(hash,"hex"), b = Buffer.from(record?.password_hash ?? "00".repeat(64),"hex");
  if (!record || !timingSafeEqual(a,b)) return reply.code(401).send({ error: "Invalid credentials" });
  const token = randomBytes(32).toString("hex");
  await db.query("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES ($1,$2,now()+interval '7 days')", [hashToken(token),record.id]);
  return { token, token_type: "Bearer", expires_in: 604800 };
});
app.get("/api/v10/users/@me", async (request, reply) => {
  const user = await auth(request.headers.authorization);
  return user ?? reply.code(401).send({ message: "401: Unauthorized", code: 0 });
});
app.post("/api/v10/guilds", async (request, reply) => {
  const user = await auth(request.headers.authorization);
  if (!user) return reply.code(401).send({ message: "Unauthorized" });
  const data = safeName.safeParse(request.body);
  if (!data.success) return reply.code(400).send({ message: "Invalid name" });
  const client = await db.connect();
  try {
    await client.query("BEGIN");
    const id = randomUUID(), channelId = randomUUID();
    await client.query("INSERT INTO guilds(id,name,owner_id) VALUES ($1,$2,$3)",[id,data.data.name,user.id]);
    await client.query("INSERT INTO guild_members(guild_id,user_id) VALUES ($1,$2)",[id,user.id]);
    await client.query("INSERT INTO channels(id,guild_id,name) VALUES ($1,$2,'general')",[channelId,id]);
    await client.query("COMMIT");
    return reply.code(201).send({ id, name: data.data.name, owner_id: user.id, channels: [{ id: channelId, name:"general" }] });
  } catch (err) { await client.query("ROLLBACK"); throw err; }
  finally { client.release(); }
});
app.get("/api/v10/users/@me/guilds", async (request, reply) => {
  const user = await auth(request.headers.authorization);
  if (!user) return reply.code(401).send({ message:"Unauthorized" });
  const r=await db.query("SELECT g.id,g.name,g.owner_id FROM guilds g JOIN guild_members gm ON gm.guild_id=g.id WHERE gm.user_id=$1",[user.id]);
  return r.rows;
});
app.get("/api/v10/guilds/:id/channels", async (request, reply) => {
  const user = await auth(request.headers.authorization);
  const id = (request.params as any).id;
  if (!user) return reply.code(401).send({ message:"Unauthorized" });
  if (!uuid.safeParse(id).success) return reply.code(400).send({ message:"Invalid guild ID" });
  const r=await db.query("SELECT c.id,c.name,c.kind FROM channels c JOIN guild_members gm ON gm.guild_id=c.guild_id WHERE gm.user_id=$1 AND c.guild_id=$2",[user.id,id]);
  return r.rows;
});
app.get("/api/v10/channels/:id/messages", async (request, reply) => {
  const user = await auth(request.headers.authorization);
  const id = (request.params as any).id;
  if (!user) return reply.code(401).send({ message:"Unauthorized" });
  if (!uuid.safeParse(id).success) return reply.code(400).send({ message:"Invalid channel ID" });
  if (!await member(user.id,id)) return reply.code(403).send({ message:"Forbidden" });
  const r=await db.query("SELECT id,channel_id,author_id,ciphertext,algorithm,created_at FROM messages WHERE channel_id=$1 ORDER BY created_at DESC,id DESC LIMIT 50",[id]);
  return r.rows.reverse();
});
app.post("/api/v10/channels/:id/messages", async (request, reply) => {
  const user = await auth(request.headers.authorization);
  const id = (request.params as any).id;
  if (!user) return reply.code(401).send({ message:"Unauthorized" });
  if (!uuid.safeParse(id).success) return reply.code(400).send({ message:"Invalid channel ID" });
  if (!await member(user.id,id)) return reply.code(403).send({ message:"Forbidden" });
  const parsed=encryptedEnvelope.safeParse(request.body);
  if (!parsed.success) return reply.code(400).send({ message:"Only opaque ciphertext envelopes are accepted" });
  const messageId=randomUUID();
  const r=await db.query("INSERT INTO messages(id,channel_id,author_id,ciphertext,algorithm) VALUES ($1,$2,$3,$4,$5) RETURNING id,channel_id,author_id,ciphertext,algorithm,created_at",
    [messageId,id,user.id,parsed.data.ciphertext,parsed.data.algorithm]);
  broadcast(id,{ op:0,t:"MESSAGE_CREATE",s:null,d:r.rows[0] });
  return reply.code(201).send(r.rows[0]);
});
// Initial native event gateway: NOT yet discord.js protocol compatible.
app.get("/gateway", { websocket:true }, (socket) => {
  let identity: Identity | null = null, subscriptions = new Set<string>();
  socket.send(JSON.stringify({ op:10,d:{ heartbeat_interval:30000 } }));
  socket.on("message", async (data: Buffer) => {
    try {
      const payload=JSON.parse(data.toString());
      if (payload.op===1) { socket.send(JSON.stringify({ op:11,d:null })); return; }
      if (payload.op===2) {
        identity=await auth("Bearer "+String(payload.d?.token ?? ""));
        if (!identity) { socket.close(4004,"Authentication failed"); return; }
        socket.send(JSON.stringify({ op:0,t:"READY",s:null,d:{ user:identity } }));
      } else if (payload.op===42 && identity) {
        const channelId=payload.d?.channel_id;
        if (!uuid.safeParse(channelId).success || !await member(identity.id,channelId)) return;
        if (!sockets.has(channelId)) sockets.set(channelId,new Set());
        sockets.get(channelId)!.add(socket);
        subscriptions.add(channelId);
      }
    } catch { socket.close(4002,"Invalid gateway payload"); }
  });
  socket.on("close",()=>{ for (const id of subscriptions) { sockets.get(id)?.delete(socket); if (!sockets.get(id)?.size) sockets.delete(id); } });
});
try {
  await db.query("SELECT 1");
  await app.listen({ host: process.env.HOST || "127.0.0.1", port });
} catch (error) {
  app.log.error(error);
  await db.end();
  process.exit(1);
}
