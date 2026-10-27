import Fastify from "fastify";
import websocket from "@fastify/websocket";
import { Pool } from "pg";
import { randomBytes, randomUUID, scrypt as scryptCallback, timingSafeEqual, createHash } from "node:crypto";
import { promisify } from "node:util";
import { z } from "zod";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

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
const frontend = fileURLToPath(new URL("../../../web/index.html", import.meta.url));
const frontendJs = fileURLToPath(new URL("../../../web/app.js", import.meta.url));
app.get("/", async (_request, reply) => reply.type("text/html; charset=utf-8").send(await readFile(frontend)));
app.get("/app.js", async (_request, reply) => reply.header("Cache-Control", "no-store").type("application/javascript").send(await readFile(frontendJs)));
app.get("/api/v10/gateway", async (request) => {
  const host = request.headers.host ?? "localhost:3000";
  // Only use forwarded proto if an administrator has configured a trusted proxy.
  const scheme = process.env.PUBLIC_BASE_URL?.startsWith("https://") ? "wss" : "ws";
  const publicHost = process.env.PUBLIC_BASE_URL ? new URL(process.env.PUBLIC_BASE_URL).host : host;
  return { url: `${scheme}://${publicHost}/gateway` };
});
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
app.post("/api/v1/auth/logout", async (request, reply) => {
  const raw = /^Bearer ([a-f0-9]{64})$/.exec(request.headers.authorization ?? "");
  if (!raw) return reply.code(401).send({ message: "Unauthorized" });
  await db.query("DELETE FROM sessions WHERE token_hash=$1", [hashToken(raw[1])]);
  return reply.code(204).send();
});

app.get("/api/v1/auth/sessions",async(request,reply)=>{
 const user=await auth(request.headers.authorization);
 if(!user)return reply.code(401).send({message:"Unauthorized"});
 const rows=await db.query("SELECT left(token_hash,12) AS id,expires_at FROM sessions WHERE user_id=$1 AND expires_at>now() ORDER BY expires_at DESC",[user.id]);
 return rows.rows;
});
app.post("/api/v1/auth/logout-all",async(request,reply)=>{
 const user=await auth(request.headers.authorization);
 if(!user)return reply.code(401).send({message:"Unauthorized"});
 await db.query("DELETE FROM sessions WHERE user_id=$1",[user.id]);
 return reply.code(204).send();
});


const deviceInput=z.object({name:z.string().trim().min(1).max(80),identity_key:z.string().regex(/^[A-Za-z0-9_-]{43}$/)});
app.post("/api/v1/devices",async(request,reply)=>{
 const user=await auth(request.headers.authorization);
 if(!user)return reply.code(401).send({message:"Unauthorized"});
 const data=deviceInput.safeParse(request.body);
 if(!data.success)return reply.code(400).send({message:"Invalid device public-key record"});
 const id=randomUUID();
 try {
  const result=await db.query("INSERT INTO user_devices(id,user_id,name,identity_key) VALUES($1,$2,$3,$4) RETURNING id,name,identity_key,created_at",[id,user.id,data.data.name,data.data.identity_key]);
  return reply.code(201).send(result.rows[0]);
 }catch(e:any){if(e.code==="23505")return reply.code(409).send({message:"Key already registered"});throw e}
});
app.get("/api/v1/devices",async(request,reply)=>{
 const user=await auth(request.headers.authorization);
 if(!user)return reply.code(401).send({message:"Unauthorized"});
 const result=await db.query("SELECT id,name,identity_key,created_at FROM user_devices WHERE user_id=$1 AND revoked_at IS NULL ORDER BY created_at",[user.id]);
 return result.rows;
});
app.get("/api/v1/users/:id/devices",async(request,reply)=>{
 const user=await auth(request.headers.authorization);
 if(!user)return reply.code(401).send({message:"Unauthorized"});
 const id=(request.params as {id:string}).id;
 if(!uuid.safeParse(id).success)return reply.code(400).send({message:"Invalid user ID"});
 // Public keys are intended for client-side verification, never a server attestation of trust.
 const result=await db.query("SELECT id,identity_key,created_at FROM user_devices WHERE user_id=$1 AND revoked_at IS NULL ORDER BY created_at",[id]);
 return result.rows;
});
app.delete("/api/v1/devices/:id",async(request,reply)=>{
 const user=await auth(request.headers.authorization);
 if(!user)return reply.code(401).send({message:"Unauthorized"});
 const id=(request.params as {id:string}).id;
 if(!uuid.safeParse(id).success)return reply.code(400).send({message:"Invalid device ID"});
 const result=await db.query("UPDATE user_devices SET revoked_at=now() WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL RETURNING id",[id,user.id]);
 if(!result.rowCount)return reply.code(404).send({message:"Device not found"});
 return reply.code(204).send();
});

app.get("/api/v10/users/@me", async (request, reply) => {
  const user = await auth(request.headers.authorization);
  return user ?? reply.code(401).send({ message: "401: Unauthorized", code: 0 });
});

const profileInput=z.object({ display_name:z.string().trim().max(50),bio:z.string().trim().max(500) });
const socialInput=z.object({provider:z.enum(["twitch","youtube","github","steam"]),url:z.string().url().max(400)});
const socialDomains: Record<string,string[]> = {
  twitch:["twitch.tv","www.twitch.tv"],
  youtube:["youtube.com","www.youtube.com","youtu.be"],
  github:["github.com","www.github.com"],
  steam:["steamcommunity.com","www.steamcommunity.com"]
};
app.get("/api/v1/profiles/@me", async(request,reply)=>{
  const user=await auth(request.headers.authorization);
  if(!user) return reply.code(401).send({message:"Unauthorized"});
  const profile=await db.query("SELECT display_name,bio FROM user_profiles WHERE user_id=$1",[user.id]);
  const links=await db.query("SELECT provider,url,verified FROM user_social_links WHERE user_id=$1 ORDER BY provider",[user.id]);
  return {user,display_name:profile.rows[0]?.display_name ?? "",bio:profile.rows[0]?.bio ?? "",social_links:links.rows};
});
app.put("/api/v1/profiles/@me", async(request,reply)=>{
  const user=await auth(request.headers.authorization);
  if(!user) return reply.code(401).send({message:"Unauthorized"});
  const data=profileInput.safeParse(request.body);
  if(!data.success) return reply.code(400).send({message:"Invalid profile"});
  await db.query("INSERT INTO user_profiles(user_id,display_name,bio) VALUES($1,$2,$3) ON CONFLICT(user_id) DO UPDATE SET display_name=EXCLUDED.display_name,bio=EXCLUDED.bio,updated_at=now()",[user.id,data.data.display_name,data.data.bio]);
  return {updated:true};
});
app.put("/api/v1/profiles/@me/links", async(request,reply)=>{
  const user=await auth(request.headers.authorization);
  if(!user) return reply.code(401).send({message:"Unauthorized"});
  const data=socialInput.safeParse(request.body);
  if(!data.success) return reply.code(400).send({message:"Invalid social link"});
  const url=new URL(data.data.url);
  if(url.protocol!=="https:" || url.username || url.password || url.port || !socialDomains[data.data.provider].includes(url.hostname.toLowerCase())) {
    return reply.code(400).send({message:"Provider URL must use its official HTTPS domain"});
  }
  await db.query("INSERT INTO user_social_links(user_id,provider,url,verified) VALUES($1,$2,$3,false) ON CONFLICT(user_id,provider) DO UPDATE SET url=EXCLUDED.url,verified=false",[user.id,data.data.provider,url.toString()]);
  return {provider:data.data.provider,url:url.toString(),verified:false};
});
app.delete("/api/v1/profiles/@me/links/:provider", async(request,reply)=>{
  const user=await auth(request.headers.authorization);
  if(!user) return reply.code(401).send({message:"Unauthorized"});
  const provider=(request.params as {provider:string}).provider;
  if(!Object.hasOwn(socialDomains,provider)) return reply.code(400).send({message:"Invalid provider"});
  await db.query("DELETE FROM user_social_links WHERE user_id=$1 AND provider=$2",[user.id,provider]);
  return reply.code(204).send();
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

const inviteOptions=z.object({ max_uses:z.number().int().min(1).max(100).default(10), expires_hours:z.number().int().min(1).max(168).default(24) });
app.post("/api/v1/guilds/:id/invites",async(request,reply)=>{
  const user=await auth(request.headers.authorization);
  if(!user) return reply.code(401).send({message:"Unauthorized"});
  const id=(request.params as {id:string}).id;
  if(!uuid.safeParse(id).success) return reply.code(400).send({message:"Invalid guild"});
  const options=inviteOptions.safeParse(request.body ?? {});
  if(!options.success) return reply.code(400).send({message:"Invalid invite options"});
  // Owner-only during this milestone; future permission roles must be checked here.
  const owner=await db.query("SELECT 1 FROM guilds WHERE id=$1 AND owner_id=$2",[id,user.id]);
  if(!owner.rowCount) return reply.code(403).send({message:"Only the community owner may invite"});
  const code=randomBytes(24).toString("base64url");
  const expires=new Date(Date.now()+options.data.expires_hours*3600000);
  await db.query("INSERT INTO guild_invites(code_hash,guild_id,created_by,expires_at,max_uses) VALUES($1,$2,$3,$4,$5)",
   [hashToken(code),id,user.id,expires,options.data.max_uses]);
  return reply.code(201).send({code,expires_at:expires.toISOString(),max_uses:options.data.max_uses});
});
app.post("/api/v1/invites/:code/join",async(request,reply)=>{
  const user=await auth(request.headers.authorization);
  if(!user) return reply.code(401).send({message:"Unauthorized"});
  const code=(request.params as {code:string}).code;
  if(!/^[A-Za-z0-9_-]{32}$/.test(code)) return reply.code(404).send({message:"Invite not found"});
  const client=await db.connect();
  try {
    await client.query("BEGIN");
    // Lock and consume atomically so simultaneous requests cannot exceed max_uses.
    const result=await client.query("SELECT guild_id,uses,max_uses FROM guild_invites WHERE code_hash=$1 AND expires_at>now() AND uses<max_uses FOR UPDATE",[hashToken(code)]);
    const invite=result.rows[0];
    if(!invite){await client.query("ROLLBACK");return reply.code(404).send({message:"Invite expired or unavailable"})}
    const joined=await client.query("INSERT INTO guild_members(guild_id,user_id) VALUES($1,$2) ON CONFLICT DO NOTHING RETURNING user_id",[invite.guild_id,user.id]);
    if(joined.rowCount) await client.query("UPDATE guild_invites SET uses=uses+1 WHERE code_hash=$1",[hashToken(code)]);
    await client.query("COMMIT");
    return {guild_id:invite.guild_id,already_member:!joined.rowCount};
  } catch(e){await client.query("ROLLBACK");throw e}
  finally{client.release()}
});

app.get("/api/v10/users/@me/guilds", async (request, reply) => {
  const user = await auth(request.headers.authorization);
  if (!user) return reply.code(401).send({ message:"Unauthorized" });
  const r=await db.query("SELECT g.id,g.name,g.owner_id FROM guilds g JOIN guild_members gm ON gm.guild_id=g.id WHERE gm.user_id=$1",[user.id]);
  return r.rows;
});

const channelInput=z.object({name:z.string().trim().min(1).max(80).regex(/^[a-z0-9_-]+$/)});
app.post("/api/v1/guilds/:id/channels", async(request,reply)=>{
 const user=await auth(request.headers.authorization);
 if(!user)return reply.code(401).send({message:"Unauthorized"});
 const id=(request.params as {id:string}).id;
 if(!uuid.safeParse(id).success)return reply.code(400).send({message:"Invalid community ID"});
 const data=channelInput.safeParse(request.body);
 if(!data.success)return reply.code(400).send({message:"Channel names must be 1–80 lowercase letters, digits, - or _"});
 const owner=await db.query("SELECT 1 FROM guilds WHERE id=$1 AND owner_id=$2",[id,user.id]);
 if(!owner.rowCount)return reply.code(403).send({message:"Only community owners can create channels"});
 const channelId=randomUUID();
 const result=await db.query("INSERT INTO channels(id,guild_id,name) VALUES ($1,$2,$3) RETURNING id,guild_id,name,kind",[channelId,id,data.data.name]);
 return reply.code(201).send(result.rows[0]);
});
app.patch("/api/v1/channels/:id", async(request,reply)=>{
 const user=await auth(request.headers.authorization);
 if(!user)return reply.code(401).send({message:"Unauthorized"});
 const id=(request.params as {id:string}).id;
 if(!uuid.safeParse(id).success)return reply.code(400).send({message:"Invalid channel ID"});
 const data=channelInput.safeParse(request.body);
 if(!data.success)return reply.code(400).send({message:"Invalid channel name"});
 const result=await db.query("UPDATE channels c SET name=$1 FROM guilds g WHERE c.id=$2 AND g.id=c.guild_id AND g.owner_id=$3 RETURNING c.id,c.guild_id,c.name,c.kind",[data.data.name,id,user.id]);
 if(!result.rowCount)return reply.code(403).send({message:"Only community owners can rename channels"});
 return result.rows[0];
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
