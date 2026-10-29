import Fastify from "fastify";
import websocket from "@fastify/websocket";
import { Pool } from "pg";
import { newSecret, verifyTotp, encryptSecret, decryptSecret } from "./totp.js";
import { randomBytes, randomUUID, scrypt as scryptCallback, timingSafeEqual, createHash } from "node:crypto";
import { promisify } from "node:util";
import { z } from "zod";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const scrypt = promisify(scryptCallback);
const app = Fastify({
 logger:{redact:["req.headers.authorization","req.headers.cookie","req.body.password","req.body.token","res.headers.set-cookie"]},
 bodyLimit:1024*1024,
 // Only named proxy networks can supply X-Forwarded-For. Direct deployments trust none.
 trustProxy:process.env.TRUSTED_PROXY_CIDRS ? process.env.TRUSTED_PROXY_CIDRS.split(",").map(s=>s.trim()).filter(Boolean) : false
});
// Same-origin frontend: reject browser cross-site mutations and WebSocket handshakes.
// Non-browser CLI calls without Origin are allowed; enforce TLS and credential controls at the proxy.
app.addHook("onRequest",async(request,reply)=>{
 const origin=request.headers.origin;
 if(origin){
  let parsed:URL;
  try{parsed=new URL(origin)}catch{return reply.code(403).send({message:"Invalid Origin"})}
  const forwardedProto=request.headers["x-forwarded-proto"];
  // Reverse-proxy deployments must set PUBLIC_BASE_URL and overwrite forwarded headers.
  const expected=process.env.PUBLIC_BASE_URL
   ? new URL(process.env.PUBLIC_BASE_URL).origin
   : (request.protocol+"://"+request.headers.host);
  if(parsed.origin!==expected)return reply.code(403).send({message:"Cross-origin requests are disabled"});
 }
});
app.addHook("onSend",async(_request,reply,payload)=>{
 reply.header("X-Content-Type-Options","nosniff");
 reply.header("Referrer-Policy","no-referrer");
 reply.header("X-Frame-Options","DENY");
 reply.header("Permissions-Policy","camera=(), microphone=(), geolocation=()");
 reply.header("Content-Security-Policy","default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self' ws: wss:; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
 reply.header("Cache-Control","no-store");
 return payload;
});
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
// A bounded process-local KDF admission gate prevents unbounded scrypt jobs.
// The shared database quotas below apply across instances as well.
const MAX_ACTIVE_KDF=Number(process.env.MAX_ACTIVE_KDF||4);
let activeKdf=0;
async function passwordHash(password: string, salt: string) {
  if(activeKdf>=MAX_ACTIVE_KDF)throw Object.assign(new Error("Authentication temporarily busy"),{statusCode:503});
  activeKdf++;
  try{return (await scrypt(password, salt, 64) as Buffer).toString("hex")}
  finally{activeKdf--}
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
const botSockets = new Map<string,Set<any>>();
async function broadcastBotMetadata(channelId:string,messageId:string){
 const found=await db.query("SELECT guild_id FROM channels WHERE id=$1",[channelId]);
 if(!found.rowCount)return;
 const guildId=found.rows[0].guild_id as string;
 for(const socket of botSockets.get(guildId)??[]){
  if(socket.readyState!==1)continue;
  const appId=botSocketApplication.get(socket);
  const credentialHash=botSocketTokenHash.get(socket);
  if(!appId||!credentialHash)continue;
  const allowed=await db.query("SELECT 1 FROM guild_bots b JOIN developer_apps a ON a.id=b.app_id WHERE b.guild_id=$1 AND b.app_id=$2 AND b.can_read_events=true AND a.revoked_at IS NULL AND a.bot_token_hash=$3",[guildId,appId,credentialHash]);
  if(allowed.rowCount)socket.send(JSON.stringify({op:0,t:"MESSAGE_METADATA_CREATE",s:null,d:{guild_id:guildId,channel_id:channelId,message_id:messageId}}));
 }
}
const botSocketApplication=new WeakMap<any,string>();
const botSocketTokenHash=new WeakMap<any,string>();
const botConnections=new Map<string,Set<any>>();
function closeBotConnections(appId:string){
 const connections=botConnections.get(appId);
 if(!connections)return;
 for(const socket of [...connections])socket.close(4004,"Bot credential revoked");
 botConnections.delete(appId);
}
const socketIdentity = new WeakMap<any,string>();
const userConnections = new Map<string,Set<any>>();
const socketSessionHash = new WeakMap<any,string>();
function closeUserConnections(userId:string,sessionHash?:string){
 const active=userConnections.get(userId);
 if(!active)return;
 for(const socket of [...active]){
  if(sessionHash && socketSessionHash.get(socket)!==sessionHash)continue;
  socket.close(4004,"Session revoked");
  active.delete(socket);
 }
 if(!active.size)userConnections.delete(userId);
}
const socketSubscriptions = new WeakMap<any,Set<string>>();
function evictMemberSockets(userId:string,channelIds:string[]){
 for(const id of channelIds){
  const set=sockets.get(id);
  if(!set)continue;
  for(const socket of set){
   if(socketIdentity.get(socket)!==userId)continue;
   set.delete(socket);
   socketSubscriptions.get(socket)?.delete(id);
   if(socket.readyState===1)socket.send(JSON.stringify({op:0,t:"CHANNEL_ACCESS_REVOKED",s:null,d:{channel_id:id}}));
  }
  if(!set.size)sockets.delete(id);
 }
}
// PostgreSQL notification bus: every API instance must LISTEN to the same database.
const eventsClient=await db.connect();
async function publishSecurityEvent(payload:Record<string,string>){
 await db.query("WITH e AS (INSERT INTO security_events(payload) VALUES($1::jsonb) RETURNING payload) SELECT pg_notify('nexora_security',payload::text) FROM e",[JSON.stringify(payload)]);
}
async function processSecurityEvent(event:any){
 if(!event||typeof event!=="object")return;
 if(event.kind==="session"&&uuid.safeParse(event.user).success)closeUserConnections(event.user,event.hash);
 if(event.kind==="bot"&&uuid.safeParse(event.app).success)closeBotConnections(event.app);
 if(event.kind==="bot_uninstall"&&uuid.safeParse(event.app).success&&uuid.safeParse(event.guild).success){
  for(const socket of botSockets.get(event.guild)??[]){
   if(botSocketApplication.get(socket)!==event.app)continue;
   botSockets.get(event.guild)?.delete(socket);
   if(socket.readyState===1)socket.send(JSON.stringify({op:0,t:"GUILD_ACCESS_REVOKED",s:null,d:{guild_id:event.guild}}));
  }
  if(!botSockets.get(event.guild)?.size)botSockets.delete(event.guild);
 }
 if(event.kind==="member"&&uuid.safeParse(event.user).success&&uuid.safeParse(event.guild).success){
  const channels=await db.query("SELECT id FROM channels WHERE guild_id=$1",[event.guild]);
  evictMemberSockets(event.user,channels.rows.map((r:{id:string})=>r.id));
 }
 if(event.kind==="message_deleted"&&uuid.safeParse(event.message).success&&uuid.safeParse(event.channel).success){
  for(const socket of sockets.get(event.channel)??[]){
   const user=socketIdentity.get(socket),hash=socketSessionHash.get(socket);
   if(socket.readyState!==1||!user||!hash)continue;
   const allowed=await db.query("SELECT 1 FROM sessions s JOIN guild_members gm ON gm.user_id=s.user_id JOIN channels c ON c.guild_id=gm.guild_id WHERE s.token_hash=$1 AND s.user_id=$2 AND s.expires_at>now() AND c.id=$3",[hash,user,event.channel]);
   if(allowed.rowCount)socket.send(JSON.stringify({op:0,t:"MESSAGE_DELETE",s:null,d:{channel_id:event.channel,id:event.message}}));
   else socket.close(4004,"Authorization revoked");
  }
 }
 if(event.kind==="message"&&uuid.safeParse(event.message).success&&uuid.safeParse(event.channel).success){
  const found=await db.query("SELECT m.id,m.channel_id,m.author_id,m.ciphertext,m.algorithm,m.created_at FROM messages m WHERE m.id=$1 AND m.channel_id=$2",[event.message,event.channel]);
  if(!found.rowCount)return;
  const row=found.rows[0];
  // Revalidate session and guild membership for each recipient at delivery time.
  for(const socket of sockets.get(event.channel)??[]){
   const user=socketIdentity.get(socket),hash=socketSessionHash.get(socket);
   if(socket.readyState!==1||!user||!hash)continue;
   const allowed=await db.query("SELECT 1 FROM sessions s JOIN guild_members gm ON gm.user_id=s.user_id JOIN channels c ON c.guild_id=gm.guild_id WHERE s.token_hash=$1 AND s.user_id=$2 AND s.expires_at>now() AND c.id=$3",[hash,user,event.channel]);
   if(allowed.rowCount)socket.send(JSON.stringify({op:0,t:"MESSAGE_CREATE",s:null,d:row}));
   else{socket.close(4004,"Authorization revoked");}
  }
  await broadcastBotMetadata(event.channel,event.message);
 }
}
eventsClient.on("notification",msg=>{
 if(msg.channel!=="nexora_security"||!msg.payload)return;
 try{void processSecurityEvent(JSON.parse(msg.payload)).catch(error=>app.log.error(error))}
 catch(error){app.log.warn(error)}
});
eventsClient.on("error",error=>{app.log.error(error);process.exitCode=1;void app.close()});
await eventsClient.query("LISTEN nexora_security");
/*
 * A persisted best-effort catch-up path covers missed LISTEN notifications.
 * Cursors are per process because subscriptions are per process. The periodic
 * session/member watchdog remains the safety fallback after event gaps.
 */
let securityCursor=BigInt((await db.query("SELECT COALESCE(MAX(id),0)::text AS id FROM security_events")).rows[0].id);
let replaying=false;
const catchUpSecurityEvents=async()=>{
 if(replaying)return;
 replaying=true;
 try{
  for(let batch=0;batch<10;batch++){
   const found=await db.query("SELECT id::text AS id,payload FROM security_events WHERE id>$1 ORDER BY id LIMIT 200",[securityCursor.toString()]);
   if(!found.rows.length)break;
   for(const record of found.rows){
    await processSecurityEvent(record.payload);
    securityCursor=BigInt(record.id);
   }
  }
 }catch(error){app.log.error(error);await app.close()}
 finally{replaying=false}
};
const catchUpInterval=setInterval(()=>{void catchUpSecurityEvents()},5000);
app.addHook("onClose",async()=>clearInterval(catchUpInterval));


await app.register(websocket);
app.get("/health", async () => ({ status: "ok", service: "nexora" }));
const frontend = fileURLToPath(new URL("../../../web/index.html", import.meta.url));
const frontendJs = fileURLToPath(new URL("../../../web/app.js", import.meta.url));
app.get("/", async (_request, reply) => reply.type("text/html; charset=utf-8").send(await readFile(frontend)));
app.get("/app.js", async (_request, reply) => reply.header("Cache-Control", "no-store").type("application/javascript").send(await readFile(frontendJs)));
const cryptoJs=fileURLToPath(new URL("../../../web/crypto.mjs",import.meta.url));
const vaultJs=fileURLToPath(new URL("../../../web/private-key-vault.mjs",import.meta.url));
app.get("/crypto.mjs",async(_request,reply)=>reply.type("application/javascript").send(await readFile(cryptoJs)));
app.get("/private-key-vault.mjs",async(_request,reply)=>reply.type("application/javascript").send(await readFile(vaultJs)));
app.get("/api/v10/gateway", async (request) => {
  const host = request.headers.host ?? "localhost:3000";
  // Only use forwarded proto if an administrator has configured a trusted proxy.
  const scheme = process.env.PUBLIC_BASE_URL?.startsWith("https://") ? "wss" : "ws";
  const publicHost = process.env.PUBLIC_BASE_URL ? new URL(process.env.PUBLIC_BASE_URL).host : host;
  return { url: `${scheme}://${publicHost}/gateway` };
});
// PostgreSQL quota counters are shared by all API processes using the same database.
// Atomic upserts prevent concurrent requests bypassing the quota.
async function takeQuota(key:string,limit:number,windowSeconds:number){
 const hashed=hashToken(key);
 const result=await db.query(
  "INSERT INTO auth_rate_limits(key_hash,count,expires_at) VALUES ($1,1,now()+($2::int*interval '1 second')) ON CONFLICT(key_hash) DO UPDATE SET count=CASE WHEN auth_rate_limits.expires_at<=now() THEN 1 ELSE auth_rate_limits.count+1 END,expires_at=CASE WHEN auth_rate_limits.expires_at<=now() THEN now()+($2::int*interval '1 second') ELSE auth_rate_limits.expires_at END RETURNING count",
  [hashed,windowSeconds]
 );
 return Number(result.rows[0].count)<=limit;
}
app.post("/api/v1/auth/register", async (request, reply) => {
  const parsed = credentials.safeParse(request.body);
  if (!parsed.success) return reply.code(400).send({ error: "Invalid username or password" });
  if(!await takeQuota("registration:"+request.ip,5,3600))return reply.code(429).header("Retry-After","3600").send({error:"Too many registrations; try again later"});
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
const mfaEncryptionKey=process.env.MFA_ENCRYPTION_KEY && /^[a-f0-9]{64}$/i.test(process.env.MFA_ENCRYPTION_KEY)?Buffer.from(process.env.MFA_ENCRYPTION_KEY,"hex"):null;
app.post("/api/v1/auth/mfa/enroll",async(request,reply)=>{
 const user=await auth(request.headers.authorization);if(!user)return reply.code(401).send({message:"Unauthorized"});
 if(!mfaEncryptionKey)return reply.code(503).send({message:"MFA not configured"});
 const existing=await db.query("SELECT enabled FROM user_mfa WHERE user_id=$1",[user.id]);
 if(existing.rows[0]?.enabled)return reply.code(409).send({message:"Already enrolled"});
 // Enrolling a second factor requires fresh password proof, not merely a stolen bearer token.
 const input=z.object({password:z.string().min(12).max(256)}).safeParse(request.body);
 if(!input.success)return reply.code(400).send({message:"Password required for MFA enrollment"});
 if(!await takeQuota("mfa-enroll-proof:"+user.id,6,900))return reply.code(429).send({message:"Too many enrollment attempts"});
 const owner=await db.query("SELECT password_hash,password_salt FROM users WHERE id=$1",[user.id]);
 if(!owner.rowCount)return reply.code(401).send({message:"Unauthorized"});
 const expected=Buffer.from(owner.rows[0].password_hash,"hex");
 const proof=Buffer.from(await passwordHash(input.data.password,owner.rows[0].password_salt),"hex");
 if(expected.length!==proof.length||!timingSafeEqual(expected,proof))return reply.code(401).send({message:"Invalid password"});
 const secret=newSecret();
 await db.query("INSERT INTO user_mfa(user_id,secret_enc) VALUES($1,$2) ON CONFLICT(user_id) DO UPDATE SET secret_enc=EXCLUDED.secret_enc,enabled=false,last_step=-1",[user.id,encryptSecret(secret.raw,mfaEncryptionKey)]);
 return {secret:secret.base32,period:30,digits:6,algorithm:"SHA1"};
});
app.post("/api/v1/auth/mfa/confirm",async(request,reply)=>{
 const user=await auth(request.headers.authorization);if(!user)return reply.code(401).send({message:"Unauthorized"});
 const code=z.object({code:z.string().regex(/^[0-9]{6}$/)}).safeParse(request.body);
 if(!code.success)return reply.code(400).send({message:"Invalid code"});
 if(!mfaEncryptionKey)return reply.code(503).send({message:"MFA not configured"});
 if(!await takeQuota("mfa-confirm:"+user.id,10,900))return reply.code(429).send({message:"Too many attempts"});
 const row=await db.query("SELECT secret_enc FROM user_mfa WHERE user_id=$1 AND enabled=false",[user.id]);
 if(!row.rowCount)return reply.code(409).send({message:"Enrollment not pending"});
 const step=verifyTotp(decryptSecret(row.rows[0].secret_enc,mfaEncryptionKey),code.data.code);
 if(step===null)return reply.code(401).send({message:"Invalid code"});
 const client=await db.connect();
 try{
  await client.query("BEGIN");
  const enabled=await client.query("UPDATE user_mfa SET enabled=true,last_step=$2 WHERE user_id=$1 AND enabled=false RETURNING user_id",[user.id,step]);
  if(!enabled.rowCount){await client.query("ROLLBACK");return reply.code(409).send({message:"Already enrolled"})}
  const codes=Array.from({length:8},()=>randomBytes(16).toString("hex"));
  for(const code of codes)await client.query("INSERT INTO mfa_recovery_codes(user_id,code_hash) VALUES($1,$2)",[user.id,hashToken(code)]);
  await client.query("COMMIT");
  return {enabled:true,recovery_codes:codes,warning:"Store recovery codes offline. Each can be used only once."};
 }catch(error){await client.query("ROLLBACK");throw error}
 finally{client.release()}
});
app.post("/api/v1/auth/login", async (request, reply) => {
  const parsed = credentials.extend({mfa_code:z.string().regex(/^[0-9]{6}$/).optional(),recovery_code:z.string().regex(/^[a-f0-9]{32}$/).optional()}).safeParse(request.body);
  if (!parsed.success) return reply.code(401).send({ error: "Invalid credentials" });
  const { username, password } = parsed.data;
  // An IP-wide budget prevents switching usernames to evade pairwise throttles.
  if(!await takeQuota("login-ip:"+request.ip,60,900))
   return reply.code(429).header("Retry-After","900").send({error:"Too many login attempts; try again later"});
  // Account-wide quota prevents distributing guesses for one username across IPs.
  if(!await takeQuota("login-account:"+username.toLowerCase(),40,900))
   return reply.code(429).header("Retry-After","900").send({error:"Too many login attempts; try again later"});
  if(!await takeQuota("login:"+request.ip+":"+username.toLowerCase(),7,900))
   return reply.code(429).header("Retry-After","900").send({error:"Too many login attempts; try again later"});
  const r = await db.query("SELECT id,password_hash,password_salt FROM users WHERE username=$1", [username]);
  const record = r.rows[0];
  // Avoid a fast unknown-user path and never leak which usernames exist.
  const hash = await passwordHash(password, record?.password_salt ?? "00000000000000000000000000000000");
  const a = Buffer.from(hash,"hex"), b = Buffer.from(record?.password_hash ?? "00".repeat(64),"hex");
  if (!record || !timingSafeEqual(a,b)) return reply.code(401).send({ error: "Invalid credentials" });

  let recovered=false;
  const mfa=await db.query("SELECT secret_enc FROM user_mfa WHERE user_id=$1 AND enabled=true",[record.id]);
  if(mfa.rowCount){
   if(!mfaEncryptionKey)return reply.code(503).send({error:"MFA unavailable"});
   if(parsed.data.recovery_code){
    const used=await db.query("DELETE FROM mfa_recovery_codes WHERE user_id=$1 AND code_hash=$2 RETURNING user_id",[record.id,hashToken(parsed.data.recovery_code)]);
    if(!used.rowCount)return reply.code(401).send({error:"Invalid recovery code"});
    recovered=true;
   }else{
    const step=verifyTotp(decryptSecret(mfa.rows[0].secret_enc,mfaEncryptionKey),parsed.data.mfa_code??"");
    if(step===null)return reply.code(401).send({error:"MFA code required or invalid"});
    const consumed=await db.query("UPDATE user_mfa SET last_step=$2 WHERE user_id=$1 AND last_step<$2 RETURNING user_id",[record.id,step]);
    if(!consumed.rowCount)return reply.code(401).send({error:"MFA code already used"});
   }
  }
  const token = randomBytes(32).toString("hex");
  // Recovery is a high-risk action: invalidate other sessions before issuing a new token.
  // Triggers notify every connected API instance after commit.
  if(recovered){
   await db.query("DELETE FROM sessions WHERE user_id=$1",[record.id]);
   closeUserConnections(record.id);
  }
  await db.query("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES ($1,$2,now()+interval '7 days')", [hashToken(token),record.id]);
  return { token, token_type: "Bearer", expires_in: 604800 };
});
app.post("/api/v1/auth/logout", async (request, reply) => {
  const raw = /^Bearer ([a-f0-9]{64})$/.exec(request.headers.authorization ?? "");
  if (!raw) return reply.code(401).send({ message: "Unauthorized" });
  const sessionHash=hashToken(raw[1]);
  const owner=await db.query("DELETE FROM sessions WHERE token_hash=$1 RETURNING user_id",[sessionHash]);
  if(owner.rows[0]){closeUserConnections(owner.rows[0].user_id,sessionHash);await publishSecurityEvent({kind:"session",user:owner.rows[0].user_id,hash:sessionHash})}
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
 closeUserConnections(user.id);
 await publishSecurityEvent({kind:"session",user:user.id});
 return reply.code(204).send();
});


const deviceInput=z.object({name:z.string().trim().min(1).max(80),identity_key:z.string().regex(/^[A-Za-z0-9_-]{43}$/)});
app.post("/api/v1/devices",async(request,reply)=>{
 const user=await auth(request.headers.authorization);
 if(!user)return reply.code(401).send({message:"Unauthorized"});
 const data=deviceInput.safeParse(request.body);
 if(!data.success)return reply.code(400).send({message:"Invalid device public-key record"});
 // Proof of password is required for key enrollment, even with a stolen session.
 const password=z.object({password:z.string().min(12).max(256)}).safeParse(request.body);
 if(!password.success)return reply.code(400).send({message:"Password required to enroll device"});
 if(!await takeQuota("device-enroll:"+user.id,6,900))return reply.code(429).send({message:"Too many attempts"});
 const owner=await db.query("SELECT password_salt,password_hash FROM users WHERE id=$1",[user.id]);
 if(!owner.rowCount)return reply.code(401).send({message:"Unauthorized"});
 const proof=Buffer.from(await passwordHash(password.data.password,owner.rows[0].password_salt),"hex");
 const expected=Buffer.from(owner.rows[0].password_hash,"hex");
 if(proof.length!==expected.length||!timingSafeEqual(proof,expected))return reply.code(401).send({message:"Invalid password"});
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
 // Reveal another user's device keys only within a currently shared community.
 const shared=await db.query("SELECT 1 FROM guild_members gm JOIN guild_members peer ON peer.guild_id=gm.guild_id WHERE gm.user_id=$1 AND peer.user_id=$2 LIMIT 1",[user.id,id]);
 if(user.id!==id&&!shared.rowCount)return reply.code(403).send({message:"No shared community"});
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


const appInput=z.object({name:z.string().trim().min(2).max(80)});
app.post("/api/v1/developer/apps",async(request,reply)=>{
 const user=await auth(request.headers.authorization);
 if(!user)return reply.code(401).send({message:"Unauthorized"});
 const valid=appInput.safeParse(request.body);
 if(!valid.success)return reply.code(400).send({message:"Invalid app name"});
 const token=randomBytes(32).toString("hex"),id=randomUUID();
 await db.query("INSERT INTO developer_apps(id,owner_id,name,bot_token_hash) VALUES($1,$2,$3,$4)",[id,user.id,valid.data.name,hashToken(token)]);
 return reply.code(201).send({id,name:valid.data.name,bot_token:token,warning:"Save this token. It will not be displayed again."});
});

app.post("/api/v1/developer/apps/:id/rotate-token",async(request,reply)=>{
 const user=await auth(request.headers.authorization);
 if(!user)return reply.code(401).send({message:"Unauthorized"});
 const id=(request.params as {id:string}).id;
 if(!uuid.safeParse(id).success)return reply.code(400).send({message:"Invalid app ID"});
 const token=randomBytes(32).toString("hex");
 const rotated=await db.query("UPDATE developer_apps SET bot_token_hash=$1 WHERE id=$2 AND owner_id=$3 AND revoked_at IS NULL RETURNING id",[hashToken(token),id,user.id]);
 if(!rotated.rowCount)return reply.code(404).send({message:"Active developer application not found"});
 closeBotConnections(id);
 await publishSecurityEvent({kind:"bot",app:id});
 return {id,bot_token:token,warning:"Store this credential securely. The previous token is now invalid."};
});

app.get("/api/v1/developer/apps",async(request,reply)=>{
 const user=await auth(request.headers.authorization);
 if(!user)return reply.code(401).send({message:"Unauthorized"});
 const result=await db.query("SELECT id,name,created_at FROM developer_apps WHERE owner_id=$1 AND revoked_at IS NULL ORDER BY created_at",[user.id]);
 return result.rows;
});
app.delete("/api/v1/developer/apps/:id",async(request,reply)=>{
 const user=await auth(request.headers.authorization);
 if(!user)return reply.code(401).send({message:"Unauthorized"});
 const id=(request.params as {id:string}).id;
 if(!uuid.safeParse(id).success)return reply.code(400).send({message:"Invalid app ID"});
 const result=await db.query("UPDATE developer_apps SET revoked_at=now() WHERE id=$1 AND owner_id=$2 AND revoked_at IS NULL RETURNING id",[id,user.id]);
 if(!result.rowCount)return reply.code(404).send({message:"App not found"});
 closeBotConnections(id);
 await publishSecurityEvent({kind:"bot",app:id});
 return reply.code(204).send();
});
// Separate early bot identity endpoint; bot credentials cannot authenticate as humans.
app.get("/api/v1/bots/@me",async(request,reply)=>{
 const match=/^Bot ([a-f0-9]{64})$/.exec(request.headers.authorization ?? "");
 if(!match)return reply.code(401).send({message:"Invalid bot token"});
 const result=await db.query("SELECT id,name FROM developer_apps WHERE bot_token_hash=$1 AND revoked_at IS NULL",[hashToken(match[1])]);
 if(!result.rowCount)return reply.code(401).send({message:"Invalid bot token"});
 return {id:result.rows[0].id,username:result.rows[0].name,bot:true};
});


const botInstallInput=z.object({app_id:z.string().uuid(),can_read_events:z.boolean().default(false)});
app.post("/api/v1/guilds/:id/bots",async(request,reply)=>{
 const user=await auth(request.headers.authorization);
 if(!user)return reply.code(401).send({message:"Unauthorized"});
 const guildId=(request.params as {id:string}).id;
 if(!uuid.safeParse(guildId).success)return reply.code(400).send({message:"Invalid community ID"});
 const data=botInstallInput.safeParse(request.body);
 if(!data.success)return reply.code(400).send({message:"Invalid app ID or bot permissions"});
 const owner=await db.query("SELECT 1 FROM guilds WHERE id=$1 AND owner_id=$2",[guildId,user.id]);
 if(!owner.rowCount)return reply.code(403).send({message:"Only community owners may install bots"});
 const ownedApp=await db.query("SELECT 1 FROM developer_apps WHERE id=$1 AND owner_id=$2 AND revoked_at IS NULL",[data.data.app_id,user.id]);
 if(!ownedApp.rowCount)return reply.code(404).send({message:"Developer application not found or not owned by you"});
 await db.query("INSERT INTO guild_bots(guild_id,app_id,can_read_events,installed_by) VALUES($1,$2,$3,$4) ON CONFLICT (guild_id,app_id) DO UPDATE SET can_read_events=EXCLUDED.can_read_events",[guildId,data.data.app_id,data.data.can_read_events,user.id]);
 return reply.code(201).send({guild_id:guildId,app_id:data.data.app_id,can_read_events:data.data.can_read_events});
});
app.get("/api/v1/guilds/:id/bots",async(request,reply)=>{
 const user=await auth(request.headers.authorization);
 if(!user)return reply.code(401).send({message:"Unauthorized"});
 const guildId=(request.params as {id:string}).id;
 if(!uuid.safeParse(guildId).success)return reply.code(400).send({message:"Invalid community ID"});
 const member=await db.query("SELECT 1 FROM guild_members WHERE guild_id=$1 AND user_id=$2",[guildId,user.id]);
 if(!member.rowCount)return reply.code(403).send({message:"Not a member"});
 const found=await db.query("SELECT a.id,a.name,b.can_read_events FROM guild_bots b JOIN developer_apps a ON a.id=b.app_id WHERE b.guild_id=$1 AND a.revoked_at IS NULL ORDER BY a.name",[guildId]);
 return found.rows;
});
app.delete("/api/v1/guilds/:id/bots/:appId",async(request,reply)=>{
 const user=await auth(request.headers.authorization);
 if(!user)return reply.code(401).send({message:"Unauthorized"});
 const {id,appId}=request.params as {id:string,appId:string};
 if(!uuid.safeParse(id).success||!uuid.safeParse(appId).success)return reply.code(400).send({message:"Invalid ID"});
 const result=await db.query("DELETE FROM guild_bots USING guilds WHERE guild_bots.guild_id=$1 AND guild_bots.app_id=$2 AND guilds.id=guild_bots.guild_id AND guilds.owner_id=$3 RETURNING guild_bots.app_id",[id,appId,user.id]);
 if(!result.rowCount)return reply.code(404).send({message:"Bot installation not found or not permitted"});
 await publishSecurityEvent({kind:"bot_uninstall",app:appId,guild:id});
 return reply.code(204).send();
});


app.get("/api/v1/bots/@me/guilds",async(request,reply)=>{
 const match=/^Bot ([a-f0-9]{64})$/.exec(request.headers.authorization ?? "");
 if(!match)return reply.code(401).send({message:"Invalid bot token"});
 const result=await db.query(
  "SELECT g.id,g.name,b.can_read_events FROM developer_apps a JOIN guild_bots b ON b.app_id=a.id JOIN guilds g ON g.id=b.guild_id WHERE a.bot_token_hash=$1 AND a.revoked_at IS NULL ORDER BY g.name",
  [hashToken(match[1])]
 );
 return result.rows;
});
// Bot-facing event feed intentionally returns metadata only, never plaintext or encrypted message bodies.
app.get("/api/v1/bots/guilds/:id/channels",async(request,reply)=>{
 const match=/^Bot ([a-f0-9]{64})$/.exec(request.headers.authorization ?? "");
 if(!match)return reply.code(401).send({message:"Invalid bot token"});
 const guildId=(request.params as {id:string}).id;
 if(!uuid.safeParse(guildId).success)return reply.code(400).send({message:"Invalid community ID"});
 const allowed=await db.query(
  "SELECT 1 FROM developer_apps a JOIN guild_bots b ON b.app_id=a.id WHERE a.bot_token_hash=$1 AND a.revoked_at IS NULL AND b.guild_id=$2 AND b.can_read_events=true",
  [hashToken(match[1]),guildId]
 );
 if(!allowed.rowCount)return reply.code(403).send({message:"Bot lacks event permission"});
 const channels=await db.query("SELECT id,name,kind FROM channels WHERE guild_id=$1 ORDER BY created_at",[guildId]);
 return channels.rows;
});


app.get("/api/v1/bots/guilds/:id/events",async(request,reply)=>{
 const match=/^Bot ([a-f0-9]{64})$/.exec(request.headers.authorization ?? "");
 if(!match)return reply.code(401).send({message:"Invalid bot token"});
 const guildId=(request.params as {id:string}).id;
 const query=z.object({after:z.string().uuid().optional()}).safeParse(request.query);
 if(!uuid.safeParse(guildId).success||!query.success)return reply.code(400).send({message:"Invalid community or cursor"});
 const allowed=await db.query("SELECT 1 FROM developer_apps a JOIN guild_bots b ON b.app_id=a.id WHERE a.bot_token_hash=$1 AND a.revoked_at IS NULL AND b.guild_id=$2 AND b.can_read_events=true",[hashToken(match[1]),guildId]);
 if(!allowed.rowCount)return reply.code(403).send({message:"Bot lacks event permission"});
 if(query.data.after){
  const cursor=await db.query("SELECT 1 FROM messages m JOIN channels c ON c.id=m.channel_id WHERE m.id=$1 AND c.guild_id=$2",[query.data.after,guildId]);
  if(!cursor.rowCount)return reply.code(400).send({message:"Cursor does not belong to this community"});
 }
 // Compare timestamps in PostgreSQL; Node Date loses microseconds and can replay the cursor row.
 const result=await db.query(
  "SELECT m.id AS message_id,m.channel_id,c.guild_id,m.created_at FROM messages m JOIN channels c ON c.id=m.channel_id WHERE c.guild_id=$1 AND ($2::uuid IS NULL OR (m.created_at,m.id)>(SELECT previous.created_at,previous.id FROM messages previous WHERE previous.id=$2::uuid)) ORDER BY m.created_at ASC,m.id ASC LIMIT 100",
  [guildId,query.data.after??null]
 );
 return {events:result.rows,next_after:result.rows.at(-1)?.message_id??query.data.after??null};
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
  if(!await takeQuota("invite-ip:"+request.ip,30,3600) || !await takeQuota("invite-user:"+user.id,30,3600))
   return reply.code(429).header("Retry-After","3600").send({message:"Too many invite attempts"});
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


app.get("/api/v1/guilds/:id/members",async(request,reply)=>{
 const user=await auth(request.headers.authorization);
 if(!user)return reply.code(401).send({message:"Unauthorized"});
 const id=(request.params as {id:string}).id;
 if(!uuid.safeParse(id).success)return reply.code(400).send({message:"Invalid community ID"});
 const memberCheck=await db.query("SELECT 1 FROM guild_members WHERE guild_id=$1 AND user_id=$2",[id,user.id]);
 if(!memberCheck.rowCount)return reply.code(403).send({message:"Not a member"});
 const result=await db.query("SELECT u.id,u.username FROM users u JOIN guild_members gm ON gm.user_id=u.id WHERE gm.guild_id=$1 ORDER BY u.username LIMIT 500",[id]);
 return result.rows;
});
app.delete("/api/v1/guilds/:id/members/:userId",async(request,reply)=>{
 const user=await auth(request.headers.authorization);
 if(!user)return reply.code(401).send({message:"Unauthorized"});
 const {id,userId}=(request.params as {id:string,userId:string});
 if(!uuid.safeParse(id).success || !uuid.safeParse(userId).success)return reply.code(400).send({message:"Invalid ID"});
 const guild=await db.query("SELECT owner_id FROM guilds WHERE id=$1",[id]);
 if(!guild.rowCount)return reply.code(404).send({message:"Community not found"});
 if(userId===guild.rows[0].owner_id)return reply.code(403).send({message:"Owner cannot be removed"});
 if(user.id!==userId && user.id!==guild.rows[0].owner_id)return reply.code(403).send({message:"Only owners can remove other members"});
 const removed=await db.query("DELETE FROM guild_members gm USING guilds g WHERE gm.guild_id=$1 AND gm.user_id=$2 AND g.id=gm.guild_id AND g.owner_id<>gm.user_id AND ($3=gm.user_id OR $3=g.owner_id) RETURNING gm.user_id",[id,userId,user.id]);
 if(!removed.rowCount)return reply.code(404).send({message:"Membership not found or removal not permitted"});
 const channels=await db.query("SELECT id FROM channels WHERE guild_id=$1",[id]);
 evictMemberSockets(userId,channels.rows.map((row:{id:string})=>row.id));
 await publishSecurityEvent({kind:"member",user:userId,guild:id});
 return reply.code(204).send();
});

app.get("/api/v10/guilds/:id/channels", async (request, reply) => {
  const user = await auth(request.headers.authorization);
  const id = (request.params as any).id;
  if (!user) return reply.code(401).send({ message:"Unauthorized" });
  if (!uuid.safeParse(id).success) return reply.code(400).send({ message:"Invalid guild ID" });
  const allowed=await db.query("SELECT 1 FROM guild_members WHERE guild_id=$1 AND user_id=$2",[id,user.id]);
  if(!allowed.rowCount)return reply.code(403).send({message:"Forbidden"});
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
  // INSERT ... SELECT performs the membership check within the write statement,
  // avoiding the separate authorization-query/INSERT race on this route.
  const r=await db.query(
    "INSERT INTO messages(id,channel_id,author_id,ciphertext,algorithm) SELECT $1,c.id,$3,$4,$5 FROM channels c JOIN guild_members gm ON gm.guild_id=c.guild_id WHERE c.id=$2 AND gm.user_id=$3 RETURNING id,channel_id,author_id,ciphertext,algorithm,created_at",
    [messageId,id,user.id,parsed.data.ciphertext,parsed.data.algorithm]
  );
  if(!r.rowCount)return reply.code(403).send({message:"Forbidden"});
  await publishSecurityEvent({kind:"message",channel:id,message:r.rows[0].id});
  return reply.code(201).send(r.rows[0]);
});
// Author-only ciphertext deletion. SQL checks ownership and current membership atomically.
app.delete("/api/v10/channels/:id/messages/:messageId",async(request,reply)=>{
 const user=await auth(request.headers.authorization);
 if(!user)return reply.code(401).send({message:"Unauthorized"});
 const {id,messageId}=request.params as {id:string,messageId:string};
 if(!uuid.safeParse(id).success||!uuid.safeParse(messageId).success)return reply.code(400).send({message:"Invalid ID"});
 const client=await db.connect();
 try{
  await client.query("BEGIN");
  const result=await client.query(
   "DELETE FROM messages m USING channels c,guild_members gm WHERE m.id=$1 AND m.channel_id=$2 AND m.author_id=$3 AND c.id=m.channel_id AND gm.guild_id=c.guild_id AND gm.user_id=$3 RETURNING m.id",
   [messageId,id,user.id]
  );
  if(!result.rowCount){await client.query("ROLLBACK");return reply.code(404).send({message:"Message not found or deletion not permitted"})}
  await client.query("INSERT INTO message_tombstones(id,channel_id,deleted_by) VALUES($1,$2,$3)",[messageId,id,user.id]);
  await client.query("COMMIT");
 }catch(error){await client.query("ROLLBACK");throw error}
 finally{client.release()}
 await publishSecurityEvent({kind:"message_deleted",channel:id,message:messageId});
 return reply.code(204).send();
});
// Tombstones contain IDs only and allow authorized offline clients to resync.
app.get("/api/v10/channels/:id/deletions",async(request,reply)=>{
 const user=await auth(request.headers.authorization);
 if(!user)return reply.code(401).send({message:"Unauthorized"});
 const channel=(request.params as {id:string}).id;
 if(!uuid.safeParse(channel).success)return reply.code(400).send({message:"Invalid channel ID"});
 if(!await member(user.id,channel))return reply.code(403).send({message:"Forbidden"});
 const cursor=z.object({after:z.string().datetime({offset:true}).optional()}).safeParse(request.query);
 if(!cursor.success)return reply.code(400).send({message:"Invalid cursor"});
 const from=cursor.data.after??"1970-01-01T00:00:00.000Z";
 const rows=await db.query("SELECT id,channel_id,deleted_at FROM message_tombstones WHERE channel_id=$1 AND deleted_at>$2::timestamptz ORDER BY deleted_at,id LIMIT 100",[channel,from]);
 return {deletions:rows.rows};
});
// Initial native event gateway: NOT yet discord.js protocol compatible.

app.get("/bot-gateway",{websocket:true},socket=>{
 let appId:string|null=null;
 const subscriptions=new Set<string>();
 let lastHeartbeat=Date.now();
 let activeTokenHash:string|null=null,checkingCredential=false;
 let windowStart=Date.now(),windowMessages=0;
 const interval=process.env.NODE_ENV==="test"?1000:30000;
 const watchdog=setInterval(async()=>{
  if(Date.now()-lastHeartbeat>interval*2.5){socket.close(4009,"Heartbeat timeout");return}
  if(!appId||!activeTokenHash||checkingCredential||socket.readyState!==1)return;
  checkingCredential=true;
  try{
   const live=await db.query("SELECT 1 FROM developer_apps WHERE id=$1 AND bot_token_hash=$2 AND revoked_at IS NULL",[appId,activeTokenHash]);
   if(!live.rowCount){socket.close(4004,"Bot token revoked");return}
   for(const guildId of [...subscriptions]){
    const stillAllowed=await db.query("SELECT 1 FROM guild_bots b JOIN developer_apps a ON a.id=b.app_id WHERE b.guild_id=$1 AND b.app_id=$2 AND b.can_read_events=true AND a.revoked_at IS NULL AND a.bot_token_hash=$3",[guildId,appId,activeTokenHash]);
    if(!stillAllowed.rowCount){
     subscriptions.delete(guildId);botSockets.get(guildId)?.delete(socket);
     if(!botSockets.get(guildId)?.size)botSockets.delete(guildId);
     if(socket.readyState===1)socket.send(JSON.stringify({op:0,t:"GUILD_ACCESS_REVOKED",s:null,d:{guild_id:guildId}}));
    }
   }
  }catch(error){app.log.error(error);socket.close(1011,"Credential check failed")}
  finally{checkingCredential=false}
 },interval);
 socket.send(JSON.stringify({op:10,d:{heartbeat_interval:interval}}));
 socket.on("message",async(data:Buffer)=>{
  try{
   if(data.byteLength>8192){socket.close(4002,"Payload too large");return}
   const now=Date.now();
   if(now-windowStart>=10000){windowStart=now;windowMessages=0}
   if(++windowMessages>100){socket.close(4008,"Gateway rate limit exceeded");return}
   const packet=JSON.parse(data.toString());
   if(packet.op===1){lastHeartbeat=Date.now();socket.send(JSON.stringify({op:11,d:null}));return}
   if(packet.op===2){
    if(appId){socket.close(4005,"Already authenticated");return}
    const raw=String(packet.d?.token??"");
    if(!/^[a-f0-9]{64}$/.test(raw)){socket.close(4004,"Invalid bot token");return}
    const found=await db.query("SELECT id FROM developer_apps WHERE bot_token_hash=$1 AND revoked_at IS NULL",[hashToken(raw)]);
    if(!found.rowCount){socket.close(4004,"Invalid bot token");return}
    const authenticatedId:string=found.rows[0].id;appId=authenticatedId;activeTokenHash=hashToken(raw);botSocketApplication.set(socket,authenticatedId);botSocketTokenHash.set(socket,activeTokenHash);
    if(!botConnections.has(authenticatedId))botConnections.set(authenticatedId,new Set());
    botConnections.get(authenticatedId)!.add(socket);
    socket.send(JSON.stringify({op:0,t:"READY",s:null,d:{bot_id:appId}}));return
   }
   if(packet.op===42&&appId&&activeTokenHash){
    const guildId=packet.d?.guild_id;
    if(!uuid.safeParse(guildId).success)return;
    const allowed=await db.query("SELECT 1 FROM guild_bots b JOIN developer_apps a ON a.id=b.app_id WHERE b.guild_id=$1 AND b.app_id=$2 AND b.can_read_events=true AND a.revoked_at IS NULL AND a.bot_token_hash=$3",[guildId,appId,activeTokenHash]);
    if(!allowed.rowCount)return;
    if(!subscriptions.has(guildId)&&subscriptions.size>=25){socket.close(4008,"Subscription limit exceeded");return}
    if(!botSockets.has(guildId))botSockets.set(guildId,new Set());
    botSockets.get(guildId)!.add(socket);subscriptions.add(guildId);
    socket.send(JSON.stringify({op:0,t:"GUILD_SUBSCRIBED",s:null,d:{guild_id:guildId}}));return
   }
   if(packet.op===43&&appId){
    const guildId=packet.d?.guild_id;
    if(typeof guildId!=="string")return;
    subscriptions.delete(guildId);botSockets.get(guildId)?.delete(socket);
    if(!botSockets.get(guildId)?.size)botSockets.delete(guildId);
   }
  }catch{socket.close(4002,"Invalid bot Gateway payload")}
 });
 socket.on("close",()=>{
  clearInterval(watchdog);
  const activeApp=botSocketApplication.get(socket);
  if(activeApp){const connections=botConnections.get(activeApp);connections?.delete(socket);if(!connections?.size)botConnections.delete(activeApp)}
  for(const guildId of subscriptions){botSockets.get(guildId)?.delete(socket);if(!botSockets.get(guildId)?.size)botSockets.delete(guildId)}
 });
});

app.get("/gateway", { websocket:true }, (socket) => {
  let identity: Identity | null = null;
  const subscriptions = new Set<string>();
  socketSubscriptions.set(socket,subscriptions);
  let lastHeartbeat = Date.now();
  let sessionHash:string|null=null;
  let checkingSession=false;
  let windowStart = Date.now(), windowMessages = 0;
  const heartbeatMs = process.env.NODE_ENV === "test" ? 1000 : 30000;
  const watchdog = setInterval(async () => {
    if (Date.now() - lastHeartbeat > heartbeatMs * 2.5) {socket.close(4009,"Heartbeat timeout");return}
    if(!sessionHash||checkingSession||socket.readyState!==1)return;
    checkingSession=true;
    try{
      const live=await db.query("SELECT 1 FROM sessions WHERE token_hash=$1 AND expires_at>now()",[sessionHash]);
      if(!live.rowCount){socket.close(4004,"Session expired or revoked");return}
      if(identity){
       for(const channelId of [...subscriptions]){
        if(await member(identity.id,channelId))continue;
        subscriptions.delete(channelId);sockets.get(channelId)?.delete(socket);
        if(!sockets.get(channelId)?.size)sockets.delete(channelId);
        if(socket.readyState===1)socket.send(JSON.stringify({op:0,t:"CHANNEL_ACCESS_REVOKED",s:null,d:{channel_id:channelId}}));
       }
      }
    }catch(error){app.log.error(error);socket.close(1011,"Session check failed")}
    finally{checkingSession=false}
  }, heartbeatMs);
  socket.send(JSON.stringify({ op:10,d:{ heartbeat_interval:heartbeatMs } }));
  socket.on("message", async (data: Buffer) => {
    try {
      if (data.byteLength > 8192) { socket.close(4002,"Payload too large"); return; }
      const now = Date.now();
      if (now - windowStart >= 10000) { windowStart = now; windowMessages = 0; }
      if (++windowMessages > 100) { socket.close(4008,"Gateway rate limit exceeded"); return; }
      const payload=JSON.parse(data.toString());
      if (payload.op===1) { lastHeartbeat=Date.now(); socket.send(JSON.stringify({ op:11,d:null })); return; }
      if (payload.op===2) {
        if(identity) { socket.close(4005,"Already authenticated");return; }
        identity=await auth("Bearer "+String(payload.d?.token ?? ""));
        if(identity){
          socketIdentity.set(socket,identity.id);
          sessionHash=hashToken(String(payload.d?.token ?? ""));
          socketSessionHash.set(socket,sessionHash);
          if(!userConnections.has(identity.id))userConnections.set(identity.id,new Set());
          userConnections.get(identity.id)!.add(socket);
        }
        if (!identity) { socket.close(4004,"Authentication failed"); return; }
        socket.send(JSON.stringify({ op:0,t:"READY",s:null,d:{ user:identity } }));
      } else if (payload.op===42 && identity) {
        const channelId=payload.d?.channel_id;
        if (!uuid.safeParse(channelId).success || !await member(identity.id,channelId)) return;
        if (!subscriptions.has(channelId) && subscriptions.size >= 25) { socket.close(4008,"Subscription limit exceeded"); return; }
        if (!sockets.has(channelId)) sockets.set(channelId,new Set());
        sockets.get(channelId)!.add(socket);
        subscriptions.add(channelId);
        socket.send(JSON.stringify({op:0,t:"CHANNEL_SUBSCRIBED",s:null,d:{channel_id:channelId}}));
      } else if (payload.op===43 && identity) {
        const channelId=payload.d?.channel_id;
        if(typeof channelId!=="string")return;
        subscriptions.delete(channelId);
        sockets.get(channelId)?.delete(socket);
        if (!sockets.get(channelId)?.size) sockets.delete(channelId);
      }
    } catch { socket.close(4002,"Invalid gateway payload"); }
  });
  socket.on("close",()=>{
    clearInterval(watchdog);
    const userId=socketIdentity.get(socket);
    if(userId){const connections=userConnections.get(userId);connections?.delete(socket);if(!connections?.size)userConnections.delete(userId)}
    for (const id of subscriptions) {
      sockets.get(id)?.delete(socket);
      if (!sockets.get(id)?.size) sockets.delete(id);
    }
  });
});

try {
  await db.query("SELECT 1");
  await app.listen({ host: process.env.HOST || "127.0.0.1", port });
} catch (error) {
  app.log.error(error);
  await db.end();
  process.exit(1);
}
