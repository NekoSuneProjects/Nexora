import Fastify from "fastify";
import websocket from "@fastify/websocket";
import { Pool } from "pg";
import { newSecret, verifyTotp, encryptSecret, decryptSecret } from "./totp.js";
import { randomBytes, randomUUID, scrypt as scryptCallback, timingSafeEqual, createHash } from "node:crypto";
import { promisify } from "node:util";
import { z } from "zod";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { registerCommunity, guildAccess, channelAccess, bundleFingerprint, PRESENCE_SQL } from "./community.js";
import { Permissions, DEFAULT_PERMISSIONS, has } from "./permissions.js";
import { registerSecurity } from "./security.js";

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
 reply.header("Content-Security-Policy","default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self' ws: wss:; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
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
    "SELECT u.id,u.username FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>now() AND u.suspended_at IS NULL",
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
async function publishSecurityEvent(payload:Record<string,unknown>){
 // The persisted row ID travels with the notification so the catch-up loop does not redeliver it.
 await db.query("WITH e AS (INSERT INTO security_events(payload) VALUES($1::jsonb) RETURNING id,payload) SELECT pg_notify('nexora_security',(payload||jsonb_build_object('_id',id::text))::text) FROM e",[JSON.stringify(payload)]);
}
// Ephemeral events (typing, presence) are NOT persisted: losing one is harmless.
async function publishEphemeral(payload:Record<string,unknown>){
 const text=JSON.stringify(payload);
 if(text.length>7000)throw Error("Ephemeral event too large");
 await db.query("SELECT pg_notify('nexora_security',$1)",[text]);
}
const deliveredEvents=new Set<string>();
function rememberDelivered(id:string){deliveredEvents.add(id);if(deliveredEvents.size>5000){const first=deliveredEvents.values().next().value;if(first!==undefined)deliveredEvents.delete(first)}}
function sendToUser(userId:string,packet:string){
 for(const socket of userConnections.get(userId)??[])if(socket.readyState===1)socket.send(packet);
}
const userTyping=new Map<string,number>();
async function processDispatch(event:any){
 if(typeof event.t!=="string"||!/^[A-Z_]{3,40}$/.test(event.t))return;
 const packet=JSON.stringify({op:0,t:event.t,s:null,d:event.d&&typeof event.d==="object"?event.d:{}});
 if(uuid.safeParse(event.channel).success){
  // Channel-scoped metadata (reactions, pins) is delivered only to live, authorized subscribers.
  for(const socket of sockets.get(event.channel)??[]){
   const user=socketIdentity.get(socket);
   if(socket.readyState!==1||!user)continue;
   if(await member(user,event.channel))socket.send(packet);
  }
  return;
 }
 let targets:string[]=[];
 if(uuid.safeParse(event.guild).success)targets=(await db.query("SELECT user_id FROM guild_members WHERE guild_id=$1",[event.guild])).rows.map((r:{user_id:string})=>r.user_id);
 else if(Array.isArray(event.users))targets=event.users.filter((u:unknown)=>uuid.safeParse(u).success);
 for(const user of targets)sendToUser(user,packet);
}
async function presenceAudience(userId:string){
 const r=await db.query("SELECT DISTINCT peer.user_id FROM guild_members gm JOIN guild_members peer ON peer.guild_id=gm.guild_id WHERE gm.user_id=$1 UNION SELECT target_id FROM user_relationships WHERE user_id=$1 AND status='friend'",[userId]);
 return r.rows.map((x:{user_id:string})=>x.user_id);
}
async function processSecurityEvent(event:any){
 if(!event||typeof event!=="object")return;
 if(event.kind==="dispatch"){await processDispatch(event);return}
 if(event.kind==="typing"&&uuid.safeParse(event.channel).success&&uuid.safeParse(event.user).success){
  const packet=JSON.stringify({op:0,t:"TYPING_START",s:null,d:{channel_id:event.channel,user_id:event.user,username:String(event.username??"").slice(0,32)}});
  for(const socket of sockets.get(event.channel)??[])if(socket.readyState===1&&socketIdentity.get(socket)!==event.user)socket.send(packet);
  return;
 }
 if(event.kind==="presence"&&uuid.safeParse(event.user).success){
  const r=await db.query(`SELECT ${PRESENCE_SQL} AS presence,COALESCE(up.custom_status,'') AS custom_status FROM users u LEFT JOIN user_profiles up ON up.user_id=u.id LEFT JOIN user_presence pr ON pr.user_id=u.id WHERE u.id=$1`,[event.user]);
  if(!r.rowCount)return;
  const status=event.offline===true&&!userConnections.has(event.user)?"offline":r.rows[0].presence;
  const packet=JSON.stringify({op:0,t:"PRESENCE_UPDATE",s:null,d:{user_id:event.user,status,custom_status:r.rows[0].custom_status}});
  const audience=await presenceAudience(event.user);
  for(const user of audience)if(userConnections.has(user))sendToUser(user,packet);
  return;
 }
 if(event.kind==="message_updated"&&uuid.safeParse(event.message).success&&uuid.safeParse(event.channel).success){
  const found=await db.query("SELECT id,channel_id,author_id,ciphertext,algorithm,created_at,edited_at FROM messages WHERE id=$1 AND channel_id=$2",[event.message,event.channel]);
  if(!found.rowCount)return;
  const packet=JSON.stringify({op:0,t:"MESSAGE_UPDATE",s:null,d:found.rows[0]});
  for(const socket of sockets.get(event.channel)??[]){
   const user=socketIdentity.get(socket);
   if(socket.readyState===1&&user&&await member(user,event.channel))socket.send(packet);
  }
  return;
 }
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
  // A replayed removal must not evict someone who has since rejoined.
  const rejoined=await db.query("SELECT 1 FROM guild_members WHERE guild_id=$1 AND user_id=$2",[event.guild,event.user]);
  if(rejoined.rowCount)return;
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
  const found=await db.query("SELECT m.id,m.channel_id,m.author_id,u.username AS author_username,m.ciphertext,m.algorithm,m.created_at,m.edited_at,m.reply_to,'[]'::json AS reactions,false AS pinned FROM messages m LEFT JOIN users u ON u.id=m.author_id WHERE m.id=$1 AND m.channel_id=$2",[event.message,event.channel]);
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
 try{
  const event=JSON.parse(msg.payload);
  if(typeof event?._id==="string"){if(deliveredEvents.has(event._id))return;rememberDelivered(event._id)}
  void processSecurityEvent(event).catch(error=>app.log.error(error));
 }
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
    // Skip events already delivered through LISTEN/NOTIFY; replay only the gaps.
    if(!deliveredEvents.has(record.id)){rememberDelivered(record.id);await processSecurityEvent(record.payload)}
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
const frontend = fileURLToPath(new URL("../../web/index.html", import.meta.url));
const frontendJs = fileURLToPath(new URL("../../web/app.js", import.meta.url));
const homepage=fileURLToPath(new URL("../../web/home.html",import.meta.url));
app.get("/",async(_request,reply)=>reply.type("text/html; charset=utf-8").send(await readFile(homepage)));
app.get("/app",async(_request,reply)=>reply.type("text/html; charset=utf-8").send(await readFile(frontend)));
app.get("/app/channels/:guildId/:channelId",async(_request,reply)=>reply.type("text/html; charset=utf-8").send(await readFile(frontend)));
app.get("/app.js", async (_request, reply) => reply.header("Cache-Control", "no-store").type("application/javascript").send(await readFile(frontendJs)));
const cryptoJs=fileURLToPath(new URL("../../web/crypto.mjs",import.meta.url));
const vaultJs=fileURLToPath(new URL("../../web/private-key-vault.mjs",import.meta.url));
app.get("/crypto.mjs",async(_request,reply)=>reply.type("application/javascript").send(await readFile(cryptoJs)));
app.get("/private-key-vault.mjs",async(_request,reply)=>reply.type("application/javascript").send(await readFile(vaultJs)));
// Static client assets: fixed file names only, never request-derived paths.
const staticAssets:Record<string,[string,string]>={
 "/e2ee.mjs":["../../web/e2ee.mjs","application/javascript"],
 "/app.css":["../../web/app.css","text/css; charset=utf-8"],
 "/home.css":["../../web/home.css","text/css; charset=utf-8"],
 "/favicon.svg":["../../web/favicon.svg","image/svg+xml"]
};
for(const [route,[file,type]] of Object.entries(staticAssets)){
 const path=fileURLToPath(new URL(file,import.meta.url));
 app.get(route,async(_request,reply)=>reply.type(type).send(await readFile(path)));
}
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
  const r = await db.query("SELECT id,password_hash,password_salt,suspended_at FROM users WHERE username=$1", [username]);
  const record = r.rows[0];
  // Avoid a fast unknown-user path and never leak which usernames exist.
  const hash = await passwordHash(password, record?.password_salt ?? "00000000000000000000000000000000");
  const a = Buffer.from(hash,"hex"), b = Buffer.from(record?.password_hash ?? "00".repeat(64),"hex");
  if (!record || !timingSafeEqual(a,b)) return reply.code(401).send({ error: "Invalid credentials" });
  // Only revealed after a correct password, so suspension status does not leak to guessers.
  if (record.suspended_at) return reply.code(403).send({ error: "Account suspended" });

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


// Password change: proof of the current password, then every OTHER session is revoked
// (the sessions trigger notifies all API instances, closing their Gateway sockets).
app.post("/api/v1/auth/password",async(request,reply)=>{
 const raw=/^Bearer ([a-f0-9]{64})$/.exec(request.headers.authorization ?? "");
 const user=await auth(request.headers.authorization);
 if(!user||!raw)return reply.code(401).send({message:"Unauthorized"});
 const input=z.object({current_password:z.string().min(12).max(256),new_password:z.string().min(12).max(256)}).safeParse(request.body);
 if(!input.success)return reply.code(400).send({message:"New password must be 12–256 characters"});
 if(input.data.current_password===input.data.new_password)return reply.code(400).send({message:"Choose a different password"});
 if(!await takeQuota("password-change:"+user.id,6,900))return reply.code(429).header("Retry-After","900").send({message:"Too many attempts"});
 const owner=await db.query("SELECT password_salt,password_hash FROM users WHERE id=$1",[user.id]);
 if(!owner.rowCount)return reply.code(401).send({message:"Unauthorized"});
 const proof=Buffer.from(await passwordHash(input.data.current_password,owner.rows[0].password_salt),"hex");
 const expected=Buffer.from(owner.rows[0].password_hash,"hex");
 if(proof.length!==expected.length||!timingSafeEqual(proof,expected))return reply.code(401).send({message:"Current password is incorrect"});
 const salt=randomBytes(16).toString("hex");
 const hashed=await passwordHash(input.data.new_password,salt);
 await db.query("UPDATE users SET password_salt=$2,password_hash=$3 WHERE id=$1",[user.id,salt,hashed]);
 await db.query("DELETE FROM sessions WHERE user_id=$1 AND token_hash<>$2",[user.id,hashToken(raw[1])]);
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
 const rawBundle=(request.body as any)?.public_bundle;
 if(rawBundle!==undefined&&bundleFingerprint(rawBundle)!==data.data.identity_key)return reply.code(400).send({message:"Public bundle does not match identity fingerprint"});
 const id=randomUUID();
 try {
  const result=await db.query("INSERT INTO user_devices(id,user_id,name,identity_key,public_bundle) VALUES($1,$2,$3,$4,$5::jsonb) RETURNING id,name,identity_key,created_at",[id,user.id,data.data.name,data.data.identity_key,rawBundle===undefined?null:JSON.stringify(rawBundle)]);
  // Existing devices of this account are prompted to approve (cross-sign) the new one.
  await publishSecurityEvent({kind:"dispatch",users:[user.id],t:"DEVICE_ADDED",d:{device_id:id,name:data.data.name}});
  return reply.code(201).send(result.rows[0]);
 }catch(e:any){if(e.code==="23505")return reply.code(409).send({message:"Key already registered"});throw e}
});
app.get("/api/v1/devices",async(request,reply)=>{
 const user=await auth(request.headers.authorization);
 if(!user)return reply.code(401).send({message:"Unauthorized"});
 const result=await db.query("SELECT id,name,identity_key,created_at,public_bundle,attestation,public_bundle IS NOT NULL AS has_bundle FROM user_devices WHERE user_id=$1 AND revoked_at IS NULL ORDER BY created_at",[user.id]);
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
 const result=await db.query("SELECT id,user_id,identity_key,public_bundle,attestation,created_at FROM user_devices WHERE user_id=$1 AND revoked_at IS NULL ORDER BY created_at",[id]);
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
  if(!user)return reply.code(401).send({ message: "401: Unauthorized", code: 0 });
  const extra=await db.query("SELECT is_admin FROM users WHERE id=$1",[user.id]);
  return {...user,is_admin:extra.rows[0]?.is_admin===true};
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
    await client.query("INSERT INTO guild_roles(id,guild_id,name,permissions,position,is_default) VALUES($1,$1,'@everyone',$2::bigint,0,true)",[id,DEFAULT_PERMISSIONS.toString()]);
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
  // Role-based: CREATE_INVITE (granted to @everyone by default, owners always). Never for DMs.
  const access=await guildAccess(db,id,user.id);
  if(!access||access.kind!=="community"||!has(access.perms,Permissions.CREATE_INVITE)) return reply.code(403).send({message:"Missing CREATE_INVITE permission"});
  const code=randomBytes(24).toString("base64url");
  const expires=new Date(Date.now()+options.data.expires_hours*3600000);
  await db.query("INSERT INTO guild_invites(code_hash,guild_id,created_by,expires_at,max_uses,code_hint) VALUES($1,$2,$3,$4,$5,$6)",
   [hashToken(code),id,user.id,expires,options.data.max_uses,code.slice(0,4)]);
  await db.query("INSERT INTO guild_audit_log(guild_id,actor_id,action,target_id,details) VALUES($1,$2,'invite.create',$3,$4::jsonb)",[id,user.id,hashToken(code).slice(0,16),JSON.stringify({max_uses:options.data.max_uses,expires_hours:options.data.expires_hours})]);
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
    const banned=await client.query("SELECT 1 FROM guild_bans WHERE guild_id=$1 AND user_id=$2",[invite.guild_id,user.id]);
    if(banned.rowCount){await client.query("ROLLBACK");return reply.code(403).send({message:"You are banned from this community"})}
    const joined=await client.query("INSERT INTO guild_members(guild_id,user_id) VALUES($1,$2) ON CONFLICT DO NOTHING RETURNING user_id",[invite.guild_id,user.id]);
    if(joined.rowCount) await client.query("UPDATE guild_invites SET uses=uses+1 WHERE code_hash=$1",[hashToken(code)]);
    await client.query("COMMIT");
    if(joined.rowCount){
     await publishSecurityEvent({kind:"dispatch",guild:invite.guild_id,t:"GUILD_MEMBER_ADD",d:{guild_id:invite.guild_id,user_id:user.id,username:user.username}});
     await publishSecurityEvent({kind:"dispatch",users:[user.id],t:"GUILD_CREATE",d:{id:invite.guild_id}});
    }
    return {guild_id:invite.guild_id,already_member:!joined.rowCount};
  } catch(e){await client.query("ROLLBACK");throw e}
  finally{client.release()}
});

app.get("/api/v10/users/@me/guilds", async (request, reply) => {
  const user = await auth(request.headers.authorization);
  if (!user) return reply.code(401).send({ message:"Unauthorized" });
  const r=await db.query("SELECT g.id,g.name,g.owner_id,g.description FROM guilds g JOIN guild_members gm ON gm.guild_id=g.id WHERE gm.user_id=$1 AND g.kind='community' ORDER BY gm.joined_at,g.created_at",[user.id]);
  return r.rows;
});

const channelInput=z.object({name:z.string().trim().min(1).max(80).regex(/^[a-z0-9_-]+$/)});
const channelExtras=z.object({kind:z.enum(["encrypted_text","announcement","category"]).default("encrypted_text"),topic:z.string().trim().max(1024).default(""),parent_id:z.string().uuid().nullable().optional()});
const channelColumns="id,guild_id,name,kind,topic,position,parent_id";
app.post("/api/v1/guilds/:id/channels", async(request,reply)=>{
 const user=await auth(request.headers.authorization);
 if(!user)return reply.code(401).send({message:"Unauthorized"});
 const id=(request.params as {id:string}).id;
 if(!uuid.safeParse(id).success)return reply.code(400).send({message:"Invalid community ID"});
 const data=channelInput.merge(channelExtras).safeParse(request.body);
 if(!data.success)return reply.code(400).send({message:"Channel names must be 1–80 lowercase letters, digits, - or _"});
 const access=await guildAccess(db,id,user.id);
 if(!access||access.kind!=="community"||!has(access.perms,Permissions.MANAGE_CHANNELS))return reply.code(403).send({message:"Missing MANAGE_CHANNELS permission"});
 const count=await db.query("SELECT count(*)::int AS n,COALESCE(max(position),0)+1 AS next FROM channels WHERE guild_id=$1",[id]);
 if(count.rows[0].n>=500)return reply.code(409).send({message:"Channel limit reached"});
 const parent=data.data.kind==="category"?null:(data.data.parent_id??null);
 const channelId=randomUUID();
 // Parent must be a category in the same community, verified inside the INSERT.
 const result=await db.query("INSERT INTO channels(id,guild_id,name,kind,topic,position,parent_id) SELECT $1,$2,$3,$4,$5,$6,$7::uuid WHERE $7::uuid IS NULL OR EXISTS(SELECT 1 FROM channels WHERE id=$7 AND guild_id=$2 AND kind='category') RETURNING "+channelColumns,[channelId,id,data.data.name,data.data.kind,data.data.topic,count.rows[0].next,parent]);
 if(!result.rowCount)return reply.code(400).send({message:"Parent must be a category in this community"});
 await db.query("INSERT INTO guild_audit_log(guild_id,actor_id,action,target_id,details) VALUES($1,$2,'channel.create',$3,$4::jsonb)",[id,user.id,channelId,JSON.stringify({name:data.data.name,kind:data.data.kind})]);
 await publishSecurityEvent({kind:"dispatch",guild:id,t:"CHANNEL_CREATE",d:result.rows[0]});
 return reply.code(201).send(result.rows[0]);
});
const channelPatch=channelInput.partial().extend({topic:z.string().trim().max(1024).optional()}).refine(v=>v.name!==undefined||v.topic!==undefined,"Nothing to update");
app.patch("/api/v1/channels/:id", async(request,reply)=>{
 const user=await auth(request.headers.authorization);
 if(!user)return reply.code(401).send({message:"Unauthorized"});
 const id=(request.params as {id:string}).id;
 if(!uuid.safeParse(id).success)return reply.code(400).send({message:"Invalid channel ID"});
 const data=channelPatch.safeParse(request.body);
 if(!data.success)return reply.code(400).send({message:"Invalid channel name"});
 const access=await channelAccess(db,id,user.id);
 if(!access||access.kind!=="community"||!has(access.perms,Permissions.MANAGE_CHANNELS))return reply.code(403).send({message:"Missing MANAGE_CHANNELS permission"});
 // Guild scope is re-checked in the UPDATE itself.
 const result=await db.query("UPDATE channels c SET name=COALESCE($1,c.name),topic=COALESCE($4,c.topic) FROM guilds g WHERE c.id=$2 AND g.id=c.guild_id AND g.id=$3 AND g.kind='community' RETURNING c.id,c.guild_id,c.name,c.kind,c.topic,c.position,c.parent_id",[data.data.name??null,id,access.guildId,data.data.topic??null]);
 if(!result.rowCount)return reply.code(403).send({message:"Missing MANAGE_CHANNELS permission"});
 await db.query("INSERT INTO guild_audit_log(guild_id,actor_id,action,target_id,details) VALUES($1,$2,'channel.update',$3,$4::jsonb)",[access.guildId,user.id,id,JSON.stringify(data.data)]);
 await publishSecurityEvent({kind:"dispatch",guild:access.guildId,t:"CHANNEL_UPDATE",d:result.rows[0]});
 return result.rows[0];
});


app.get("/api/v1/guilds/:id/members",async(request,reply)=>{
 const user=await auth(request.headers.authorization);
 if(!user)return reply.code(401).send({message:"Unauthorized"});
 const id=(request.params as {id:string}).id;
 if(!uuid.safeParse(id).success)return reply.code(400).send({message:"Invalid community ID"});
 const memberCheck=await db.query("SELECT 1 FROM guild_members WHERE guild_id=$1 AND user_id=$2",[id,user.id]);
 if(!memberCheck.rowCount)return reply.code(403).send({message:"Not a member"});
 const result=await db.query(`SELECT u.id,u.username,gm.nickname,gm.joined_at,COALESCE(up.display_name,'') AS display_name,COALESCE(up.custom_status,'') AS custom_status,${PRESENCE_SQL} AS presence,COALESCE((SELECT json_agg(mr.role_id) FROM guild_member_roles mr WHERE mr.guild_id=gm.guild_id AND mr.user_id=gm.user_id),'[]') AS roles FROM users u JOIN guild_members gm ON gm.user_id=u.id LEFT JOIN user_profiles up ON up.user_id=u.id LEFT JOIN user_presence pr ON pr.user_id=u.id WHERE gm.guild_id=$1 ORDER BY u.username LIMIT 1000`,[id]);
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
 let moderated=false;
 if(user.id!==userId){
  // Kicking needs KICK_MEMBERS and a strictly higher top role than the target (owners bypass).
  const access=await guildAccess(db,id,user.id);
  if(!access||access.kind!=="community"||!has(access.perms,Permissions.KICK_MEMBERS))return reply.code(403).send({message:"Only owners can remove other members"});
  const targetTop=await db.query("SELECT COALESCE(max(r.position),0) AS top FROM guild_member_roles mr JOIN guild_roles r ON r.id=mr.role_id WHERE mr.guild_id=$1 AND mr.user_id=$2",[id,userId]);
  if(!access.owner&&Number(targetTop.rows[0].top)>=access.top)return reply.code(403).send({message:"Target has an equal or higher role"});
  moderated=true;
 }
 const removed=await db.query("DELETE FROM guild_members gm USING guilds g WHERE gm.guild_id=$1 AND gm.user_id=$2 AND g.id=gm.guild_id AND g.owner_id<>gm.user_id AND ($3=gm.user_id OR $4::boolean) RETURNING gm.user_id",[id,userId,user.id,moderated]);
 if(!removed.rowCount)return reply.code(404).send({message:"Membership not found or removal not permitted"});
 if(moderated)await db.query("INSERT INTO guild_audit_log(guild_id,actor_id,action,target_id) VALUES($1,$2,'member.kick',$3)",[id,user.id,userId]);
 await publishSecurityEvent({kind:"dispatch",guild:id,t:"GUILD_MEMBER_REMOVE",d:{guild_id:id,user_id:userId}});
 await publishSecurityEvent({kind:"dispatch",users:[userId],t:"GUILD_DELETE",d:{id}});
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
  const r=await db.query("SELECT c.id,c.name,c.kind,c.topic,c.position,c.parent_id,(SELECT max(m.created_at) FROM messages m WHERE m.channel_id=c.id) AS last_message_at,rs.last_read_at FROM channels c JOIN guild_members gm ON gm.guild_id=c.guild_id LEFT JOIN channel_read_states rs ON rs.channel_id=c.id AND rs.user_id=gm.user_id WHERE gm.user_id=$1 AND c.guild_id=$2 ORDER BY c.position,c.created_at",[user.id,id]);
  return r.rows;
});
app.get("/api/v10/channels/:id/messages", async (request, reply) => {
  const user = await auth(request.headers.authorization);
  const id = (request.params as any).id;
  if (!user) return reply.code(401).send({ message:"Unauthorized" });
  if (!uuid.safeParse(id).success) return reply.code(400).send({ message:"Invalid channel ID" });
  if (!await member(user.id,id)) return reply.code(403).send({ message:"Forbidden" });
  const page=z.object({before:z.string().uuid().optional(),limit:z.coerce.number().int().min(1).max(100).default(50)}).safeParse(request.query);
  if(!page.success)return reply.code(400).send({message:"Invalid pagination"});
  if(page.data.before){
   const cursor=await db.query("SELECT 1 FROM messages WHERE id=$1 AND channel_id=$2",[page.data.before,id]);
   if(!cursor.rowCount)return reply.code(400).send({message:"Cursor does not belong to this channel"});
  }
  const r=await db.query(`SELECT m.id,m.channel_id,m.author_id,u.username AS author_username,m.ciphertext,m.algorithm,m.created_at,m.edited_at,m.reply_to,
    COALESCE((SELECT json_agg(json_build_object('emoji',x.emoji,'count',x.n,'me',x.me) ORDER BY x.first) FROM (SELECT emoji,count(*)::int AS n,bool_or(user_id=$3) AS me,min(created_at) AS first FROM message_reactions WHERE message_id=m.id GROUP BY emoji) x),'[]') AS reactions,
    EXISTS(SELECT 1 FROM message_pins p WHERE p.message_id=m.id) AS pinned
   FROM messages m LEFT JOIN users u ON u.id=m.author_id WHERE m.channel_id=$1 AND ($2::uuid IS NULL OR (m.created_at,m.id)<(SELECT b.created_at,b.id FROM messages b WHERE b.id=$2::uuid)) ORDER BY m.created_at DESC,m.id DESC LIMIT $4`,[id,page.data.before??null,user.id,page.data.limit]);
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
  const access=await channelAccess(db,id,user.id);
  if(!access||!has(access.perms,Permissions.SEND_MESSAGES))return reply.code(403).send({message:"Missing SEND_MESSAGES permission"});
  if(access.channel.kind==="category")return reply.code(400).send({message:"Categories do not hold messages"});
  if(access.channel.kind==="announcement"&&!has(access.perms,Permissions.MANAGE_MESSAGES))return reply.code(403).send({message:"Only moderators can post in announcement channels"});
  if(access.kind==="dm"){
   const blocked=await db.query("SELECT 1 FROM guild_members peer JOIN user_relationships r ON r.status='blocked' AND ((r.user_id=$2 AND r.target_id=peer.user_id) OR (r.user_id=peer.user_id AND r.target_id=$2)) JOIN guilds g ON g.id=peer.guild_id AND g.dm_key IS NOT NULL WHERE peer.guild_id=$1 AND peer.user_id<>$2 LIMIT 1",[access.guildId,user.id]);
   if(blocked.rowCount)return reply.code(403).send({message:"You cannot message this user"});
  }
  const replyTo=z.string().uuid().safeParse((request.body as any)?.reply_to);
  let replyId:string|null=null;
  if(replyTo.success){const target=await db.query("SELECT 1 FROM messages WHERE id=$1 AND channel_id=$2",[replyTo.data,id]);if(target.rowCount)replyId=replyTo.data}
  const messageId=randomUUID();
  // INSERT ... SELECT performs the membership check within the write statement,
  // avoiding the separate authorization-query/INSERT race on this route.
  const r=await db.query(
    "INSERT INTO messages(id,channel_id,author_id,ciphertext,algorithm,reply_to) SELECT $1,c.id,$3,$4,$5,$6 FROM channels c JOIN guild_members gm ON gm.guild_id=c.guild_id LEFT JOIN guild_key_epochs e ON e.guild_id=c.guild_id WHERE c.id=$2 AND gm.user_id=$3 AND (CASE WHEN left($4,1)='{' THEN COALESCE(($4::jsonb->'context'->>'epoch')::bigint,-1)=COALESCE(e.epoch,1) ELSE true END) RETURNING id,channel_id,author_id,ciphertext,algorithm,created_at,edited_at,reply_to",
    [messageId,id,user.id,parsed.data.ciphertext,parsed.data.algorithm,replyId]
  );
  if(!r.rowCount)return reply.code(403).send({message:"Forbidden"});
  userTyping.delete(user.id+":"+id); // sending ends the typing session
  await publishSecurityEvent({kind:"message",channel:id,message:r.rows[0].id});
  return reply.code(201).send({...r.rows[0],author_username:user.username,reactions:[],pinned:false});
});
// Author or MANAGE_MESSAGES deletion. SQL checks ownership/moderation and current membership atomically.
app.delete("/api/v10/channels/:id/messages/:messageId",async(request,reply)=>{
 const user=await auth(request.headers.authorization);
 if(!user)return reply.code(401).send({message:"Unauthorized"});
 const {id,messageId}=request.params as {id:string,messageId:string};
 if(!uuid.safeParse(id).success||!uuid.safeParse(messageId).success)return reply.code(400).send({message:"Invalid ID"});
 const access=await channelAccess(db,id,user.id);
 const moderator=!!access&&access.kind==="community"&&has(access.perms,Permissions.MANAGE_MESSAGES);
 const client=await db.connect();
 try{
  await client.query("BEGIN");
  const result=await client.query(
   "DELETE FROM messages m USING channels c,guild_members gm WHERE m.id=$1 AND m.channel_id=$2 AND (m.author_id=$3 OR $4::boolean) AND c.id=m.channel_id AND gm.guild_id=c.guild_id AND gm.user_id=$3 RETURNING m.id,m.author_id",
   [messageId,id,user.id,moderator]
  );
  if(!result.rowCount){await client.query("ROLLBACK");return reply.code(404).send({message:"Message not found or deletion not permitted"})}
  await client.query("INSERT INTO message_tombstones(id,channel_id,deleted_by) VALUES($1,$2,$3)",[messageId,id,user.id]);
  if(access&&result.rows[0].author_id!==user.id)await client.query("INSERT INTO guild_audit_log(guild_id,actor_id,action,target_id,details) VALUES($1,$2,'message.delete',$3,$4::jsonb)",[access.guildId,user.id,messageId,JSON.stringify({channel:id,author:result.rows[0].author_id})]);
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

app.get("/api/v1/channels/:id/keys",async(request,reply)=>{
 const user=await auth(request.headers.authorization);if(!user)return reply.code(401).send({message:"Unauthorized"});
 const id=(request.params as {id:string}).id;if(!uuid.safeParse(id).success)return reply.code(400).send({message:"Invalid channel"});
 if(!await member(user.id,id))return reply.code(403).send({message:"Forbidden"});
 const rows=await db.query("SELECT c.guild_id,COALESCE(e.epoch,1)::text AS epoch FROM channels c LEFT JOIN guild_key_epochs e ON e.guild_id=c.guild_id WHERE c.id=$1",[id]);
 if(!rows.rowCount)return reply.code(404).send({message:"Channel not found"});
 const recipients=await db.query("SELECT d.id,d.user_id,u.username,d.identity_key,d.public_bundle,d.attestation,d.created_at FROM user_devices d JOIN users u ON u.id=d.user_id JOIN guild_members gm ON gm.user_id=d.user_id WHERE gm.guild_id=$1 AND d.revoked_at IS NULL ORDER BY d.user_id,d.created_at,d.id",[rows.rows[0].guild_id]);
 // Each wrapped key is encrypted to one device; callers receive only their own devices' envelopes.
 const wrapped=await db.query("SELECT k.device_id,k.wrapped_key,k.granted_by FROM channel_device_keys k JOIN user_devices d ON d.id=k.device_id WHERE k.channel_id=$1 AND k.epoch=$2 AND d.user_id=$3",[id,rows.rows[0].epoch,user.id]);
 const granted=await db.query("SELECT device_id FROM channel_device_keys WHERE channel_id=$1 AND epoch=$2",[id,rows.rows[0].epoch]);
 const claim=await db.query("SELECT creator_device_id,key_commitment FROM channel_epoch_keys WHERE channel_id=$1 AND epoch=$2",[id,rows.rows[0].epoch]);
 const history=await db.query("SELECT k.epoch::int AS epoch,k.device_id,k.wrapped_key,k.granted_by,c.key_commitment FROM channel_device_keys k JOIN user_devices d ON d.id=k.device_id AND d.user_id=$2 LEFT JOIN channel_epoch_keys c ON c.channel_id=k.channel_id AND c.epoch=k.epoch WHERE k.channel_id=$1 AND k.epoch<$3 ORDER BY k.epoch DESC LIMIT 200",[id,user.id,rows.rows[0].epoch]);
 return {epoch:Number(rows.rows[0].epoch),recipients:recipients.rows,wrapped:wrapped.rows,granted_device_ids:granted.rows.map((r:{device_id:string})=>r.device_id),claim:claim.rows[0]??null,history:history.rows};
});
app.put("/api/v1/channels/:id/keys/:deviceId",async(request,reply)=>{
 const user=await auth(request.headers.authorization);
 if(!user)return reply.code(401).send({message:"Unauthorized"});
 const {id,deviceId}=request.params as {id:string,deviceId:string};
 if(!uuid.safeParse(id).success||!uuid.safeParse(deviceId).success)return reply.code(400).send({message:"Invalid ID"});
 const body=z.object({epoch:z.number().int().positive(),wrapped_key:z.record(z.string(),z.unknown()),granter_device_id:z.string().uuid().optional()}).safeParse(request.body);
 if(!body.success)return reply.code(400).send({message:"Invalid key envelope"});
 if(JSON.stringify(body.data.wrapped_key).length>16384)return reply.code(400).send({message:"Key envelope too large"});
 const inserted=await db.query(
 "INSERT INTO channel_device_keys(channel_id,epoch,device_id,wrapped_key,granted_by) SELECT c.id,$2,d.id,$4::jsonb,(SELECT g.id FROM user_devices g WHERE g.id=$6::uuid AND g.user_id=$5 AND g.revoked_at IS NULL) FROM channels c JOIN guild_members author ON author.guild_id=c.guild_id JOIN user_devices d ON d.id=$3 AND d.revoked_at IS NULL JOIN guild_members recipient ON recipient.guild_id=c.guild_id AND recipient.user_id=d.user_id LEFT JOIN guild_key_epochs e ON e.guild_id=c.guild_id WHERE c.id=$1 AND author.user_id=$5 AND COALESCE(e.epoch,1)=$2 ON CONFLICT(channel_id,epoch,device_id) DO NOTHING RETURNING device_id",
 [id,body.data.epoch,deviceId,JSON.stringify(body.data.wrapped_key),user.id,body.data.granter_device_id??null]);
 if(!inserted.rowCount)return reply.code(409).send({message:"Key rejected: membership, epoch or duplicate"});
 return reply.code(201).send({device_id:deviceId,epoch:body.data.epoch});
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
  let windowStart = Date.now(), windowMessages = 0, lastPresence = 0;
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
      if (payload.op===1) {
        lastHeartbeat=Date.now(); socket.send(JSON.stringify({ op:11,d:null }));
        if(identity&&Date.now()-lastPresence>20000){lastPresence=Date.now();void touchPresence(identity.id).catch(error=>app.log.warn(error))}
        return;
      }
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
        lastPresence=Date.now();void touchPresence(identity.id).catch(error=>app.log.warn(error));
      } else if (payload.op===42 && identity) {
        const channelId=payload.d?.channel_id;
        if (!uuid.safeParse(channelId).success || !await member(identity.id,channelId)) return;
        if (!subscriptions.has(channelId) && subscriptions.size >= 25) { socket.close(4008,"Subscription limit exceeded"); return; }
        if (!sockets.has(channelId)) sockets.set(channelId,new Set());
        sockets.get(channelId)!.add(socket);
        subscriptions.add(channelId);
        socket.send(JSON.stringify({op:0,t:"CHANNEL_SUBSCRIBED",s:null,d:{channel_id:channelId}}));
      } else if (payload.op===44 && identity) {
        // Typing indicator: only for a channel this socket is subscribed to, throttled per user/channel.
        const channelId=payload.d?.channel_id;
        if(typeof channelId!=="string"||!subscriptions.has(channelId))return;
        const key=identity.id+":"+channelId,last=userTyping.get(key)??0;
        if(Date.now()-last<2500)return;
        if(userTyping.size>10000)userTyping.clear();
        userTyping.set(key,Date.now());
        await publishEphemeral({kind:"typing",channel:channelId,user:identity.id,username:identity.username});
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
    if(userId){
      const connections=userConnections.get(userId);connections?.delete(socket);
      if(!connections?.size){userConnections.delete(userId);void markOffline(userId).catch(error=>app.log.warn(error))}
    }
    for (const id of subscriptions) {
      sockets.get(id)?.delete(socket);
      if (!sockets.get(id)?.size) sockets.delete(id);
    }
  });
});

// Presence is stored as a heartbeat timestamp so every API instance derives the same status.
async function touchPresence(userId:string){
 const r=await db.query("WITH old AS (SELECT last_seen FROM user_presence WHERE user_id=$1) INSERT INTO user_presence(user_id,last_seen) VALUES($1,now()) ON CONFLICT(user_id) DO UPDATE SET last_seen=now() RETURNING COALESCE((SELECT last_seen<now()-interval '90 seconds' FROM old),true) AS was_offline",[userId]);
 if(r.rows[0]?.was_offline)await publishEphemeral({kind:"presence",user:userId});
}
async function markOffline(userId:string){
 // Another instance holding a live connection refreshes last_seen on its next heartbeat.
 await db.query("UPDATE user_presence SET last_seen=now()-interval '5 minutes' WHERE user_id=$1",[userId]);
 await publishEphemeral({kind:"presence",user:userId});
}
registerCommunity(app,{db,auth,publish:publishSecurityEvent,publishEphemeral,takeQuota});
async function verifyPassword(userId:string,password:string){
 const owner=await db.query("SELECT password_salt,password_hash FROM users WHERE id=$1",[userId]);
 if(!owner.rowCount)return false;
 const proof=Buffer.from(await passwordHash(password,owner.rows[0].password_salt),"hex"),expected=Buffer.from(owner.rows[0].password_hash,"hex");
 return proof.length===expected.length&&timingSafeEqual(proof,expected);
}
registerSecurity(app,{db,auth,publish:publishSecurityEvent,takeQuota,verifyPassword});
// Bootstrap instance administrators from configuration (comma-separated usernames).
if(process.env.INSTANCE_ADMINS){
 const names=process.env.INSTANCE_ADMINS.split(",").map(s=>s.trim()).filter(Boolean);
 if(names.length)await db.query("UPDATE users SET is_admin=true WHERE username=ANY($1::text[])",[names]);
}

try {
  await db.query("SELECT 1");
  await app.listen({ host: process.env.HOST || "127.0.0.1", port });
} catch (error) {
  app.log.error(error);
  await db.end();
  process.exit(1);
}
