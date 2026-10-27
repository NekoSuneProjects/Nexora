import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";

const base="http://127.0.0.1:3100";
const processHandle=spawn(process.execPath,["node_modules/tsx/dist/cli.mjs","apps/api/src/index.ts"],{env:{...process.env,PORT:"3100",HOST:"127.0.0.1"},stdio:"pipe"});
let log="";
processHandle.stdout.on("data",d=>{log+=d.toString()});
processHandle.stderr.on("data",d=>{log+=d.toString()});
async function ready(){
 for(let attempt=0;attempt<60;attempt++){
  if(processHandle.exitCode!==null)throw new Error("API exited: "+log);
  try{const r=await fetch(base+"/health");if(r.ok)return}catch{}
  await sleep(500);
 }
 throw new Error("API not ready: "+log);
}
async function request(path,method="GET",body,token){
 const res=await fetch(base+path,{method,headers:{...(body!==undefined?{"content-type":"application/json"}:{}),...(token?{authorization:"Bearer "+token}:{})},...(body!==undefined?{body:JSON.stringify(body)}:{})});
 let data=null;try{data=await res.json()}catch{}
 return {status:res.status,data};
}

async function botSocket(token,guildId){
 const ws=new WebSocket("ws://127.0.0.1:3100/bot-gateway");
 const queue=[];
 const listeners=[];
 ws.addEventListener("message",event=>{
  const packet=JSON.parse(event.data);
  if(listeners.length)listeners.shift()(packet);else queue.push(packet);
 });
 const next=()=>queue.length?Promise.resolve(queue.shift()):new Promise(resolve=>listeners.push(resolve));
 const receive=async(type)=>{
  for(let i=0;i<8;i++){
   const packet=await Promise.race([next(),sleep(2500).then(()=>{throw Error("Bot Gateway timeout waiting for "+type)})]);
   if(packet.t===type||packet.op===type)return packet;
  }
  throw Error("Expected "+type);
 };
 await receive(10);
 ws.send(JSON.stringify({op:2,d:{token}}));
 await receive("READY");
 ws.send(JSON.stringify({op:42,d:{guild_id:guildId}}));
 await receive("GUILD_SUBSCRIBED");
 return {ws,receive};
}

test("API uses a real PostgreSQL database and enforces community membership",async()=>{
 try{
  await ready();
  const suffix=Math.random().toString(36).slice(2,10);
  const a="alpha_"+suffix,b="bravo_"+suffix;
  assert.equal((await request("/api/v1/auth/register","POST",{username:a,password:"a secure test passphrase 123"})).status,201);
  assert.equal((await request("/api/v1/auth/register","POST",{username:b,password:"another secure passphrase 123"})).status,201);
  const loginA=await request("/api/v1/auth/login","POST",{username:a,password:"a secure test passphrase 123"});
  const loginB=await request("/api/v1/auth/login","POST",{username:b,password:"another secure passphrase 123"});
  assert.equal(loginA.status,200);assert.equal(loginB.status,200);
  const tokenA=loginA.data.token,tokenB=loginB.data.token;
  for(let attempt=0;attempt<6;attempt++)assert.equal((await request("/api/v1/auth/login","POST",{username:a,password:"intentionally-wrong-password"})).status,401);
  assert.equal((await request("/api/v1/auth/login","POST",{username:a,password:"intentionally-wrong-password"})).status,429);
  assert.equal((await request("/api/v1/auth/login","POST",{username:b,password:"another secure passphrase 123"})).status,200);
  const guild=await request("/api/v10/guilds","POST",{name:"CI Community"},tokenA);
  assert.equal(guild.status,201);
  const id=guild.data.id,channelId=guild.data.channels[0].id;
  assert.equal((await request("/api/v10/channels/"+channelId+"/messages","GET",undefined,tokenB)).status,403);
  assert.equal((await request("/api/v10/users/@me","GET")).status,401);
  assert.equal((await request("/api/v1/guilds/"+id+"/invites","POST",{max_uses:1,expires_hours:1},tokenB)).status,403);
  const invite=await request("/api/v1/guilds/"+id+"/invites","POST",{max_uses:1,expires_hours:1},tokenA);
  assert.equal(invite.status,201);
  const join=await request("/api/v1/invites/"+invite.data.code+"/join","POST",undefined,tokenB);
  assert.equal(join.status,200);assert.equal(join.data.already_member,false);
  assert.equal((await request("/api/v10/channels/"+channelId+"/messages","GET",undefined,tokenB)).status,200);
  assert.equal((await request("/api/v1/guilds/"+id+"/channels","POST",{name:"should-fail"},tokenB)).status,403);
  assert.equal((await request("/api/v1/guilds/"+id+"/members/"+(await request("/api/v10/users/@me","GET",undefined,tokenB)).data.id,"DELETE",undefined,tokenA)).status,204);
  assert.equal((await request("/api/v10/channels/"+channelId+"/messages","GET",undefined,tokenB)).status,403);

  // Verify actual bot Gateway delivery against PostgreSQL and WebSocket.
  const dev=await request("/api/v1/developer/apps","POST",{name:"CI metadata bot"},tokenA);
  assert.equal(dev.status,201);
  const appId=dev.data.id,botToken=dev.data.bot_token;
  assert.equal((await request("/api/v1/guilds/"+id+"/bots","POST",{app_id:appId,can_read_events:true},tokenA)).status,201);
  const bot=await botSocket(botToken,id);
  try{
   const sent=await request("/api/v10/channels/"+channelId+"/messages","POST",{ciphertext:"opaque-test-only",algorithm:"client-encrypted-v1"},tokenA);
   assert.equal(sent.status,201);
   const event=await bot.receive("MESSAGE_METADATA_CREATE");
   assert.deepEqual(event.d,{guild_id:id,channel_id:channelId,message_id:sent.data.id});
   assert.equal(Object.hasOwn(event.d,"ciphertext"),false);
   assert.equal((await request("/api/v1/guilds/"+id+"/bots/"+appId,"DELETE",undefined,tokenA)).status,204);
   const after=await request("/api/v10/channels/"+channelId+"/messages","POST",{ciphertext:"opaque-test-only-2",algorithm:"client-encrypted-v1"},tokenA);
   assert.equal(after.status,201);
   // Permission is checked for every emission, so uninstalling prevents additional events.
   const unexpected=await Promise.race([bot.receive("MESSAGE_METADATA_CREATE").then(()=>true).catch(()=>false),sleep(400).then(()=>false)]);
   assert.equal(unexpected,false);
  }finally{bot.ws.close()}
  const rotated=await request("/api/v1/developer/apps/"+appId+"/rotate-token","POST",undefined,tokenA);
  assert.equal(rotated.status,200);
  assert.notEqual(rotated.data.bot_token,botToken);
  const oldIdentity=await fetch(base+"/api/v1/bots/@me",{headers:{authorization:"Bot "+botToken}});
  assert.equal(oldIdentity.status,401);
  const newIdentity=await fetch(base+"/api/v1/bots/@me",{headers:{authorization:"Bot "+rotated.data.bot_token}});
  assert.equal(newIdentity.status,200);
  for(let n=0;n<3;n++)assert.equal((await request("/api/v1/auth/register","POST",{username:"extra_"+suffix+"_"+n,password:"another long test password 123"})).status,201);
  assert.equal((await request("/api/v1/auth/register","POST",{username:"over_"+suffix,password:"another long test password 123"})).status,429);
  assert.equal((await request("/api/v1/auth/logout-all","POST",undefined,tokenA)).status,204);
  assert.equal((await request("/api/v10/users/@me","GET",undefined,tokenA)).status,401);
 }finally{
  processHandle.kill("SIGTERM");
  await Promise.race([new Promise(resolve=>processHandle.once("exit",resolve)),sleep(3000)]);
 }
},{timeout:50000});
