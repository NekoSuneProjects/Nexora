import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";

const base="http://127.0.0.1:3100";
const processHandle=spawn("npm",["run","start"],{env:{...process.env,PORT:"3100",HOST:"127.0.0.1"},stdio:"pipe"});
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
 const res=await fetch(base+path,{method,headers:{"content-type":"application/json",...(token?{authorization:"Bearer "+token}:{})},...(body!==undefined?{body:JSON.stringify(body)}:{})});
 let data=null;try{data=await res.json()}catch{}
 return {status:res.status,data};
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
  const guild=await request("/api/v10/guilds","POST",{name:"CI Community"},tokenA);
  assert.equal(guild.status,201);
  const id=guild.data.id,channelId=guild.data.channels[0].id;
  assert.equal((await request("/api/v10/channels/"+channelId+"/messages","GET",undefined,tokenB)).status,403);
  assert.equal((await request("/api/v1/guilds/"+id+"/invites","POST",{max_uses:1,expires_hours:1},tokenB)).status,403);
  const invite=await request("/api/v1/guilds/"+id+"/invites","POST",{max_uses:1,expires_hours:1},tokenA);
  assert.equal(invite.status,201);
  const join=await request("/api/v1/invites/"+invite.data.code+"/join","POST",undefined,tokenB);
  assert.equal(join.status,200);assert.equal(join.data.already_member,false);
  assert.equal((await request("/api/v10/channels/"+channelId+"/messages","GET",undefined,tokenB)).status,200);
  assert.equal((await request("/api/v1/guilds/"+id+"/channels","POST",{name:"should-fail"},tokenB)).status,403);
  assert.equal((await request("/api/v1/guilds/"+id+"/members/"+(await request("/api/v10/users/@me","GET",undefined,tokenB)).data.id,"DELETE",undefined,tokenA)).status,204);
  assert.equal((await request("/api/v10/channels/"+channelId+"/messages","GET",undefined,tokenB)).status,403);
  assert.equal((await request("/api/v1/auth/logout-all","POST",undefined,tokenA)).status,204);
  assert.equal((await request("/api/v10/users/@me","GET",undefined,tokenA)).status,401);
 }finally{
  processHandle.kill("SIGTERM");
 }
},{timeout:50000});
