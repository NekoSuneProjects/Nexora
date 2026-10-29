import { readFile, writeFile, rename } from "node:fs/promises";
// Experimental Nexora metadata bot (Node.js 22+). Never log or commit credentials.
// NEXORA_BOT_TOKEN=... NEXORA_GUILD_ID=... node examples/metadata-bot.mjs
const token=process.env.NEXORA_BOT_TOKEN;
const guildId=process.env.NEXORA_GUILD_ID;
const url=process.env.NEXORA_GATEWAY_URL||"ws://127.0.0.1:3000/bot-gateway";
const apiBase=process.env.NEXORA_API_URL||new URL(url.replace(/^ws/,"http")).origin;
const cursorFile=process.env.NEXORA_CURSOR_FILE||null;
let cursor=process.env.NEXORA_EVENT_CURSOR||null,catchingUp=false;
// Suppress duplicates when live Gateway delivery overlaps with REST catch-up.
const recentlySeen=new Set();
const MAX_SEEN=10000;
function reportMetadata(event,recovered=false){
 if(!event||typeof event.message_id!=="string"||typeof event.channel_id!=="string"||event.guild_id!==guildId)return;
 if(recentlySeen.has(event.message_id))return;
 recentlySeen.add(event.message_id);
 if(recentlySeen.size>MAX_SEEN)recentlySeen.delete(recentlySeen.values().next().value);
 console.log(recovered?"Recovered metadata:":"Message metadata:",event.guild_id,event.channel_id,event.message_id);
}
async function loadCursor(){
 if(!cursorFile||cursor)return;
 try{
  const saved=JSON.parse(await readFile(cursorFile,"utf8"));
  if(saved.guild_id===guildId && typeof saved.after==="string" && /^[a-f0-9-]{36}$/i.test(saved.after))cursor=saved.after;
 }catch(error){if(error.code!=="ENOENT")console.error("Could not load cursor:",error.message)}
}
async function saveCursor(next){
 if(!cursorFile)return;
 const tmp=cursorFile+"."+process.pid+".tmp";
 await writeFile(tmp,JSON.stringify({guild_id:guildId,after:next})+"\n",{mode:0o600});
 await rename(tmp,cursorFile);
}
if(!token||!/^[a-f0-9]{64}$/.test(token)||!guildId){
 console.error("Provide NEXORA_BOT_TOKEN (64 hex chars) and NEXORA_GUILD_ID");
 process.exit(1);
}
let socket=null,heartbeat=null,retryTimer=null,attempt=0,stopping=false;
function cleanup(){
 if(heartbeat!==null){clearInterval(heartbeat);heartbeat=null}
}
async function catchUp(){
 if(catchingUp||stopping)return;
 catchingUp=true;
 try{
  for(let page=0;page<100&&!stopping;page++){
   const endpoint=new URL("/api/v1/bots/guilds/"+encodeURIComponent(guildId)+"/events",apiBase);
   if(cursor)endpoint.searchParams.set("after",cursor);
   const result=await fetch(endpoint,{headers:{Authorization:"Bot "+token}});
   if(!result.ok)throw Error("Catch-up HTTP "+result.status);
   const data=await result.json();
   if(!Array.isArray(data.events)||data.events.length>100)throw Error("Malformed catch-up page");
   for(const event of data.events){
    reportMetadata(event,true);
   }
   if(data.next_after && data.next_after!==cursor){
    await saveCursor(data.next_after);
    cursor=data.next_after;
   }
   if(data.events.length<100)break;
   if(!data.next_after)throw Error("Missing cursor in full page");
  }
 }catch(error){console.error("Metadata catch-up failed:",error.message)}
 finally{catchingUp=false}
}
function connect(){
 if(stopping)return;
 const ws=new WebSocket(url);
 socket=ws;
 let ready=false;
 ws.addEventListener("message",event=>{
  if(socket!==ws||stopping)return;
  let packet;
  try{packet=JSON.parse(event.data)}catch{return}
  if(packet.op===10){
   ws.send(JSON.stringify({op:2,d:{token}}));
   cleanup();
   const ms=Number(packet.d?.heartbeat_interval);
   if(Number.isFinite(ms)&&ms>=1000&&ms<=120000)
    heartbeat=setInterval(()=>{if(ws.readyState===WebSocket.OPEN)ws.send(JSON.stringify({op:1,d:null}))},ms);
   else ws.close(4002,"Invalid heartbeat interval");
  }else if(packet.t==="READY"){
   ready=true;attempt=0;
   ws.send(JSON.stringify({op:42,d:{guild_id:guildId}}));
  }else if(packet.t==="GUILD_SUBSCRIBED"){
   console.log("Subscribed to guild:",packet.d.guild_id);
   void catchUp();
  }else if(packet.t==="MESSAGE_METADATA_CREATE"){
   reportMetadata(packet.d);
  }
 });
 ws.addEventListener("close",event=>{
  if(socket!==ws)return;
  cleanup();socket=null;
  if(stopping)return;
  if(event.code===4004||event.code===4005){
   console.error("Bot authentication rejected; refusing to retry until credentials are fixed.");
   return;
  }
  // Reconnect, resubscribe and recover retained message metadata via REST.
  const delay=Math.min(30000,1000*2**Math.min(attempt++,5));
  console.error("Gateway closed",event.code,ready?"after READY":"before READY","; reconnecting in",delay,"ms");
  retryTimer=setTimeout(()=>{retryTimer=null;connect()},delay);
 });
 ws.addEventListener("error",()=>console.error("Bot Gateway connection error"));
}
function stop(){
 stopping=true;
 if(retryTimer!==null){clearTimeout(retryTimer);retryTimer=null}
 cleanup();
 if(socket){
  const ws=socket;socket=null;
  if(ws.readyState===WebSocket.OPEN)ws.send(JSON.stringify({op:43,d:{guild_id:guildId}}));
  ws.close();
 }
}
process.on("SIGINT",stop);
process.on("SIGTERM",stop);
void loadCursor().then(connect).catch(error=>{console.error("Cursor startup failed:",error.message);process.exitCode=1});
