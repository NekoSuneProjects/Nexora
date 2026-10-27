// Experimental Nexora metadata bot (Node.js 22+). Never log or commit credentials.
// NEXORA_BOT_TOKEN=... NEXORA_GUILD_ID=... node examples/metadata-bot.mjs
const token=process.env.NEXORA_BOT_TOKEN;
const guildId=process.env.NEXORA_GUILD_ID;
const url=process.env.NEXORA_GATEWAY_URL||"ws://127.0.0.1:3000/bot-gateway";
if(!token||!/^[a-f0-9]{64}$/.test(token)||!guildId){
 console.error("Provide NEXORA_BOT_TOKEN (64 hex chars) and NEXORA_GUILD_ID");
 process.exit(1);
}
let socket=null,heartbeat=null,retryTimer=null,attempt=0,stopping=false;
function cleanup(){
 if(heartbeat!==null){clearInterval(heartbeat);heartbeat=null}
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
  }else if(packet.t==="MESSAGE_METADATA_CREATE"){
   console.log("Message metadata:",packet.d.guild_id,packet.d.channel_id,packet.d.message_id);
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
  // Reconnect and resubscribe; this experimental Gateway does not replay missed events.
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
connect();
