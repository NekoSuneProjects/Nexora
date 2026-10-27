// Nexora experimental bot Gateway example. Node.js 22+ required.
// Usage: NEXORA_BOT_TOKEN=<your-secret> NEXORA_GUILD_ID=<uuid> node examples/metadata-bot.mjs
// Never commit your bot token or log it.
const token=process.env.NEXORA_BOT_TOKEN;
const guildId=process.env.NEXORA_GUILD_ID;
const url=process.env.NEXORA_GATEWAY_URL||"ws://127.0.0.1:3000/bot-gateway";
if(!token||!guildId){console.error("NEXORA_BOT_TOKEN and NEXORA_GUILD_ID are required");process.exit(1)}
const ws=new WebSocket(url);
let heartbeat=null;
ws.addEventListener("message",event=>{
 let packet;
 try{packet=JSON.parse(event.data)}catch{return}
 if(packet.op===10){
  ws.send(JSON.stringify({op:2,d:{token}}));
  heartbeat=setInterval(()=>{if(ws.readyState===WebSocket.OPEN)ws.send(JSON.stringify({op:1,d:null}))},packet.d.heartbeat_interval);
 }else if(packet.t==="READY"){
  ws.send(JSON.stringify({op:42,d:{guild_id:guildId}}));
 }else if(packet.t==="GUILD_SUBSCRIBED"){
  console.log("Subscribed to guild:",packet.d.guild_id);
 }else if(packet.t==="MESSAGE_METADATA_CREATE"){
  console.log("Message metadata:",packet.d.guild_id,packet.d.channel_id,packet.d.message_id);
 }
});
ws.addEventListener("close",event=>{if(heartbeat)clearInterval(heartbeat);console.error("Bot Gateway closed:",event.code)});
ws.addEventListener("error",()=>console.error("Gateway connection failed"));
process.on("SIGINT",()=>{if(ws.readyState===WebSocket.OPEN)ws.send(JSON.stringify({op:43,d:{guild_id:guildId}}));ws.close()});
