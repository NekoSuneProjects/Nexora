import {createDevice,publicBundle,fingerprint,createRoomKey,encryptMessage,decryptMessage,wrapRoomKey,unwrapRoomKey} from "/crypto.mjs";
import {encryptDeviceVault,decryptDeviceVault,saveDeviceVault,loadDeviceVault} from "/private-key-vault.mjs";
const $ = id => document.getElementById(id);
let token = null, currentGuild = null, currentChannel = null, currentGuildOwner = false, selfId = null;
let ws = null, heartbeat = null;
let unlockedDevice=null,roomKeys=new Map();
async function prepareRoomKey(channelId){
 if(!unlockedDevice)throw Error("Unlock your encrypted device vault first.");
 const state=await request("/api/v1/channels/"+encodeURIComponent(channelId)+"/keys");
 const cached=roomKeys.get(channelId);
 if(cached?.epoch===state.epoch)return cached;
 const bundle=await publicBundle(unlockedDevice),own=await fingerprint(bundle);
 const registered=state.recipients.find(x=>x.user_id===selfId&&x.identity_key===own);
 if(!registered)throw Error("This device is not registered for your account.");
 const existing=state.wrapped.find(x=>x.device_id===registered.id);
 let key;
 const context={room:channelId,epoch:state.epoch,recipient:registered.id};
 if(existing)key=await unwrapRoomKey(existing.wrapped_key,unlockedDevice,own,context);
 else {
  if(state.wrapped.length)throw Error("A room key exists but this device has no verified grant. Ask an existing trusted device.");
  if(state.recipients.length!==1)throw Error("Multi-device room onboarding requires verified key exchange and is disabled.");
  key=await createRoomKey();
  const envelope=await wrapRoomKey(key,unlockedDevice,bundle,context);
  await request("/api/v1/channels/"+encodeURIComponent(channelId)+"/keys/"+registered.id,"PUT",{epoch:state.epoch,wrapped_key:envelope});
 }
 const value={epoch:state.epoch,key};roomKeys.set(channelId,value);return value;
}

function status(message){ $("status").textContent = message; }
function node(tag, text){ const n=document.createElement(tag); n.textContent=text; return n; }
async function request(path, method="GET", body){
  const res=await fetch(path,{method,headers:{...(body!==undefined?{"Content-Type":"application/json"}:{}),...(token?{Authorization:"Bearer "+token}:{})},...(body?{body:JSON.stringify(body)}:{})});
  if(!res.ok){let error;try{error=await res.json()}catch{};throw new Error(error?.message||error?.error||"HTTP "+res.status)}
  return res.status===204?null:res.json();
}
async function signedIn(){
  const me=await request("/api/v10/users/@me"); $("user").textContent=me.username;selfId=me.id;
  $("logged-out").classList.add("hidden");$("logged-in").classList.remove("hidden");
  await loadGuilds();await loadProfile();await loadSessions();connectGateway();
}
async function loadGuilds(){
  const guilds=await request("/api/v10/users/@me/guilds");
  $("guilds").replaceChildren();
  for(const guild of guilds){
    const button=node("button",guild.name);button.type="button";
    if(guild.id===currentGuild)button.classList.add("selected");
    button.onclick=()=>run(()=>openGuild(guild.id));$("guilds").append(button);
  }
  const active=guilds.find(g=>g.id===currentGuild);currentGuildOwner=!!active && active.owner_id===selfId;
  $("create-channel").classList.toggle("hidden",!currentGuildOwner);
  if(currentGuild && !active)currentGuild=null;
}
async function openGuild(id){
  currentGuild=id;currentChannel=null;$("messages").replaceChildren();$("channel-title").textContent="Select a channel";
  await loadGuilds();await loadMembers();
  const channels=await request("/api/v10/guilds/"+encodeURIComponent(id)+"/channels");
  $("channels").replaceChildren();
  for(const channel of channels){
    const button=node("button","# "+channel.name);button.type="button";
    button.onclick=()=>run(()=>openChannel(channel));$("channels").append(button);
    if(currentGuildOwner){const rename=node("button","Rename");rename.type="button";rename.onclick=()=>run(async()=>{const name=prompt("New channel name",channel.name);if(name===null)return;await request("/api/v1/channels/"+encodeURIComponent(channel.id),"PATCH",{name});await openGuild(currentGuild)});$("channels").append(rename)}
  }
}
async function openChannel(channel){
  if(ws?.readyState===1 && currentChannel)ws.send(JSON.stringify({op:43,d:{channel_id:currentChannel}}));
  currentChannel=channel.id;$("channel-title").textContent="# "+channel.name;
  if(ws?.readyState===1)ws.send(JSON.stringify({op:42,d:{channel_id:currentChannel}}));
  const messages=await request("/api/v10/channels/"+encodeURIComponent(channel.id)+"/messages");
  const parent=$("messages");parent.replaceChildren();
  if(!messages.length)parent.append(node("p","No encrypted message envelopes yet."));
  for(const m of messages){const entry=document.createElement("article");
    entry.append(node("strong","Author "+m.author_id),node("p","Encrypted envelope ("+m.algorithm+")"));
    try {
      const envelope=JSON.parse(m.ciphertext);
      const state=await prepareRoomKey(channel.id);
      if(state.epoch!==envelope.context?.epoch)throw Error("Older epoch or untrusted device");
      const text=await decryptMessage(state.key,envelope,{room:channel.id,sender:m.author_id,epoch:state.epoch});
      entry.append(node("p",text));
    }catch{entry.append(node("code","Encrypted message – unlock trusted device or obtain correct epoch key."))}
    parent.append(entry);
  }
}
$("send-encrypted-form").addEventListener("submit",event=>{event.preventDefault();run(async()=>{
 if(!currentChannel)throw Error("Select a channel");
 const state=await prepareRoomKey(currentChannel);
 const plaintext=$("chat-plaintext").value;if(!plaintext.trim())return;
 const envelope=await encryptMessage(state.key,plaintext,{room:currentChannel,sender:selfId,epoch:state.epoch});
 await request("/api/v10/channels/"+encodeURIComponent(currentChannel)+"/messages","POST",{algorithm:"client-encrypted-v1",ciphertext:JSON.stringify(envelope)});
 $("chat-plaintext").value="";
 const current=await request("/api/v10/guilds/"+encodeURIComponent(currentGuild)+"/channels");
 const target=current.find(x=>x.id===currentChannel);if(target)await openChannel(target);
})});
async function run(task){try{status("");await task()}catch(e){status(e.message)}}
$("login-form").addEventListener("submit",e=>{e.preventDefault();run(async()=>{
  const result=await request("/api/v1/auth/login","POST",{username:$("username").value,password:$("password").value,...($("mfa-code").value?{mfa_code:$("mfa-code").value}:{}),...($("recovery-code").value?{recovery_code:$("recovery-code").value.trim()}:{})});
  token=result.token;$("password").value="";$("mfa-code").value="";$("recovery-code").value="";await signedIn();
})});
$("register").addEventListener("click",()=>run(async()=>{
  await request("/api/v1/auth/register","POST",{username:$("username").value,password:$("password").value});
  status("Account created. You can now sign in.");
}));
$("create-guild").addEventListener("submit",e=>{e.preventDefault();run(async()=>{
  const guild=await request("/api/v10/guilds","POST",{name:$("guild-name").value});
  $("guild-name").value="";await openGuild(guild.id);
})});
$("logout").addEventListener("click",()=>run(async()=>{
  try{await request("/api/v1/auth/logout","POST")}finally{
    token=null;currentGuild=null;currentChannel=null;unlockedDevice=null;roomKeys.clear();
    $("logged-in").classList.add("hidden");$("logged-out").classList.remove("hidden");status("Signed out.");
  }
}));

async function loadProfile(){
  const profile=await request("/api/v1/profiles/@me");
  $("display-name").value=profile.display_name;
  $("bio").value=profile.bio;
  $("social-links").replaceChildren();
  for(const link of profile.social_links){
    const row=document.createElement("p");
    const anchor=node("a",link.provider+" (unverified)");
    anchor.href=link.url;anchor.target="_blank";anchor.rel="noopener noreferrer";
    const remove=node("button","Remove");remove.type="button";
    remove.onclick=()=>run(async()=>{await request("/api/v1/profiles/@me/links/"+link.provider,"DELETE");await loadProfile()});
    row.append(anchor," ",remove);$("social-links").append(row);
  }
}
$("profile-form").addEventListener("submit",e=>{e.preventDefault();run(async()=>{
  await request("/api/v1/profiles/@me","PUT",{display_name:$("display-name").value,bio:$("bio").value});
  status("Profile saved.");
})});
$("social-form").addEventListener("submit",e=>{e.preventDefault();run(async()=>{
  await request("/api/v1/profiles/@me/links","PUT",{provider:$("provider").value,url:$("social-url").value});
  $("social-url").value="";await loadProfile();status("Unverified link saved.");
})});

$("make-invite").addEventListener("click",()=>run(async()=>{
  if(!currentGuild)throw new Error("Select a community first");
  const result=await request("/api/v1/guilds/"+encodeURIComponent(currentGuild)+"/invites","POST",{max_uses:10,expires_hours:24});
  $("invite-result").textContent="Invite code (copy now): "+result.code+" — expires "+new Date(result.expires_at).toLocaleString();
}));
$("join-form").addEventListener("submit",e=>{e.preventDefault();run(async()=>{
  const result=await request("/api/v1/invites/"+encodeURIComponent($("invite-code").value.trim())+"/join","POST");
  $("invite-code").value="";
  await openGuild(result.guild_id);status(result.already_member?"Already a member.":"Joined community.");
})});

$("create-channel").addEventListener("submit",e=>{e.preventDefault();run(async()=>{
 if(!currentGuild)throw new Error("Select a community first.");
 const channel=await request("/api/v1/guilds/"+encodeURIComponent(currentGuild)+"/channels","POST",{name:$("channel-name").value});
 $("channel-name").value="";await openGuild(currentGuild);await openChannel(channel);status("Channel created.");
})});

async function loadSessions(){
 const sessions=await request("/api/v1/auth/sessions");
 $("session-count").textContent=sessions.length+" active session(s).";
}
$("logout-all").addEventListener("click",()=>run(async()=>{
 await request("/api/v1/auth/logout-all","POST");
 token=null;currentGuild=null;currentChannel=null;
 $("logged-in").classList.add("hidden");$("logged-out").classList.remove("hidden");
 status("All sessions revoked. Please sign in again.");
}));

function disconnectGateway(){
 if(heartbeat){clearInterval(heartbeat);heartbeat=null}
 if(ws){const old=ws;ws=null;old.close()}
}
async function connectGateway(){
 disconnectGateway();
 const discovered=await request("/api/v10/gateway");
 const socket=new WebSocket(discovered.url);
 ws=socket;
 socket.onmessage=event=>{
   if(ws!==socket)return;
   let packet;try{packet=JSON.parse(event.data)}catch{return}
   if(packet.op===10){
     socket.send(JSON.stringify({op:2,d:{token}}));
     heartbeat=setInterval(()=>{if(socket.readyState===1)socket.send(JSON.stringify({op:1,d:null}))},packet.d.heartbeat_interval);
   }else if(packet.t==="READY"){
     if(currentChannel)socket.send(JSON.stringify({op:42,d:{channel_id:currentChannel}}));
     status("Real-time Gateway connected.");
   }else if(packet.t==="MESSAGE_CREATE" && packet.d?.channel_id===currentChannel){
     // Only opaque ciphertext is rendered, never interpreted as plaintext.
     run(async()=>{const selected=currentChannel;const channels=await request("/api/v10/guilds/"+encodeURIComponent(currentGuild)+"/channels");const channel=channels.find(c=>c.id===selected);if(channel)await openChannel(channel)});
   }
 };
 socket.onclose=()=>{if(ws!==socket)return;if(heartbeat){clearInterval(heartbeat);heartbeat=null}status("Gateway disconnected. Refresh to reconnect.")};
}

$("device-enroll-form").addEventListener("submit",event=>{event.preventDefault();run(async()=>{
  if(await loadDeviceVault())throw new Error("Local device vault already exists. Export/recover it before replacing this device.");
  const proof=$("device-proof").value,passphrase=$("device-vault-passphrase").value;
  if(passphrase.length<16)throw new Error("Use a vault passphrase of at least 16 characters.");
  const device=await createDevice(),bundle=await publicBundle(device),id=await fingerprint(bundle);
  const vault=await encryptDeviceVault(device,passphrase);
  await request("/api/v1/devices","POST",{name:$("device-name").value,identity_key:id,password:proof});
  await saveDeviceVault(vault);
  $("device-proof").value="";$("device-vault-passphrase").value="";
  $("device-vault-status").textContent="Encrypted local device saved. Public-key fingerprint: "+id+" (verify out of band before trusting another device).";
})});
$("device-unlock-form").addEventListener("submit",event=>{event.preventDefault();run(async()=>{
  const vault=await loadDeviceVault();if(!vault)throw new Error("No local device vault found.");
  const device=await decryptDeviceVault(vault,$("device-unlock-passphrase").value);
  unlockedDevice=device;roomKeys.clear();
  $("device-unlock-passphrase").value="";
  const id=await fingerprint(await publicBundle(device));
  $("device-vault-status").textContent="Local private keys verified. Fingerprint: "+id;
})});
$("logout").addEventListener("click",disconnectGateway);
$("logout-all").addEventListener("click",disconnectGateway);

async function loadMembers(){
 if(!currentGuild)return;
 const members=await request("/api/v1/guilds/"+encodeURIComponent(currentGuild)+"/members");
 $("members").replaceChildren();
 for(const person of members){
   const row=document.createElement("p");row.append(node("span",person.username+" "));
   if(currentGuildOwner && person.id!==selfId){
     const remove=node("button","Remove");remove.type="button";
     remove.onclick=()=>run(async()=>{
       if(!confirm("Remove "+person.username+" from this community?"))return;
       await request("/api/v1/guilds/"+encodeURIComponent(currentGuild)+"/members/"+encodeURIComponent(person.id),"DELETE");
       await loadMembers();status("Member removed.");
     });
     row.append(remove);
   }
   $("members").append(row);
 }
}
