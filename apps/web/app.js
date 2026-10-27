const $ = id => document.getElementById(id);
let token = null, currentGuild = null, currentChannel = null, currentGuildOwner = false, selfId = null;
let ws = null, heartbeat = null;
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
    entry.append(node("code",String(m.ciphertext).slice(0,120)+"…"));parent.append(entry);
  }
}
async function run(task){try{status("");await task()}catch(e){status(e.message)}}
$("login-form").addEventListener("submit",e=>{e.preventDefault();run(async()=>{
  const result=await request("/api/v1/auth/login","POST",{username:$("username").value,password:$("password").value});
  token=result.token;$("password").value="";await signedIn();
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
    token=null;currentGuild=null;currentChannel=null;
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
