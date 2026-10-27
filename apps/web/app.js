const $ = id => document.getElementById(id);
let token = null, currentGuild = null, currentChannel = null;
function status(message){ $("status").textContent = message; }
function node(tag, text){ const n=document.createElement(tag); n.textContent=text; return n; }
async function request(path, method="GET", body){
  const res=await fetch(path,{method,headers:{"Content-Type":"application/json",...(token?{Authorization:"Bearer "+token}:{})},...(body?{body:JSON.stringify(body)}:{})});
  if(!res.ok){let error;try{error=await res.json()}catch{};throw new Error(error?.message||error?.error||"HTTP "+res.status)}
  return res.status===204?null:res.json();
}
async function signedIn(){
  const me=await request("/api/v10/users/@me"); $("user").textContent=me.username;
  $("logged-out").classList.add("hidden");$("logged-in").classList.remove("hidden");
  await loadGuilds();
}
async function loadGuilds(){
  const guilds=await request("/api/v10/users/@me/guilds");
  $("guilds").replaceChildren();
  for(const guild of guilds){
    const button=node("button",guild.name);button.type="button";
    if(guild.id===currentGuild)button.classList.add("selected");
    button.onclick=()=>run(()=>openGuild(guild.id));$("guilds").append(button);
  }
  if(currentGuild && !guilds.some(g=>g.id===currentGuild))currentGuild=null;
}
async function openGuild(id){
  currentGuild=id;currentChannel=null;$("messages").replaceChildren();$("channel-title").textContent="Select a channel";
  await loadGuilds();
  const channels=await request("/api/v10/guilds/"+encodeURIComponent(id)+"/channels");
  $("channels").replaceChildren();
  for(const channel of channels){
    const button=node("button","# "+channel.name);button.type="button";
    button.onclick=()=>run(()=>openChannel(channel));$("channels").append(button);
  }
}
async function openChannel(channel){
  currentChannel=channel.id;$("channel-title").textContent="# "+channel.name;
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
