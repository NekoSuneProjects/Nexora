const {app,BrowserWindow,ipcMain,shell,session}=require("electron");
const fs=require("node:fs");const path=require("node:path");
let window;
const configFile=()=>path.join(app.getPath("userData"),"settings.json");
function validate(input){
 const url=new URL(String(input||"").trim());
 if(!["https:","http:"].includes(url.protocol)||url.username||url.password||url.hash||url.search)throw Error("Use an HTTP(S) Nexora frontend URL without credentials or query parameters.");
 if(url.protocol==="http:"&&!["localhost","127.0.0.1","[::1]"].includes(url.hostname))throw Error("Remote Nexora servers must use HTTPS.");
 return url.origin;
}
function stored(){try{return validate(JSON.parse(fs.readFileSync(configFile(),"utf8")).frontendUrl)}catch{return null}}
function show(){
 const target=stored();
 if(target){window.loadURL(target)}else{window.loadFile(path.join(__dirname,"setup.html"))}
}
app.whenReady().then(()=>{
 ipcMain.handle("nexora:configure",async(_event,url)=>{
  const value=validate(url);fs.mkdirSync(path.dirname(configFile()),{recursive:true});
  fs.writeFileSync(configFile(),JSON.stringify({frontendUrl:value}),{mode:0o600});
  show();return value;
 });
 ipcMain.handle("nexora:settings",()=>stored());
 ipcMain.handle("nexora:reset",()=>{try{fs.unlinkSync(configFile())}catch{}show()});
 window=new BrowserWindow({width:1280,height:820,minWidth:760,minHeight:520,
  webPreferences:{nodeIntegration:false,contextIsolation:true,sandbox:true,preload:path.join(__dirname,"preload.cjs")}});
 window.webContents.setWindowOpenHandler(({url})=>{if(url.startsWith("https://"))shell.openExternal(url);return{action:"deny"}});
 window.webContents.on("will-navigate",(event,url)=>{
  const permitted=stored();
  if(permitted&&new URL(url).origin===permitted)return;
  if(!permitted&&url.startsWith("file:"))return;
  event.preventDefault();
 });
 show();
 app.on("activate",()=>{if(BrowserWindow.getAllWindows().length===0)show()});
});
app.on("window-all-closed",()=>{if(process.platform!=="darwin")app.quit()});
