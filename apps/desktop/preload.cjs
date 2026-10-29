const {contextBridge,ipcRenderer}=require("electron");
contextBridge.exposeInMainWorld("nexoraDesktop",Object.freeze({
 configure:url=>ipcRenderer.invoke("nexora:configure",url),
 configuredUrl:()=>ipcRenderer.invoke("nexora:settings"),
 reset:()=>ipcRenderer.invoke("nexora:reset")
}));
