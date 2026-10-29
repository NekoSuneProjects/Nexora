// Encrypted local device-key vault. This is NOT a complete group E2EE protocol.
const enc=new TextEncoder(),dec=new TextDecoder();
const encode=b=>{let s="";for(const x of new Uint8Array(b))s+=String.fromCharCode(x);return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"")};
const decode=s=>Uint8Array.from(atob(s.replace(/-/g,"+").replace(/_/g,"/")+"=".repeat((4-s.length%4)%4)),x=>x.charCodeAt(0));
const subtle=globalThis.crypto.subtle;
async function derive(passphrase,salt){const base=await subtle.importKey("raw",enc.encode(passphrase),"PBKDF2",false,["deriveKey"]);return subtle.deriveKey({name:"PBKDF2",hash:"SHA-256",salt,iterations:600000},base,{name:"AES-GCM",length:256},false,["encrypt","decrypt"])}
export async function encryptDeviceVault(device,passphrase){
 if(typeof passphrase!=="string"||passphrase.length<16)throw Error("Use a device vault passphrase of at least 16 characters");
 const data={version:1,agreement:await subtle.exportKey("jwk",device.agreement.privateKey),signing:await subtle.exportKey("jwk",device.signing.privateKey)};
 const salt=crypto.getRandomValues(new Uint8Array(16)),iv=crypto.getRandomValues(new Uint8Array(12));
 const key=await derive(passphrase,salt);
 const encrypted=await subtle.encrypt({name:"AES-GCM",iv,additionalData:enc.encode("nexora-device-vault-v1")},key,enc.encode(JSON.stringify(data)));
 return {version:1,kdf:"PBKDF2-SHA256-600000",cipher:"AES-256-GCM",salt:encode(salt),iv:encode(iv),encrypted:encode(encrypted)};
}
export async function decryptDeviceVault(vault,passphrase){
 if(vault?.version!==1||vault?.kdf!=="PBKDF2-SHA256-600000"||vault?.cipher!=="AES-256-GCM")throw Error("Unsupported device vault");
 const key=await derive(passphrase,decode(vault.salt));
 const raw=await subtle.decrypt({name:"AES-GCM",iv:decode(vault.iv),additionalData:enc.encode("nexora-device-vault-v1")},key,decode(vault.encrypted));
 const data=JSON.parse(dec.decode(raw));if(data.version!==1)throw Error("Invalid device backup");
 const agreement=await subtle.importKey("jwk",data.agreement,{name:"ECDH",namedCurve:"P-256"},true,["deriveBits"]);
 const signing=await subtle.importKey("jwk",data.signing,{name:"ECDSA",namedCurve:"P-256"},true,["sign"]);
 const agreementPublic=await subtle.importKey("jwk",{...data.agreement,d:undefined},{name:"ECDH",namedCurve:"P-256"},true,[]);
 const signingPublic=await subtle.importKey("jwk",{...data.signing,d:undefined},{name:"ECDSA",namedCurve:"P-256"},true,["verify"]);
 return {agreement:{privateKey:agreement,publicKey:agreementPublic},signing:{privateKey:signing,publicKey:signingPublic}};
}
export async function saveDeviceVault(vault){
 if(typeof indexedDB==="undefined")throw Error("IndexedDB unavailable");
 const db=await new Promise((resolve,reject)=>{const q=indexedDB.open("nexora-local-keys",1);q.onupgradeneeded=()=>q.result.createObjectStore("vault");q.onerror=()=>reject(q.error);q.onsuccess=()=>resolve(q.result)});
 try{await new Promise((resolve,reject)=>{const t=db.transaction("vault","readwrite");t.objectStore("vault").put(vault,"active");t.oncomplete=resolve;t.onerror=()=>reject(t.error)})}finally{db.close()}
}
export async function loadDeviceVault(){
 if(typeof indexedDB==="undefined")throw Error("IndexedDB unavailable");
 const db=await new Promise((resolve,reject)=>{const q=indexedDB.open("nexora-local-keys",1);q.onupgradeneeded=()=>q.result.createObjectStore("vault");q.onerror=()=>reject(q.error);q.onsuccess=()=>resolve(q.result)});
 try{return await new Promise((resolve,reject)=>{const t=db.transaction("vault","readonly");const r=t.objectStore("vault").get("active");r.onsuccess=()=>resolve(r.result??null);r.onerror=()=>reject(r.error)})}finally{db.close()}
}
