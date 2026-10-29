// Prototype WebCrypto building blocks. NOT a reviewed group E2EE protocol.
// WebCrypto works only in secure contexts (HTTPS or loopback).
const encoder=new TextEncoder(),decoder=new TextDecoder();
const b64=bytes=>BufferCompat.encode(bytes);
const un64=text=>BufferCompat.decode(text);
const BufferCompat={
 encode(bytes){let s="";for(const byte of new Uint8Array(bytes))s+=String.fromCharCode(byte);return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"")},
 decode(text){if(!/^[A-Za-z0-9_-]+$/.test(text))throw Error("Invalid base64url");const s=atob(text.replace(/-/g,"+").replace(/_/g,"/")+"=".repeat((4-text.length%4)%4));return Uint8Array.from(s,c=>c.charCodeAt(0))}
};
const subtle=globalThis.crypto.subtle;
export async function createDevice(){
 const agreement=await subtle.generateKey({name:"ECDH",namedCurve:"P-256"},true,["deriveBits"]);
 const signing=await subtle.generateKey({name:"ECDSA",namedCurve:"P-256"},true,["sign","verify"]);
 return {agreement,signing};
}
export async function publicBundle(device){
 return {version:1,agreement:await subtle.exportKey("jwk",device.agreement.publicKey),signing:await subtle.exportKey("jwk",device.signing.publicKey)};
}
export async function fingerprint(bundle){
 const canonical=JSON.stringify([bundle.version,bundle.agreement.x,bundle.agreement.y,bundle.signing.x,bundle.signing.y]);
 return b64(await subtle.digest("SHA-256",encoder.encode(canonical)));
}
export async function createRoomKey(){return subtle.generateKey({name:"AES-GCM",length:256},true,["encrypt","decrypt"])}
export async function encryptMessage(key,plaintext,context){
 if(typeof plaintext!=="string"||!context?.room||!context?.sender||!Number.isSafeInteger(context.epoch))throw Error("Invalid context");
 const nonce=crypto.getRandomValues(new Uint8Array(12));
 const aad=encoder.encode(JSON.stringify(["nexora-message-v1",context.room,context.sender,context.epoch]));
 const ciphertext=await subtle.encrypt({name:"AES-GCM",iv:nonce,additionalData:aad,tagLength:128},key,encoder.encode(plaintext));
 return {v:1,nonce:b64(nonce),ciphertext:b64(ciphertext),context};
}
export async function decryptMessage(key,envelope,expectedContext){
 if(envelope?.v!==1||JSON.stringify(envelope.context)!==JSON.stringify(expectedContext))throw Error("Message context mismatch");
 const aad=encoder.encode(JSON.stringify(["nexora-message-v1",expectedContext.room,expectedContext.sender,expectedContext.epoch]));
 const result=await subtle.decrypt({name:"AES-GCM",iv:un64(envelope.nonce),additionalData:aad,tagLength:128},key,un64(envelope.ciphertext));
 return decoder.decode(result);
}
export async function wrapRoomKey(roomKey,device,recipientBundle,context){
 const ephemeral=await subtle.generateKey({name:"ECDH",namedCurve:"P-256"},true,["deriveBits"]);
 const recipient=await subtle.importKey("jwk",recipientBundle.agreement,{name:"ECDH",namedCurve:"P-256"},false,[]);
 const shared=await subtle.deriveBits({name:"ECDH",public:recipient},ephemeral.privateKey,256);
 const salt=crypto.getRandomValues(new Uint8Array(32)),nonce=crypto.getRandomValues(new Uint8Array(12));
 const hkdf=await subtle.importKey("raw",shared,"HKDF",false,["deriveKey"]);
 const wrapping=await subtle.deriveKey({name:"HKDF",hash:"SHA-256",salt,info:encoder.encode("nexora-room-wrap-v1")},hkdf,{name:"AES-GCM",length:256},false,["encrypt"]);
 const payload=await subtle.exportKey("raw",roomKey);
 const ciphertext=await subtle.encrypt({name:"AES-GCM",iv:nonce,additionalData:encoder.encode(JSON.stringify(context))},wrapping,payload);
 const envelope={version:1,ephemeral:await subtle.exportKey("jwk",ephemeral.publicKey),salt:b64(salt),nonce:b64(nonce),ciphertext:b64(ciphertext),context};
 const signed=encoder.encode(JSON.stringify(envelope));
 return {...envelope,signer:await publicBundle(device),signature:b64(await subtle.sign({name:"ECDSA",hash:"SHA-256"},device.signing.privateKey,signed))};
}
export async function unwrapRoomKey(envelope,device,expectedFingerprint,expectedContext){
 if(envelope.version!==1||JSON.stringify(envelope.context)!==JSON.stringify(expectedContext))throw Error("Wrapped key context mismatch");
 if(await fingerprint(envelope.signer)!==expectedFingerprint)throw Error("Sender device identity mismatch");
 const {signature,signer,...signedFields}=envelope;
 const verifyKey=await subtle.importKey("jwk",signer.signing,{name:"ECDSA",namedCurve:"P-256"},false,["verify"]);
 if(!await subtle.verify({name:"ECDSA",hash:"SHA-256"},verifyKey,un64(signature),encoder.encode(JSON.stringify(signedFields))))throw Error("Invalid device signature");
 const ephemeral=await subtle.importKey("jwk",envelope.ephemeral,{name:"ECDH",namedCurve:"P-256"},false,[]);
 const shared=await subtle.deriveBits({name:"ECDH",public:ephemeral},device.agreement.privateKey,256);
 const hkdf=await subtle.importKey("raw",shared,"HKDF",false,["deriveKey"]);
 const key=await subtle.deriveKey({name:"HKDF",hash:"SHA-256",salt:un64(envelope.salt),info:encoder.encode("nexora-room-wrap-v1")},hkdf,{name:"AES-GCM",length:256},false,["decrypt"]);
 const raw=await subtle.decrypt({name:"AES-GCM",iv:un64(envelope.nonce),additionalData:encoder.encode(JSON.stringify(expectedContext))},key,un64(envelope.ciphertext));
 return subtle.importKey("raw",raw,{name:"AES-GCM"},true,["encrypt","decrypt"]);
}
