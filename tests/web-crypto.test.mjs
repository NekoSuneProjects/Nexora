import test from "node:test";import assert from "node:assert/strict";const {createDevice,publicBundle,fingerprint,createRoomKey,encryptMessage,decryptMessage,wrapRoomKey,unwrapRoomKey}=await import("../apps/web/crypto.mjs");
test("devices exchange an authenticated room key and messages bind room sender epoch",async()=>{
 const alice=await createDevice(),bob=await createDevice();const bundle=await publicBundle(bob);
 const key=await createRoomKey();const context={room:"room-1",epoch:1,sender:"alice"};
 const wrapped=await wrapRoomKey(key,alice,bundle,context);
 const unwrapped=await unwrapRoomKey(wrapped,bob,await fingerprint(await publicBundle(alice)),context);
 const envelope=await encryptMessage(key,"private hello",context);
 assert.equal(await decryptMessage(unwrapped,envelope,context),"private hello");
 await assert.rejects(decryptMessage(unwrapped,envelope,{...context,epoch:2}));
 const tampered={...wrapped,nonce:wrapped.nonce.slice(1)+"a"};
 await assert.rejects(unwrapRoomKey(tampered,bob,await fingerprint(await publicBundle(alice)),context));
 await assert.rejects(unwrapRoomKey(wrapped,bob,await fingerprint(bundle),context));
});
