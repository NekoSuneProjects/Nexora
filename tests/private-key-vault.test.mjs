import test from "node:test";import assert from "node:assert/strict";
import {createDevice,fingerprint,publicBundle} from "../apps/web/crypto.mjs";
import {encryptDeviceVault,decryptDeviceVault} from "../apps/web/private-key-vault.mjs";
test("device vault survives encryption and denies incorrect passphrase",async()=>{
 const device=await createDevice();
 const fp=await fingerprint(await publicBundle(device));
 const vault=await encryptDeviceVault(device,"strong local passphrase that I remember");
 assert.equal(vault.cipher,"AES-256-GCM");
 assert.equal(JSON.stringify(vault).includes('"d"'),false);
 await assert.rejects(()=>decryptDeviceVault(vault,"different local passphrase"));
 const restored=await decryptDeviceVault(vault,"strong local passphrase that I remember");
 assert.equal(await fingerprint(await publicBundle(restored)),fp);
});
