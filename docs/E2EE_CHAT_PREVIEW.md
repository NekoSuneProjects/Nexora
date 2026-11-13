# E2EE chat (multi-member prototype)

The browser encrypts every message with AES-256-GCM before upload. The associated data binds the
room, the sender and the key epoch. The server stores only ciphertext.

## How keys flow (`apps/web/e2ee.mjs`)

1. **Devices.** Each browser creates ECDH and ECDSA P-256 keys and keeps them in a passphrase-encrypted
   IndexedDB vault (`private-key-vault.mjs`). Enrolling a device requires the account password. The device
   registers its public bundle, and the server checks that the bundle hashes to the registered fingerprint.
2. **Epochs.** Every join or leave bumps the community's key epoch (a database trigger). The server rejects
   messages and edits whose envelope epoch is not current.
3. **Claiming.** The first member device to open a channel in a new epoch generates a room key. It then
   `POST`s `/keys/claim` with an HMAC **key commitment**. Only one claim per channel and epoch can succeed,
   so concurrent members cannot fork the key.
4. **Granting.** A key holder wraps the room key for every member device that lacks it. Each wrap uses
   ephemeral ECDH + HKDF + AES-GCM and is signed by the holder's device. Recipients verify the signature,
   the context, the signer's trust status and the commitment. Grants are signed over canonical JSON,
   because PostgreSQL `jsonb` re-orders keys.
5. **Trust.** Device identities are trusted on first use (TOFU) and pinned per device ID in
   `localStorage`. A changed key is rejected and the user is warned. Users can compare **safety numbers**
   in profiles and mark devices as verified.
6. **New devices.** A device without the current key sends `KEY_REQUEST`. Online holders then
   distribute the key automatically.
7. **History.** Members keep grants for earlier epochs they belonged to. People who join later cannot
   decrypt messages from before they joined.

## Known limitations (do not use for sensitive conversations)

- This is not MLS. There is no forward secrecy or post-compromise security within an epoch.
- Messages are signed by the sender's device, and new devices must be approved by an existing device of
  the same account (cross-signing). An account's *first* device is still trusted on first use, and there is
  no key transparency log.
- Key backup uses a user-held recovery key. Losing every device *and* the recovery key means losing history.
- Revoking a device stops future grants to it, but does not take back keys it already holds.
- Reactions, pins, timestamps, membership and who-talks-to-whom are visible to the server.
- Nothing here has been reviewed independently. See TODO.md (P0) and `docs/THREAT_MODEL.md`.
