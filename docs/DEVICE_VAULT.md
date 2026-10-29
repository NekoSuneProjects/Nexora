# Encrypted local device-key vault (prototype)

The module `apps/web/private-key-vault.mjs` encrypts the client's ECDH and signing private keys using a locally supplied passphrase, PBKDF2-SHA256 (600,000 iterations), authenticated AES-256-GCM, and independent random salt and nonce. The encrypted vault can be persisted in browser IndexedDB; unlocking occurs locally.

The passphrase is not sent to Nexora and must not be reused as the account password. Losing the passphrase means losing these device keys. An attacker executing JavaScript in the origin (XSS), or controlling the browser while unlocked, may still access keys; implement strict CSP, key transparency and controlled device enrollment.

**Not yet wired into chat messaging.** No trusted group-key distribution, verified device fingerprint UI, epoch rotation, recovery across devices or independently reviewed E2EE exists. This module is a tested storage building block, not a security claim.
