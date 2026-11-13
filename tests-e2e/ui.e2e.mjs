// Browser end-to-end tests: real Chromium, real API, real PostgreSQL.
// Run: DATABASE_URL=... npm run test:e2e   (optionally NEXORA_BROWSER_PATH=/path/to/chrome-or-edge)
// Needs a database with fresh registration quotas (CI uses a dedicated PostgreSQL service).
import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";
import pg from "pg";
import { chromium } from "playwright";

// "localhost", not 127.0.0.1: browsers refuse IP addresses as WebAuthn relying-party IDs.
const port = Number(process.env.E2E_PORT || 3110), base = "http://localhost:" + port;
const PASSWORD = "an e2e test password 1";
let api, browser, log = "";
const consoleErrors = [];
const pages = [], warnings = [];

test.before(async () => {
  api = spawn(process.execPath, ["scripts/start-api.mjs"], { env: { ...process.env, PORT: String(port), HOST: "127.0.0.1", MFA_ENCRYPTION_KEY: "33".repeat(32) }, stdio: "pipe" });
  api.stdout.on("data", (d) => (log += d)); api.stderr.on("data", (d) => (log += d));
  for (let i = 0; ; i++) {
    if (api.exitCode !== null) throw Error("API exited: " + log);
    try { if ((await fetch(base + "/health")).ok) break; } catch {}
    if (i > 120) throw Error("API not ready: " + log);
    await sleep(500);
  }
  browser = await chromium.launch({ headless: true, ...(process.env.NEXORA_BROWSER_PATH ? { executablePath: process.env.NEXORA_BROWSER_PATH } : {}) });
});
// On failure: screenshots in test-results/ plus any visible toasts (uploaded by CI).
async function captureFailure() {
  const { mkdir } = await import("node:fs/promises");
  await mkdir("test-results", { recursive: true });
  if (warnings.length) console.error("client warnings: " + warnings.join(" || "));
  if (consoleErrors.length) console.error("console errors: " + consoleErrors.join(" || "));
  for (const [label, page] of pages) {
    await page.screenshot({ path: `test-results/${label}.png` }).catch(() => {});
    const toasts = await page.locator(".toast").allTextContents().catch(() => []);
    if (toasts.length) console.error(label + " toasts:", toasts.join(" | "));
  }
}
test.after(async () => {
  await browser?.close();
  api?.kill("SIGTERM");
  await Promise.race([new Promise((r) => api?.once("exit", r)), sleep(3000)]);
});

async function newPage(label) {
  const ctx = await browser.newContext({ viewport: { width: 1400, height: 860 } });
  const page = await ctx.newPage();
  pages.push([label, page]);
  page.setDefaultTimeout(20000);
  page.on("console", (m) => { if (m.type() === "error") consoleErrors.push(label + ": " + m.text()); if (m.type() === "warning") warnings.push(label + ": " + m.text()); });
  page.on("pageerror", (e) => consoleErrors.push(label + " pageerror: " + e.message));
  await page.goto(base + "/app");
  return page;
}
async function register(page, name) {
  await page.fill("#username", name); await page.fill("#password", PASSWORD);
  await page.click("#register");
  await page.waitForSelector("#logged-in:not(.hidden)");
}
async function signIn(page, name) {
  await page.fill("#username", name); await page.fill("#password", PASSWORD);
  await page.click("#login-form button[type=submit]");
  await page.waitForSelector("#logged-in:not(.hidden)");
}
async function closeModal(page) { await page.click(".modal nav button:has-text('Close')"); }
async function enroll(page, label) {
  await page.click("#vault-button");
  await page.fill("#device-name", label); await page.fill("#device-proof", PASSWORD); await page.fill("#device-vault-passphrase", "vault passphrase " + label);
  await page.click("#device-enroll-form button[type=submit]");
  await page.waitForFunction(() => document.querySelector("#device-vault-status")?.textContent.includes("Safety number"));
}
const ready = (page) => page.waitForFunction(() => /epoch/.test(document.querySelector("#e2ee-state")?.textContent ?? ""));
async function send(page, text) {
  await page.fill("#chat-plaintext", text); await page.keyboard.press("Enter");
  await page.waitForSelector(`.message:has-text(${JSON.stringify(text)})`);
}
const sees = (page, text) => page.waitForFunction((t) => [...document.querySelectorAll(".msg-body")].some((b) => b.textContent.includes(t)), text);
const msg = (page, text) => page.locator(".message", { hasText: text }).last();

test("two people chat with signed, end-to-end encrypted messages; passkeys, key backup, device approval and moderation work", { timeout: 300000 }, async () => {
  try { await scenario(); } catch (error) { await captureFailure(); throw error; }
});
async function scenario() {
  const sfx = Math.random().toString(36).slice(2, 6), A = "alice_" + sfx, B = "bob_" + sfx;

  // ---- Alice: account, encryption, server, first message (signed by her device)
  const alice = await newPage("alice");
  await register(alice, A);
  await enroll(alice, "alice desktop");
  await closeModal(alice);
  await alice.click("#add-server"); await alice.fill("#guild-name", "E2E Lab"); await alice.click(".modal form button[type=submit]");
  await ready(alice);
  await send(alice, "first secret from alice");
  await alice.waitForSelector(".message:has-text('first secret') .sig-verified");

  // ---- Key backup: turn it on and keep the recovery key
  await alice.click("#vault-button");
  await alice.click("#backup-setup");
  const recoveryKey = await alice.inputValue("#ask-key");
  assert.match(recoveryKey, /^([A-Z2-9]{4}-){7}[A-Z2-9]{4}$/);
  await alice.click(".modal button[type=submit]");
  await alice.waitForFunction(() => /Key backup is on/.test(document.querySelector("#backup-status")?.textContent ?? ""));
  await closeModal(alice);

  // ---- Passkey: register with a virtual authenticator, sign out, sign back in passwordlessly
  const cdp = await alice.context().newCDPSession(alice);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
  await alice.click("#settings-button"); await alice.click(".modal nav button:has-text('Security')");
  await alice.click(".modal button:has-text('Add a passkey')");
  await alice.fill("#ask-password", PASSWORD); await alice.fill("#ask-name", "Virtual key"); await alice.click(".modal button[type=submit]");
  await alice.waitForSelector(".modal .list-row:has-text('Virtual key')");
  await alice.click("#logout");
  await alice.waitForSelector("#logged-out:not(.hidden)");
  await alice.click("#passkey-login");
  await alice.waitForSelector("#logged-in:not(.hidden)");
  await alice.fill("#quick-unlock", "vault passphrase alice desktop"); await alice.click(".modal button[type=submit]");
  await alice.click(".rail-item[title='E2E Lab']");
  await ready(alice);
  await sees(alice, "first secret");

  // ---- Invite Bob; Bob joins and they talk in real time (typing, reactions)
  await alice.click("#guild-menu-button"); await alice.click(".menu button:has-text('Invite people')");
  await alice.click(".modal button[type=submit]");
  const code = await alice.inputValue(".modal input[readonly]");
  await alice.click(".modal button:has-text('Done')");
  const bob = await newPage("bob");
  await register(bob, B);
  await enroll(bob, "bob phone"); await closeModal(bob);
  await bob.click("#add-server"); await bob.fill("#invite-code", code); await bob.click(".modal form:nth-of-type(2) button[type=submit]");
  await ready(bob);
  await send(bob, "hi alice, bob here");
  await sees(alice, "bob here");
  await alice.waitForSelector(".message:has-text('bob here') .sig-verified");
  await send(alice, "welcome bob");
  await sees(bob, "welcome bob");
  await msg(bob, "welcome bob").hover(); await msg(bob, "welcome bob").locator("button[title=React]").click();
  await bob.click(".emoji-grid button:has-text('🎉')");
  await alice.waitForSelector(".reaction:has-text('🎉')");
  await bob.type("#chat-plaintext", "typing");
  await alice.waitForFunction(() => /typing/.test(document.querySelector("#typing")?.textContent ?? ""));
  await bob.fill("#chat-plaintext", "");

  // ---- Alice's second device: restore history from backup, then approve it from the first device
  const laptop = await newPage("alice-laptop");
  await signIn(laptop, A);
  await enroll(laptop, "alice laptop");
  await laptop.waitForSelector("#device-list .list-row:has-text('alice laptop') .pill:has-text('Waiting for approval')");
  await laptop.click("#backup-restore");
  await laptop.fill("#ask-key", recoveryKey.toLowerCase()); await laptop.click(".modal button[type=submit]");
  await laptop.waitForFunction(() => /Key backup is on/.test(document.querySelector("#backup-status")?.textContent ?? ""));
  await closeModal(laptop);
  await laptop.click(".rail-item[title='E2E Lab']");
  await sees(laptop, "first secret"); // history from before this device existed, via the backup
  await alice.click("#vault-button");
  await alice.click("#device-list .list-row:has-text('alice laptop') button:has-text('Approve')");
  await alice.click(".modal button[type=submit]");
  await alice.waitForSelector("#device-list .list-row:has-text('alice laptop') .pill:has-text('Approved')");
  await closeModal(alice);
  await ready(laptop);
  await send(laptop, "hello from the laptop");
  await sees(bob, "hello from the laptop");
  await bob.waitForSelector(".message:has-text('hello from the laptop') .sig-verified");

  // ---- Direct messages between friends
  await bob.click("#home-button");
  await bob.fill(".friends input", A); await bob.click(".friends button[type=submit]");
  await alice.click("#home-button");
  await alice.click(".tabs button:has-text('Pending')"); await alice.click(".friend-row button:has-text('Accept')");
  await alice.click(".tabs button:has-text('All')"); await alice.click(".friend-row button:has-text('Message')");
  await ready(alice);
  await send(alice, "a private dm");
  await bob.click(`.side-item:has-text('${A}')`);
  await sees(bob, "a private dm");

  // ---- Bob reports a message; an instance admin reviews it
  await bob.click(".rail-item[title='E2E Lab']");
  await sees(bob, "welcome bob");
  await msg(bob, "welcome bob").hover(); await msg(bob, "welcome bob").locator("button[title=More]").click();
  await bob.click(".menu button:has-text('Report message')");
  await bob.fill("#ask-reason", "e2e report"); await bob.click(".modal button[type=submit]");
  await bob.waitForSelector(".toast:has-text('Report sent')");
  const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
  await pool.query("UPDATE users SET is_admin=true WHERE username=$1", [A]);
  await pool.end();
  await laptop.reload(); await laptop.waitForSelector("#logged-in:not(.hidden)");
  await laptop.keyboard.press("Escape").catch(() => {});
  await laptop.evaluate(() => document.querySelector(".modal-backdrop")?.remove());
  await laptop.click("#settings-button"); await laptop.click(".modal nav button:has-text('Instance admin')");
  await laptop.waitForSelector(".modal .list-row:has-text('e2e report')");
  await laptop.waitForSelector(".modal pre:has-text('welcome bob')"); // reporter-supplied evidence

  assert.deepEqual(consoleErrors, [], "browser console errors");
}
