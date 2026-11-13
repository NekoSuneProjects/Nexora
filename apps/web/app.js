// Nexora web client. Every message is encrypted in this browser (crypto.mjs + e2ee.mjs)
// before upload; untrusted strings are only ever rendered with textContent / DOM nodes.
import { createDevice, publicBundle, fingerprint, encryptMessage, decryptMessage } from "/crypto.mjs";
import { encryptDeviceVault, decryptDeviceVault, saveDeviceVault, loadDeviceVault } from "/private-key-vault.mjs";
import { createKeyring, TrustStore, safetyNumber, signEnvelope, attestDevice, evaluateDevices, generateRecoveryKey, normalizeRecoveryKey, encryptBackup, decryptBackup, sealForDevice, openForDevice } from "/e2ee.mjs";

const $ = (id) => document.getElementById(id);
/** Safe element builder: text is always assigned via textContent. */
function h(tag, props = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props ?? {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "text") el.textContent = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k === "style") Object.assign(el.style, v);
    else if (k in el && k !== "list") el[k] = v;
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  for (const child of children.flat(Infinity)) if (child !== null && child !== undefined && child !== false) el.append(child instanceof Node ? child : String(child));
  return el;
}

/** replaceChildren that skips null/false placeholders (replaceChildren would print "null"). */
const realKids = (kids) => kids.flat(Infinity).filter((k) => k !== null && k !== undefined && k !== false);
function fill(el, ...kids) { el.replaceChildren(...realKids(kids)); }
/** append() that flattens arrays (Element.append would print "[object HTMLDivElement]"). */
function add(el, ...kids) { el.append(...realKids(kids)); }
const swatchColor = (color) => (color ? "#" + color.toString(16).padStart(6, "0") : "#5f7186");

// ------------------------------------------------------------------ permissions
const PERMS = [
  ["ADMINISTRATOR", 0n, "Administrator (all permissions)"], ["MANAGE_GUILD", 1n, "Manage server"], ["MANAGE_ROLES", 2n, "Manage roles"],
  ["MANAGE_CHANNELS", 3n, "Manage channels"], ["KICK_MEMBERS", 4n, "Kick members"], ["BAN_MEMBERS", 5n, "Ban members"],
  ["CREATE_INVITE", 6n, "Create invites"], ["MANAGE_NICKNAMES", 7n, "Manage nicknames"], ["CHANGE_NICKNAME", 8n, "Change own nickname"],
  ["MANAGE_MESSAGES", 9n, "Manage messages & pins"], ["SEND_MESSAGES", 10n, "Send messages"], ["ADD_REACTIONS", 11n, "Add reactions"],
  ["VIEW_AUDIT_LOG", 12n, "View audit log"], ["MANAGE_BOTS", 13n, "Manage bots"], ["MENTION_EVERYONE", 14n, "Mention everyone"],
].map(([name, bit, label]) => ({ name, bit: 1n << bit, label }));
const P = Object.fromEntries(PERMS.map((p) => [p.name, p.bit]));
const can = (perm) => { const g = S.guild; if (!g) return false; const mine = BigInt(g.permissions ?? "0"); return (mine & P.ADMINISTRATOR) !== 0n || (mine & perm) === perm; };

// ------------------------------------------------------------------ state
const S = {
  token: null, me: null, settings: { status: "online", custom_status: "" },
  guilds: [], dms: [], relationships: [], readStates: new Map(),
  view: "home", guildId: null, guild: null, channels: [], channelId: null, members: [], roles: [],
  messages: [], hasMore: false, replyTo: null, editing: null, typing: new Map(), friendsTab: "online",
  device: null, ws: null, heartbeat: null, reconnectDelay: 1000, subscribed: new Set(), lastTypingSent: 0, showMembers: true,
};
let token = null, currentGuild = null, currentChannel = null, selfId = null; // kept for readability in handlers
let unlockedDevice = null;
const trust = new TrustStore(globalThis.localStorage);
const keyring = createKeyring({ request, getDevice: () => unlockedDevice, selfId: () => selfId, trust, onWarning: (w) => toast(w, true), onNewKey: () => scheduleBackup() });
let requestedRoute = null;
const deepLink = /^\/app\/channels\/([a-f0-9-]{36})\/([a-f0-9-]{36})$/i.exec(location.pathname);
if (deepLink) requestedRoute = { guild: deepLink[1], channel: deepLink[2] };

// ------------------------------------------------------------------ utilities
function status(message) { $("status").textContent = message; }
function toast(message, error = false) {
  const t = h("div", { class: "toast" + (error ? " error" : ""), text: message });
  $("toasts").append(t);
  setTimeout(() => t.remove(), error ? 7000 : 3500);
}
async function run(task) { try { status(""); return await task(); } catch (e) { console.warn("Nexora:", e.message); toast(e.message, true); } }
async function request(path, method = "GET", body) {
  const res = await fetch(path, { method, headers: { ...(body !== undefined ? { "Content-Type": "application/json" } : {}), ...(token ? { Authorization: "Bearer " + token } : {}) }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
  if (res.status === 401 && token && !path.startsWith("/api/v1/auth/")) { signedOut("Your session ended. Please sign in again."); throw new Error("Session expired"); }
  if (!res.ok) { let error; try { error = await res.json(); } catch {} throw new Error(error?.message || error?.error || "HTTP " + res.status); }
  return res.status === 204 ? null : res.json();
}
const enc = encodeURIComponent;
function hue(text) { let x = 0; for (const c of String(text)) x = (x * 31 + c.charCodeAt(0)) >>> 0; return x % 360; }
function avatar(name, presence, large = false) {
  const el = h("div", { class: "avatar" + (large ? " large" : ""), text: String(name || "?").slice(0, 1).toUpperCase(), style: { background: `hsl(${hue(name)} 55% 68%)` } });
  if (presence) el.append(h("span", { class: "dot " + presence }));
  return el;
}
const presenceLabel = { online: "Online", idle: "Idle", dnd: "Do not disturb", invisible: "Invisible", offline: "Offline" };
function fmtTime(iso) {
  const d = new Date(iso), now = new Date();
  const time = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  if (d.toDateString() === now.toDateString()) return "Today at " + time;
  const y = new Date(now); y.setDate(now.getDate() - 1);
  if (d.toDateString() === y.toDateString()) return "Yesterday at " + time;
  return d.toLocaleDateString() + " " + time;
}
const EMOJI = "👍 👎 ❤️ 😂 😮 😢 😡 🎉 🔥 👀 ✅ ❌ 🙏 💯 🚀 🤔 😎 🥳 😅 🙌 👏 💜 💚 💙 ⭐ 🍕 ☕ 🎮 🎵 📌 ⚠️ 🐱".split(" ");
function displayName(userId) {
  const m = S.members.find((x) => x.id === userId);
  if (m) return m.nickname || m.display_name || m.username;
  for (const dm of S.dms) { const r = dm.recipients.find((x) => x.id === userId); if (r) return r.display_name || r.username; }
  if (userId === selfId) return S.me?.username;
  return null;
}
function roleColor(userId) {
  const m = S.members.find((x) => x.id === userId);
  if (!m) return null;
  const role = S.roles.filter((r) => m.roles.includes(r.id) && r.color).sort((a, b) => b.position - a.position)[0];
  return role ? "#" + role.color.toString(16).padStart(6, "0") : null;
}

/** Minimal, safe markdown: ```code```, `code`, **bold**, *italic*, ~~strike~~, links, @mentions. */
function renderMarkdown(text) {
  const frag = document.createDocumentFragment();
  const parts = String(text).split(/```/);
  parts.forEach((part, i) => {
    if (i % 2 === 1) { frag.append(h("pre", { text: part.replace(/^\w*\n/, "") })); return; }
    const re = /(`[^`\n]+`)|(\*\*[^*\n]+\*\*)|(\*[^*\n]+\*)|(~~[^~\n]+~~)|(https?:\/\/[^\s<>"]+)|(@[A-Za-z0-9_]{3,32})/g;
    let last = 0, m;
    while ((m = re.exec(part))) {
      if (m.index > last) frag.append(part.slice(last, m.index));
      const t = m[0];
      if (m[1]) frag.append(h("code", { text: t.slice(1, -1) }));
      else if (m[2]) frag.append(h("strong", { text: t.slice(2, -2) }));
      else if (m[3]) frag.append(h("em", { text: t.slice(1, -1) }));
      else if (m[4]) frag.append(h("s", { text: t.slice(2, -2) }));
      else if (m[5]) frag.append(h("a", { href: t, text: t, target: "_blank", rel: "noopener noreferrer" }));
      else frag.append(h("span", { class: "mention-chip", text: t }));
      last = m.index + t.length;
    }
    if (last < part.length) frag.append(part.slice(last));
  });
  return frag;
}

// ------------------------------------------------------------------ modal & menus
function closeModal() { restoreTemplates(); document.querySelector(".modal-backdrop")?.remove(); }
function modal(content, { wide = false } = {}) {
  closeModal();
  const box = h("div", { class: "modal" + (wide ? " wide" : "") }, content);
  const backdrop = h("div", { class: "modal-backdrop", onmousedown: (e) => { if (e.target === backdrop) closeModal(); } }, box);
  document.body.append(backdrop);
  box.querySelector("input,textarea,select")?.focus();
  return box;
}
/** Form dialog. Resolves to field values or null when cancelled. */
function ask({ title, text, fields = [], submit = "Save", danger = false }) {
  return new Promise((resolve) => {
    const inputs = {};
    const form = h("form", {}, h("h2", { text: title }), text ? h("p", { class: "muted", text }) : null,
      fields.map((f) => {
        let input;
        if (f.type === "select") input = h("select", { id: "ask-" + f.name }, f.options.map(([v, l]) => h("option", { value: v, text: l, selected: v === f.value })));
        else if (f.type === "textarea") input = h("textarea", { id: "ask-" + f.name, value: f.value ?? "", rows: 3, maxLength: f.max ?? 1000 });
        else if (f.type === "checkbox") input = h("input", { id: "ask-" + f.name, type: "checkbox", checked: !!f.value, style: { width: "auto" } });
        else input = h("input", { id: "ask-" + f.name, type: f.type ?? "text", value: f.value ?? "", placeholder: f.placeholder ?? "", required: !!f.required, maxLength: f.max ?? 200, ...(f.min ? { minLength: f.min } : {}), ...(f.pattern ? { pattern: f.pattern } : {}), autocomplete: f.type === "password" ? "current-password" : "off" });
        inputs[f.name] = input;
        return [h("label", { htmlFor: "ask-" + f.name, text: f.label }), input];
      }),
      h("div", { class: "actions" }, h("button", { type: "button", class: "secondary", text: "Cancel", onclick: () => { closeModal(); resolve(null); } }), h("button", { type: "submit", class: danger ? "danger" : "", text: submit })));
    form.addEventListener("submit", (e) => { e.preventDefault(); const out = {}; for (const [k, el] of Object.entries(inputs)) out[k] = el.type === "checkbox" ? el.checked : el.value; closeModal(); resolve(out); });
    modal(form);
  });
}
const confirmModal = async (title, text, submit = "Confirm") => (await ask({ title, text, submit, danger: true })) !== null;
function menu(x, y, items) {
  document.querySelector(".menu")?.remove();
  const el = h("div", { class: "menu" }, items.filter(Boolean).map(([label, fn, danger]) => h("button", { type: "button", class: danger ? "danger" : "", text: label, onclick: () => { el.remove(); run(fn); } })));
  document.body.append(el);
  const r = el.getBoundingClientRect();
  el.style.left = Math.min(x, innerWidth - r.width - 8) + "px";
  el.style.top = Math.min(y, innerHeight - r.height - 8) + "px";
  setTimeout(() => document.addEventListener("mousedown", function off(e) { if (!el.contains(e.target)) { el.remove(); document.removeEventListener("mousedown", off); } }), 0);
  return el;
}
function emojiPicker(anchor, onPick) {
  const r = anchor.getBoundingClientRect();
  const el = menu(r.left, r.top - 220, []);
  el.append(h("div", { class: "emoji-grid" }, EMOJI.map((e) => h("button", { type: "button", text: e, onclick: () => { el.remove(); run(() => onPick(e)); } }))));
  const rr = el.getBoundingClientRect();
  el.style.top = Math.max(8, r.top - rr.height - 6) + "px";
}

// ------------------------------------------------------------------ auth
const storedToken = sessionStorage.getItem("nexora-token");
$("login-form").addEventListener("submit", (e) => { e.preventDefault(); run(async () => {
  const result = await request("/api/v1/auth/login", "POST", { username: $("username").value, password: $("password").value, ...($("mfa-code").value ? { mfa_code: $("mfa-code").value } : {}), ...($("recovery-code").value ? { recovery_code: $("recovery-code").value.trim() } : {}) });
  token = result.token; sessionStorage.setItem("nexora-token", token);
  $("password").value = ""; $("mfa-code").value = ""; $("recovery-code").value = "";
  await signedIn();
}); });
$("passkey-login").addEventListener("click", () => run(async () => {
  if (!globalThis.PublicKeyCredential) throw new Error("This browser does not support passkeys.");
  const options = await request("/api/v1/auth/passkeys/login/options", "POST", {});
  const credential = await navigator.credentials.get({ publicKey: { challenge: fromB64(options.challenge), rpId: options.rpId, userVerification: options.userVerification, timeout: options.timeout, allowCredentials: [] } });
  if (!credential) return;
  const r = credential.response;
  const result = await request("/api/v1/auth/passkeys/login", "POST", { credential: { id: credential.id, response: { clientDataJSON: toB64(r.clientDataJSON), authenticatorData: toB64(r.authenticatorData), signature: toB64(r.signature), userHandle: r.userHandle ? toB64(r.userHandle) : null } } });
  token = result.token; sessionStorage.setItem("nexora-token", token);
  await signedIn();
}));
$("register").addEventListener("click", () => run(async () => {
  if (!$("login-form").reportValidity()) return;
  await request("/api/v1/auth/register", "POST", { username: $("username").value, password: $("password").value });
  toast("Account created — signing you in.");
  $("login-form").requestSubmit();
}));
function signedOut(message) {
  disconnectGateway();
  token = null; selfId = null; currentGuild = null; currentChannel = null; unlockedDevice = null;
  sessionStorage.removeItem("nexora-token"); keyring.clear();
  Object.assign(S, { me: null, guilds: [], dms: [], guildId: null, channelId: null, messages: [], members: [] });
  closeModal(); updateComposer();
  $("logged-in").classList.add("hidden"); $("logged-out").classList.remove("hidden");
  if (message) toast(message);
}
async function signedIn() {
  const me = await request("/api/v10/users/@me");
  S.me = me; selfId = me.id;
  $("logged-out").classList.add("hidden"); $("logged-in").classList.remove("hidden");
  [S.settings] = await Promise.all([request("/api/v1/users/@me/settings"), loadGuilds(), loadDMs(), loadRelationships(), loadReadStates()]);
  renderUserPanel();
  connectGateway();
  if (requestedRoute) {
    const route = requestedRoute; requestedRoute = null;
    const dm = S.dms.find((d) => d.guild_id === route.guild);
    if (dm) await openDM(dm);
    else if (S.guilds.some((g) => g.id === route.guild)) await selectGuild(route.guild, route.channel);
    else await selectHome();
  } else await selectHome();
  const vault = await loadDeviceVault().catch(() => null);
  if (vault && !unlockedDevice) promptUnlock();
  else if (!vault) toast("Set up encryption (🔒 in the bottom-left) to read and send messages.");
}

// ------------------------------------------------------------------ data loading
async function loadGuilds() { S.guilds = await request("/api/v10/users/@me/guilds"); renderRail(); }
async function loadDMs() { S.dms = await request("/api/v1/users/@me/channels"); if (S.view === "home") renderSidebar(); syncSubscriptions(); }
async function loadRelationships() { S.relationships = await request("/api/v1/users/@me/relationships"); if (S.view === "home" && !S.channelId) renderFriends(); }
async function loadReadStates() { const rows = await request("/api/v1/users/@me/read-states"); S.readStates = new Map(rows.map((r) => [r.channel_id, r.last_read_at])); }
async function loadGuildDetail() {
  if (!S.guildId) return;
  const id = S.guildId;
  const [guild, channels, members] = await Promise.all([request("/api/v1/guilds/" + enc(id)), request("/api/v10/guilds/" + enc(id) + "/channels"), request("/api/v1/guilds/" + enc(id) + "/members")]);
  if (S.guildId !== id) return;
  Object.assign(S, { guild, roles: guild.roles, channels, members });
  currentGuild = id;
}

// ------------------------------------------------------------------ navigation
async function selectHome() {
  if (S.channelId) unsubscribeCurrent();
  Object.assign(S, { view: "home", guildId: null, guild: null, channelId: null, channels: [], members: [], roles: [], messages: [] });
  currentGuild = null; currentChannel = null;
  history.replaceState(null, "", "/app");
  renderRail(); renderSidebar(); renderFriends(); renderMembers(); updateComposer();
}
async function selectGuild(id, preferredChannel) {
  if (S.channelId) unsubscribeCurrent();
  Object.assign(S, { view: "guild", guildId: id, channelId: null, messages: [] });
  renderRail();
  await loadGuildDetail();
  renderSidebar(); renderMembers();
  const text = S.channels.filter((c) => c.kind !== "category");
  const target = text.find((c) => c.id === preferredChannel) ?? text.find((c) => c.id === localStorage.getItem("nexora-last-" + id)) ?? text[0];
  if (target) await openChannel(target);
}
async function openDM(dm) {
  if (S.channelId) unsubscribeCurrent();
  Object.assign(S, { view: "home", guildId: null, guild: null, channels: [], roles: [] });
  S.members = dm.recipients.map((r) => ({ ...r, roles: [], nickname: null }));
  currentGuild = dm.guild_id;
  await openChannel({ id: dm.id, guild_id: dm.guild_id, name: dmName(dm), kind: "dm", topic: dm.type === "group_dm" ? dm.recipients.length + 1 + " members" : "Direct message" });
  renderMembers();
}
const dmName = (dm) => dm.name || dm.recipients.map((r) => r.display_name || r.username).join(", ") || "Empty group";
function unsubscribeCurrent() {
  if (S.ws?.readyState === 1 && S.channelId && !S.dms.some((d) => d.id === S.channelId)) { S.ws.send(JSON.stringify({op:43,d:{channel_id:S.channelId}})); S.subscribed.delete(S.channelId); }
}
async function openChannel(channel) {
  if (channel.kind === "category") return;
  if (S.channelId && S.channelId !== channel.id) unsubscribeCurrent();
  S.channelId = channel.id; currentChannel = channel.id; S.messages = []; S.replyTo = null; S.editing = null; S.typing.clear();
  if (S.guildId) localStorage.setItem("nexora-last-" + S.guildId, channel.id);
  history.replaceState(null, "", "/app/channels/" + enc(channel.guild_id ?? S.guildId ?? currentGuild) + "/" + enc(channel.id));
  $("channel-title").textContent = (channel.kind === "dm" ? "@ " : channel.kind === "announcement" ? "📣 " : "# ") + channel.name;
  $("channel-topic").textContent = channel.topic ?? "";
  $("friends-view").classList.add("hidden"); $("chat-view").classList.remove("hidden");
  $("composer").classList.remove("hidden");
  renderSidebar(); renderComposerContext(); updateComposer();
  subscribe(channel.id);
  $("messages").replaceChildren(h("p", { class: "empty-state", text: "Loading…" }));
  if (unlockedDevice) await keyring.sync(channel.id).catch((e) => toast("Encryption: " + e.message, true));
  await loadMessages();
  updateComposer();
  ack();
  $("chat-plaintext").focus();
}
$("home-button").addEventListener("click", () => run(selectHome));
$("add-server").addEventListener("click", () => run(addServerDialog));
$("toggle-sidebar").addEventListener("click", () => $("shell").classList.toggle("show-sidebar"));
$("members-button").addEventListener("click", () => { S.showMembers = !S.showMembers; renderMembers(); });
$("refresh-workspace").addEventListener("click", () => run(async () => {
  await Promise.all([loadGuilds(), loadDMs(), loadRelationships(), loadReadStates()]);
  if (S.guildId) { await loadGuildDetail(); renderSidebar(); renderMembers(); }
  if (S.channelId) { if (unlockedDevice) await keyring.sync(S.channelId); await loadMessages(); }
  await connectGateway(); status("Workspace refreshed.");
}));

// ------------------------------------------------------------------ rendering: rail, sidebar, members, friends
function renderRail() {
  $("home-button").classList.toggle("active", S.view === "home");
  $("guilds").replaceChildren(...S.guilds.map((g) => {
    const initials = g.name.split(/\s+/).map((w) => w[0]).join("").slice(0, 3).toUpperCase();
    const b = h("button", { type: "button", class: "rail-item" + (g.id === S.guildId ? " active" : ""), title: g.name, text: initials, onclick: () => run(() => selectGuild(g.id)) });
    b.style.marginBottom = "8px";
    return b;
  }));
}
function unread(channel) { const read = S.readStates.get(channel.id) ?? channel.last_read_at; return channel.last_message_at && (!read || new Date(channel.last_message_at) > new Date(read)) && channel.id !== S.channelId; }
function renderSidebar() {
  const list = $("channels");
  if (S.view === "home") {
    $("sidebar-title").textContent = "Direct messages";
    $("guild-menu-button").textContent = "＋"; $("guild-menu-button").title = "New group conversation";
    fill(list,
      h("button", { type: "button", class: "side-item" + (!S.channelId ? " selected" : ""), onclick: () => run(selectHome) }, h("span", { class: "hash", text: "👋" }), "Friends",
        S.relationships.filter((r) => r.status === "incoming").length ? h("span", { class: "badge pill warn", text: String(S.relationships.filter((r) => r.status === "incoming").length) }) : null),
      h("div", { class: "category", text: "Conversations" }),
      S.dms.length ? null : h("p", { class: "small muted", text: "No conversations yet. Message a friend or someone from a shared server." }),
      ...S.dms.map((dm) => {
        const other = dm.recipients[0];
        const un = dm.last_message_at && (!S.readStates.get(dm.id) || new Date(dm.last_message_at) > new Date(S.readStates.get(dm.id))) && dm.id !== S.channelId;
        return h("button", { type: "button", class: "side-item" + (dm.id === S.channelId ? " selected" : "") + (un ? " unread" : ""), onclick: () => run(() => openDM(dm)) },
          avatar(dm.type === "group_dm" ? dmName(dm) : other?.username, dm.type === "dm" ? other?.presence : null), h("span", { text: dmName(dm) }));
      }));
    return;
  }
  const g = S.guild;
  $("sidebar-title").textContent = g?.name ?? "";
  $("guild-menu-button").textContent = "⌄"; $("guild-menu-button").title = "Server menu";
  const cats = S.channels.filter((c) => c.kind === "category");
  const node = (c) => h("button", { type: "button", class: "side-item" + (c.id === S.channelId ? " selected" : "") + (unread(c) ? " unread" : ""), title: c.topic || c.name,
    onclick: () => run(() => openChannel(c)), oncontextmenu: (e) => { if (!can(P.MANAGE_CHANNELS)) return; e.preventDefault(); menu(e.clientX, e.clientY, [["Edit channel", () => channelSettings(c)], ["Delete channel", () => deleteChannel(c), true]]); } },
    h("span", { class: "hash", text: c.kind === "announcement" ? "📣" : "#" }), h("span", { text: c.name }));
  const loose = S.channels.filter((c) => c.kind !== "category" && !cats.some((k) => k.id === c.parent_id));
  list.replaceChildren(...loose.map(node), ...cats.flatMap((cat) => [
    h("div", { class: "category", oncontextmenu: (e) => { if (!can(P.MANAGE_CHANNELS)) return; e.preventDefault(); menu(e.clientX, e.clientY, [["Rename category", () => channelSettings(cat)], ["Delete category", () => deleteChannel(cat), true]]); } },
      h("span", { text: cat.name }), can(P.MANAGE_CHANNELS) ? h("button", { type: "button", class: "ghost", text: "+", title: "Create channel", onclick: () => run(() => createChannelDialog(cat.id)) }) : null),
    ...S.channels.filter((c) => c.parent_id === cat.id && c.kind !== "category").map(node),
  ]));
}
$("guild-menu-button").addEventListener("click", (e) => run(async () => {
  if (S.view === "home") return newGroupDialog();
  const r = e.currentTarget.getBoundingClientRect();
  menu(r.left - 150, r.bottom + 4, [
    can(P.CREATE_INVITE) && ["Invite people", inviteDialog],
    (can(P.MANAGE_GUILD) || can(P.MANAGE_ROLES) || can(P.BAN_MEMBERS) || can(P.VIEW_AUDIT_LOG) || can(P.KICK_MEMBERS)) && ["Server settings", () => serverSettings()],
    can(P.MANAGE_CHANNELS) && ["Create channel", () => createChannelDialog(null)],
    can(P.MANAGE_CHANNELS) && ["Create category", () => createChannelDialog(null, "category")],
    ["Edit server profile", editNickname],
    ["Report server", () => reportDialog("guild", S.guildId)],
    S.guild?.owner_id !== selfId && ["Leave server", leaveGuild, true],
  ]);
}));
function renderMembers() {
  const el = $("members");
  $("shell").classList.toggle("no-members", !S.showMembers || (!S.guildId && !S.channelId));
  if (!S.members.length) { el.replaceChildren(); return; }
  const row = (m) => h("button", { type: "button", class: "member" + (m.presence === "offline" ? " offline" : ""), onclick: () => run(() => profileDialog(m.id)),
    oncontextmenu: (e) => { e.preventDefault(); memberMenu(e.clientX, e.clientY, m); } },
    avatar(m.username, m.presence ?? "offline"),
    h("div", { class: "meta" }, h("strong", { text: m.nickname || m.display_name || m.username, style: roleColor(m.id) ? { color: roleColor(m.id) } : {} }), m.custom_status ? h("span", { text: m.custom_status }) : null));
  const hoisted = S.roles.filter((r) => r.hoist && !r.is_default).sort((a, b) => b.position - a.position);
  const placed = new Set(), groups = [];
  for (const role of hoisted) {
    const people = S.members.filter((m) => !placed.has(m.id) && m.presence !== "offline" && m.roles.includes(role.id));
    people.forEach((m) => placed.add(m.id));
    if (people.length) groups.push([role.name + " — " + people.length, people]);
  }
  const online = S.members.filter((m) => !placed.has(m.id) && m.presence !== "offline");
  const offline = S.members.filter((m) => !placed.has(m.id) && m.presence === "offline");
  if (S.channelId && !S.guildId) { const meRow = { id: selfId, username: S.me.username, presence: S.settings.status === "invisible" ? "offline" : S.settings.status, roles: [] }; online.unshift(meRow); }
  if (online.length) groups.push(["Online — " + online.length, online]);
  if (offline.length) groups.push(["Offline — " + offline.length, offline]);
  el.replaceChildren(...groups.flatMap(([title, people]) => [h("h4", { text: title }), ...people.map(row)]));
}
function memberMenu(x, y, m) {
  if (m.id === selfId) return;
  menu(x, y, [
    ["Profile", () => profileDialog(m.id)],
    ["Message", () => startDM(m.id)],
    S.guildId && can(P.MANAGE_ROLES) && ["Roles…", () => memberRolesDialog(m)],
    S.guildId && can(P.MANAGE_NICKNAMES) && ["Change nickname", () => setNickname(m)],
    S.guildId && can(P.KICK_MEMBERS) && ["Kick", () => kickMember(m), true],
    S.guildId && can(P.BAN_MEMBERS) && ["Ban", () => banMember(m), true],
    ["Report user", () => reportDialog("user", m.id)],
  ]);
}
function renderFriends() {
  if (S.view !== "home" || S.channelId) return;
  $("channel-title").textContent = "Friends"; $("channel-topic").textContent = "";
  $("chat-view").classList.add("hidden"); $("composer").classList.add("hidden"); $("friends-view").classList.remove("hidden");
  const tabs = [["online", "Online"], ["all", "All"], ["pending", "Pending"], ["blocked", "Blocked"]];
  const filter = { online: (r) => r.status === "friend" && r.presence !== "offline", all: (r) => r.status === "friend", pending: (r) => r.status === "incoming" || r.status === "outgoing", blocked: (r) => r.status === "blocked" }[S.friendsTab];
  const rows = S.relationships.filter(filter);
  const addForm = h("form", { class: "row", onsubmit: (e) => { e.preventDefault(); run(async () => { const r = await request("/api/v1/users/@me/relationships", "POST", { username: addInput.value.trim() }); addInput.value = ""; toast(r.status === "friend" ? "You are now friends." : "Friend request sent."); await loadRelationships(); }); } });
  const addInput = h("input", { placeholder: "Add a friend by username", maxLength: 32, required: true, pattern: "[A-Za-z0-9_]{3,32}" });
  addForm.append(addInput, h("button", { type: "submit", text: "Send request" }));
  fill($("friends-view"),
    h("div", { class: "tabs" }, tabs.map(([k, l]) => h("button", { type: "button", class: S.friendsTab === k ? "selected" : "", text: l, onclick: () => { S.friendsTab = k; renderFriends(); } }))),
    h("div", { style: { margin: "16px 0" } }, addForm),
    rows.length ? null : h("p", { class: "muted", text: { online: "No friends online right now.", all: "No friends yet — add someone by username.", pending: "No pending requests.", blocked: "You have not blocked anyone." }[S.friendsTab] }),
    ...rows.map((r) => h("div", { class: "friend-row" }, avatar(r.username, r.status === "friend" ? r.presence : null),
      h("div", { class: "meta" }, h("strong", { text: r.display_name || r.username }), h("div", { class: "small muted", text: r.status === "incoming" ? "Incoming request" : r.status === "outgoing" ? "Outgoing request" : r.status === "blocked" ? "Blocked" : presenceLabel[r.presence] ?? "" })),
      r.status === "friend" ? h("button", { type: "button", class: "secondary", text: "Message", onclick: () => run(() => startDM(r.id)) }) : null,
      r.status === "incoming" ? h("button", { type: "button", text: "Accept", onclick: () => run(async () => { await request("/api/v1/users/@me/relationships/" + enc(r.id), "PUT", { type: "friend" }); await loadRelationships(); }) }) : null,
      h("button", { type: "button", class: "ghost", text: r.status === "blocked" ? "Unblock" : r.status === "friend" ? "Remove" : r.status === "incoming" ? "Ignore" : "Cancel", onclick: () => run(async () => { await request("/api/v1/users/@me/relationships/" + enc(r.id), "DELETE"); await loadRelationships(); }) }),
      h("button", { type: "button", class: "ghost", text: "⋯", onclick: (e) => menu(e.clientX, e.clientY, [["Profile", () => profileDialog(r.id)], r.status !== "blocked" && ["Block", () => blockUser(r.id), true]]) })))
  );
  renderSidebar();
}
function renderUserPanel() {
  $("self-avatar").replaceChildren(avatar(S.me.username, S.settings.status === "invisible" ? "offline" : S.settings.status));
  $("user").textContent = S.me.username;
  $("self-status").textContent = S.settings.custom_status || presenceLabel[S.settings.status];
  $("vault-button").textContent = unlockedDevice ? "🔓" : "🔒";
  $("vault-button").title = unlockedDevice ? "Encryption unlocked" : "Unlock or set up encryption";
}
$("self-avatar").addEventListener("click", (e) => menu(e.clientX, e.clientY - 180, [
  ...["online", "idle", "dnd", "invisible"].map((s) => [presenceLabel[s], async () => { S.settings = await request("/api/v1/users/@me/settings", "PATCH", { status: s }); renderUserPanel(); }]),
  ["Set custom status…", async () => { const v = await ask({ title: "Custom status", fields: [{ name: "custom_status", label: "Status", value: S.settings.custom_status, max: 128 }] }); if (v) { S.settings = await request("/api/v1/users/@me/settings", "PATCH", v); renderUserPanel(); } }],
]));

// ------------------------------------------------------------------ messages
const deviceRefresh = new Map();
/** Ask online holders for the current room key, then re-sync a few times to collect their grant. */
async function requestAndAwaitKey(channelId) {
  await keyring.requestKey(channelId).catch(() => {});
  for (const wait of [1000, 2500, 5000, 10000]) {
    await new Promise((r) => setTimeout(r, wait));
    if (S.channelId !== channelId || !unlockedDevice) return;
    await keyring.sync(channelId).catch(() => {});
    if (keyring.current(channelId)?.key) { await afterKeysImported(); return; }
  }
  updateComposer();
}
async function decryptRow(m) {
  if (m._state) return m;
  if (typeof m.ciphertext !== "string" || m.ciphertext[0] !== "{") { m._state = "opaque"; return m; }
  let envelope;
  try { envelope = JSON.parse(m.ciphertext); } catch { m._state = "invalid"; return m; }
  const epoch = envelope?.context?.epoch;
  const key = keyring.key(m.channel_id, epoch);
  if (!unlockedDevice) { m._state = "locked"; return m; }
  if (!key) { m._state = "nokey"; return m; }
  try { m._text = await decryptMessage(key, envelope, { room: m.channel_id, sender: m.author_id, epoch }); m._state = "ok"; }
  catch { m._state = "invalid"; return m; }
  // Sender authenticity: the author's device must have signed this exact envelope.
  m._sig = await keyring.verifyMessage(envelope, m.author_id);
  // A device we have not seen yet (e.g. just added and approved): refresh device data once, throttled.
  if ((m._sig === "unknown-device" || m._sig === "untrusted-device") && Date.now() - (deviceRefresh.get(m.channel_id) ?? 0) > 5000) {
    deviceRefresh.set(m.channel_id, Date.now());
    await keyring.sync(m.channel_id).catch(() => {});
    m._sig = await keyring.verifyMessage(envelope, m.author_id);
  }
  if (m._sig === "invalid") { m._state = "forged"; delete m._text; }
  return m;
}
async function loadMessages(before) {
  const channel = S.channelId;
  const rows = await request("/api/v10/channels/" + enc(channel) + "/messages?limit=50" + (before ? "&before=" + enc(before) : ""));
  if (S.channelId !== channel) return;
  for (const m of rows) await decryptRow(m);
  S.hasMore = rows.length === 50;
  S.messages = before ? [...rows, ...S.messages] : rows;
  const box = $("messages"), keep = before ? box.scrollHeight - box.scrollTop : null;
  renderMessages();
  if (keep !== null) box.scrollTop = box.scrollHeight - keep; else box.scrollTop = box.scrollHeight;
}
const sigLabel = { verified: ["✓", "Signed by a trusted device of the author"], unsigned: ["unsigned", "Not signed by a device (older client) — sender is only vouched for by the server"], "untrusted-device": ["⚠ unapproved device", "Signed by a device the author has not approved"], "unknown-device": ["signed", "Signed by a device that is no longer registered"] };
const lockedText = { forged: "⚠ Signature check failed — this message may be forged and is hidden.", locked: "🔒 Encrypted — unlock your device to read.", nokey: "🔒 Encrypted for a key epoch this device was not given (sent before you joined, or not yet shared with this device).", invalid: "⚠ Could not decrypt or verify this message.", opaque: "Opaque test envelope (not produced by a Nexora client)." };
function messageNode(m, prev) {
  const grouped = prev && prev.author_id === m.author_id && !m.reply_to && new Date(m.created_at) - new Date(prev.created_at) < 7 * 60000;
  const name = displayName(m.author_id) ?? m.author_username ?? "Unknown user";
  const mine = m.author_id === selfId;
  const mentioned = m._state === "ok" && S.me && new RegExp("@" + S.me.username + "\\b", "i").test(m._text);
  const body = h("div", { class: "msg-body" + (m._state === "ok" ? "" : " locked") });
  if (m._state === "ok") body.append(renderMarkdown(m._text)); else body.append(lockedText[m._state] ?? "Encrypted message");
  if (m.edited_at) body.append(h("span", { class: "edited", text: "(edited)", title: fmtTime(m.edited_at) }));
  if (m._state === "ok" && sigLabel[m._sig]) body.append(h("span", { class: "sig sig-" + m._sig, text: sigLabel[m._sig][0], title: sigLabel[m._sig][1] }));
  if (m.pinned) body.append(h("span", { class: "pin-mark", text: "📌" }));
  const actions = h("div", { class: "msg-actions" },
    h("button", { type: "button", title: "React", text: "☺", onclick: (e) => emojiPicker(e.currentTarget, (emoji) => toggleReaction(m, emoji)) }),
    h("button", { type: "button", title: "Reply", text: "↩", onclick: () => { S.replyTo = m; S.editing = null; renderComposerContext(); $("chat-plaintext").focus(); } }),
    mine && m._state === "ok" ? h("button", { type: "button", title: "Edit", text: "✎", onclick: () => startEdit(m) }) : null,
    h("button", { type: "button", title: "More", text: "⋯", onclick: (e) => menu(e.clientX - 160, e.clientY, [
      m._state === "ok" && ["Copy text", () => navigator.clipboard.writeText(m._text)],
      (!S.guildId || can(P.MANAGE_MESSAGES)) && [m.pinned ? "Unpin" : "Pin", () => togglePin(m)],
      ["Copy message ID", () => navigator.clipboard.writeText(m.id)],
      !mine && ["Report message", () => reportDialog("message", m.id, m._state === "ok" ? m._text : "")],
      (mine || can(P.MANAGE_MESSAGES)) && ["Delete", () => deleteMessage(m), true],
    ]) }));
  const replied = m.reply_to ? S.messages.find((x) => x.id === m.reply_to) : null;
  return h("div", { class: "message" + (grouped ? " grouped" : "") + (mentioned ? " mention" : ""), id: "msg-" + m.id },
    m.reply_to ? h("div", { class: "reply-preview", text: replied ? (displayName(replied.author_id) ?? replied.author_username ?? "?") + ": " + (replied._state === "ok" ? replied._text.slice(0, 120) : "encrypted message") : "Reply to an earlier message", onclick: () => $("msg-" + m.reply_to)?.scrollIntoView({ block: "center" }) }) : null,
    h("div", {}, avatar(name), h("span", { class: "hover-time", text: new Date(m.created_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) })),
    h("div", {}, h("div", { class: "msg-head" }, h("strong", { text: name, style: roleColor(m.author_id) ? { color: roleColor(m.author_id) } : {}, onclick: () => run(() => profileDialog(m.author_id)) }), h("time", { text: fmtTime(m.created_at), title: new Date(m.created_at).toLocaleString() })),
      body,
      m.reactions?.length ? h("div", { class: "reactions" }, m.reactions.map((r) => h("button", { type: "button", class: "reaction" + (r.me ? " me" : ""), text: r.emoji + " " + r.count, onclick: () => run(() => toggleReaction(m, r.emoji)) }))) : null),
    actions);
}
function renderMessages() {
  const box = $("messages");
  const nodes = [];
  if (S.hasMore) nodes.push(h("button", { type: "button", class: "secondary load-older", text: "Load older messages", onclick: () => run(() => loadMessages(S.messages[0]?.id)) }));
  else nodes.push(h("div", { class: "empty-state" }, h("h3", { text: "This is the beginning of " + $("channel-title").textContent }), h("p", { text: "Messages here are end-to-end encrypted in your browser. The server stores only ciphertext, but sees who talks when." })));
  S.messages.forEach((m, i) => nodes.push(messageNode(m, S.messages[i - 1])));
  box.replaceChildren(...nodes);
}
$("messages").addEventListener("scroll", () => { if ($("messages").scrollTop < 40 && S.hasMore && !S.loadingOlder) { S.loadingOlder = true; run(() => loadMessages(S.messages[0]?.id)).finally(() => (S.loadingOlder = false)); } });
function appendMessage(m) {
  if (S.messages.some((x) => x.id === m.id)) return;
  const box = $("messages"), atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 120;
  S.messages.push(m);
  box.append(messageNode(m, S.messages[S.messages.length - 2]));
  if (atBottom || m.author_id === selfId) box.scrollTop = box.scrollHeight;
}
function replaceMessage(m) { const i = S.messages.findIndex((x) => x.id === m.id); if (i < 0) return; S.messages[i] = m; $("msg-" + m.id)?.replaceWith(messageNode(m, S.messages[i - 1])); }
async function toggleReaction(m, emoji) {
  const mine = m.reactions?.find((r) => r.emoji === emoji)?.me;
  await request("/api/v10/channels/" + enc(m.channel_id) + "/messages/" + enc(m.id) + "/reactions/" + enc(emoji) + "/@me", mine ? "DELETE" : "PUT");
}
async function togglePin(m) { await request("/api/v10/channels/" + enc(m.channel_id) + "/pins/" + enc(m.id), m.pinned ? "DELETE" : "PUT"); m.pinned = !m.pinned; replaceMessage(m); }
async function deleteMessage(m) {
  if (!(await confirmModal("Delete message", "This permanently deletes the encrypted message for everyone.", "Delete"))) return;
  await request("/api/v10/channels/" + enc(m.channel_id) + "/messages/" + enc(m.id), "DELETE");
}
function startEdit(m) { S.editing = m; S.replyTo = null; $("chat-plaintext").value = m._text; renderComposerContext(); $("chat-plaintext").focus(); }
let ackTimer = null;
function ack() {
  clearTimeout(ackTimer);
  ackTimer = setTimeout(() => {
    if (!S.channelId || document.hidden) return;
    const last = S.messages.at(-1);
    S.readStates.set(S.channelId, new Date().toISOString());
    request("/api/v1/channels/" + enc(S.channelId) + "/ack", "POST", last ? { message_id: last.id } : {}).catch(() => {});
    renderSidebar();
  }, 800);
}
document.addEventListener("visibilitychange", () => { if (!document.hidden) ack(); });
$("pins-button").addEventListener("click", () => run(async () => {
  if (!S.channelId) return;
  const pins = await request("/api/v10/channels/" + enc(S.channelId) + "/pins");
  for (const m of pins) await decryptRow(m);
  modal(h("div", {}, h("h2", { text: "Pinned messages" }), pins.length ? null : h("p", { class: "muted", text: "Nothing pinned yet." }),
    pins.map((m) => h("div", { class: "list-row" }, avatar(m.author_username), h("div", { class: "meta" }, h("strong", { text: displayName(m.author_id) ?? m.author_username ?? "Unknown" }), " ", h("span", { class: "small muted", text: fmtTime(m.created_at) }), h("div", {}, m._state === "ok" ? renderMarkdown(m._text) : lockedText[m._state]))))));
}));

// ------------------------------------------------------------------ composer
function updateComposer() {
  const send = $("send-encrypted-button");
  const ready = !!(S.channelId && unlockedDevice && keyring.current(S.channelId)?.key);
  if (send) send.disabled = !currentChannel || !unlockedDevice || !ready;
  const lock = $("composer-lock"), pill = $("e2ee-state");
  if (!S.channelId) { pill.className = "pill"; pill.textContent = "E2EE"; return; }
  const state = keyring.current(S.channelId)?.status;
  let note = "";
  if (!unlockedDevice) note = "🔒 Unlock or set up your encryption device (🔒 bottom-left) to read and send messages.";
  else if (state === "unregistered") note = "This browser's device is not registered for your account (it may have been revoked). Set up a new device in Settings → Encryption.";
  else if (state === "waiting") note = "Waiting for a member to share this conversation's current key with your device. They will do so automatically when online.";
  lock.textContent = note; lock.classList.toggle("hidden", !note);
  if (state === "waiting") lock.append(" ", h("button", { type: "button", class: "secondary", text: "Ask again", onclick: () => run(async () => { toast("Key request sent to online members."); await requestAndAwaitKey(S.channelId); }) }));
  pill.className = "pill " + (ready ? "ok" : unlockedDevice ? "warn" : "bad");
  pill.textContent = ready ? "E2EE · epoch " + keyring.current(S.channelId).epoch : unlockedDevice ? "E2EE · no key" : "E2EE · locked";
  $("chat-plaintext").placeholder = ready ? "Message " + $("channel-title").textContent : "Encryption not ready";
}
function renderComposerContext() {
  const bar = $("composer-context"), text = $("composer-context-text");
  if (S.replyTo) { bar.classList.remove("hidden"); text.textContent = "Replying to " + (displayName(S.replyTo.author_id) ?? S.replyTo.author_username ?? "message"); }
  else if (S.editing) { bar.classList.remove("hidden"); text.textContent = "Editing message — Esc to cancel"; }
  else bar.classList.add("hidden");
}
$("composer-cancel").addEventListener("click", () => { if (S.editing) $("chat-plaintext").value = ""; S.replyTo = null; S.editing = null; renderComposerContext(); });
$("emoji-button").addEventListener("click", (e) => emojiPicker(e.currentTarget, (emoji) => { const t = $("chat-plaintext"); t.value += emoji; t.focus(); }));
$("chat-plaintext").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); $("send-encrypted-form").requestSubmit(); }
  else if (e.key === "Escape") { $("composer-cancel").click(); }
  else if (e.key === "ArrowUp" && !e.target.value) { const last = [...S.messages].reverse().find((m) => m.author_id === selfId && m._state === "ok"); if (last) { e.preventDefault(); startEdit(last); } }
});
$("chat-plaintext").addEventListener("input", (e) => {
  e.target.style.height = "auto"; e.target.style.height = Math.min(e.target.scrollHeight, innerHeight * 0.4) + "px";
  if (S.ws?.readyState === 1 && S.channelId && Date.now() - S.lastTypingSent > 3000 && e.target.value) { S.lastTypingSent = Date.now(); S.ws.send(JSON.stringify({ op: 44, d: { channel_id: S.channelId } })); }
});
$("send-encrypted-form").addEventListener("submit", (event) => { event.preventDefault(); run(async () => {
  if (!currentChannel) throw Error("Select a channel");
  const plaintext = $("chat-plaintext").value;
  if (!plaintext.trim()) return;
  const channel = S.channelId;
  const attempt = async () => {
    let state = keyring.current(channel);
    if (!state?.key) state = (await keyring.sync(channel), keyring.current(channel));
    if (!state?.key) throw Error("No room key available yet for this conversation.");
    const envelope = await signEnvelope(await encryptMessage(state.key, plaintext, { room: channel, sender: selfId, epoch: state.epoch }), unlockedDevice, state.deviceId);
    if (S.editing) return request("/api/v10/channels/" + enc(channel) + "/messages/" + enc(S.editing.id), "PATCH", { algorithm: "client-encrypted-v1", ciphertext:JSON.stringify(envelope) });
    return request("/api/v10/channels/" + enc(channel) + "/messages", "POST", { algorithm: "client-encrypted-v1", ciphertext:JSON.stringify(envelope), ...(S.replyTo ? { reply_to: S.replyTo.id } : {}) });
  };
  try { await attempt(); }
  catch (error) {
    // Membership changed since the key was cached: resync the new epoch and retry once.
    if (!/Forbidden|stale/i.test(error.message)) throw error;
    await keyring.sync(channel); updateComposer(); await attempt();
  }
  $("chat-plaintext").value = ""; $("chat-plaintext").style.height = "auto";
  S.replyTo = null; S.editing = null; S.lastTypingSent = 0; renderComposerContext();
}); });

// ------------------------------------------------------------------ gateway
function connectionState(value, online = false) { const el = $("gateway-state"); if (!el) return; el.textContent = value; el.classList.toggle("online", online); }
function disconnectGateway() {
  if (S.heartbeat) { clearInterval(S.heartbeat); S.heartbeat = null; }
  clearTimeout(S.reconnectTimer);
  if (S.ws) { const old = S.ws; S.ws = null; old.close(); }
  S.subscribed.clear();
  connectionState("Offline");
}
function subscribe(channelId) {
  if (S.subscribed.has(channelId)) return;
  if (S.ws?.readyState === 1) S.ws.send(JSON.stringify({ op: 42, d: { channel_id: channelId } }));
  S.subscribed.add(channelId);
}
/** Live delivery for the open channel plus up to 20 direct conversations (server cap: 25). */
function syncSubscriptions() { for (const dm of S.dms.slice(0, 20)) subscribe(dm.id); if (S.channelId) subscribe(S.channelId); }
async function connectGateway() {
  disconnectGateway();
  if (!token) return;
  const discovered = await request("/api/v10/gateway");
  const socket = new WebSocket(discovered.url);
  S.ws = socket;
  connectionState("Connecting…");
  socket.onmessage = (event) => {
    if (S.ws !== socket) return;
    let packet; try { packet = JSON.parse(event.data); } catch { return; }
    if (packet.op === 10) {
      socket.send(JSON.stringify({ op: 2, d: { token } }));
      S.heartbeat = setInterval(() => { if (socket.readyState === 1) socket.send(JSON.stringify({op:1,d:null})); }, packet.d.heartbeat_interval);
    } else if (packet.op === 0) run(() => dispatch(packet.t, packet.d ?? {}, socket));
  };
  socket.onclose = (event) => {
    if (S.ws !== socket) return;
    if (S.heartbeat) { clearInterval(S.heartbeat); S.heartbeat = null; }
    S.ws = null; S.subscribed.clear();
    if (event.code === 4004) { signedOut("You were signed out (session revoked or expired)."); return; }
    connectionState("Reconnecting…");
    S.reconnectTimer = setTimeout(() => run(connectGateway), S.reconnectDelay);
    S.reconnectDelay = Math.min(S.reconnectDelay * 2, 30000);
  };
}
async function dispatch(t, d, socket) {
  if (t === "READY") {
    S.reconnectDelay = 1000; S.subscribed.clear();
    syncSubscriptions();
    connectionState("Connected",true);
  } else if (t === "MESSAGE_CREATE") {
    if (d.channel_id === S.channelId) {
      await decryptRow(d);
      if (d._state === "nokey" && unlockedDevice) { await keyring.sync(d.channel_id); delete d._state; await decryptRow(d); updateComposer(); }
      appendMessage(d); S.typing.delete(d.author_id); renderTyping();
      if (document.hidden) notify(d); else ack();
    } else {
      const dm = S.dms.find((x) => x.id === d.channel_id);
      if (dm) { dm.last_message_at = d.created_at; S.dms.sort((a, b) => new Date(b.last_message_at ?? 0) - new Date(a.last_message_at ?? 0)); if (S.view === "home") renderSidebar(); if (d.author_id !== selfId) { if (unlockedDevice) await keyring.sync(d.channel_id).catch(() => {}); await decryptRow(d); notify(d, dm); } }
      const ch = S.channels.find((x) => x.id === d.channel_id);
      if (ch) { ch.last_message_at = d.created_at; renderSidebar(); }
    }
  } else if (t === "MESSAGE_UPDATE" && d.channel_id === S.channelId) {
    const old = S.messages.find((m) => m.id === d.id);
    if (old) { const fresh = { ...old, ...d, _state: undefined, _text: undefined }; await decryptRow(fresh); replaceMessage(fresh); }
  } else if (t === "MESSAGE_DELETE" && d.channel_id === S.channelId) {
    S.messages = S.messages.filter((m) => m.id !== d.id); $("msg-" + d.id)?.remove();
  } else if ((t === "MESSAGE_REACTION_ADD" || t === "MESSAGE_REACTION_REMOVE") && d.channel_id === S.channelId) {
    const m = S.messages.find((x) => x.id === d.message_id);
    if (!m) return;
    m.reactions ??= [];
    let r = m.reactions.find((x) => x.emoji === d.emoji);
    if (t === "MESSAGE_REACTION_ADD") { if (!r) m.reactions.push(r = { emoji: d.emoji, count: 0, me: false }); r.count++; if (d.user_id === selfId) r.me = true; }
    else if (r) { r.count--; if (d.user_id === selfId) r.me = false; if (r.count <= 0) m.reactions = m.reactions.filter((x) => x !== r); }
    replaceMessage(m);
  } else if (t === "CHANNEL_PINS_UPDATE" && d.channel_id === S.channelId) {
    const m = S.messages.find((x) => x.id === d.message_id); if (m) { m.pinned = d.pinned; replaceMessage(m); }
  } else if (t === "TYPING_START" && d.channel_id === S.channelId) {
    S.typing.set(d.user_id, { name: displayName(d.user_id) ?? d.username, until: Date.now() + 8000 }); renderTyping();
  } else if (t === "PRESENCE_UPDATE") {
    for (const m of S.members) if (m.id === d.user_id) { m.presence = d.status; m.custom_status = d.custom_status; }
    for (const r of S.relationships) if (r.id === d.user_id) r.presence = d.status;
    for (const dm of S.dms) for (const r of dm.recipients) if (r.id === d.user_id) r.presence = d.status;
    renderMembers(); if (S.view === "home") { renderSidebar(); renderFriends(); }
  } else if (t === "CHANNEL_ACCESS_REVOKED" && d.channel_id === S.channelId) {
    toast("You no longer have access to this channel."); await loadGuilds(); await selectHome();
  } else if (["CHANNEL_CREATE", "CHANNEL_UPDATE", "CHANNEL_DELETE", "CHANNELS_REORDER", "GUILD_MEMBER_ADD", "GUILD_MEMBER_REMOVE", "GUILD_MEMBER_UPDATE", "GUILD_ROLES_UPDATE", "GUILD_UPDATE"].includes(t)) {
    const gid = d.guild_id ?? d.id;
    if (t === "GUILD_UPDATE") await loadGuilds();
    if (gid && gid === S.guildId) {
      await loadGuildDetail(); renderSidebar(); renderMembers();
      if (t === "CHANNEL_DELETE" && d.id === S.channelId) await selectGuild(S.guildId);
      if (t === "CHANNEL_UPDATE" && d.id === S.channelId) $("channel-topic").textContent = d.topic ?? "";
    }
  } else if (t === "GUILD_CREATE" || t === "GUILD_DELETE") {
    await loadGuilds();
    if (t === "GUILD_DELETE" && d.id === S.guildId) { toast("You are no longer in that server."); await selectHome(); }
  } else if (t === "RELATIONSHIP_UPDATE") await loadRelationships();
  else if (t === "DM_CREATE" || t === "DM_UPDATE") await loadDMs();
  else if (t === "KEY_REQUEST" && d.user_id !== selfId && unlockedDevice) await keyring.sync(d.channel_id).catch(() => {});
  else if (t === "DEVICE_ADDED") await onDeviceAdded(d);
  else if (t === "DEVICE_UPDATE") {
    await renderDeviceList().catch(() => {});
    // This device may just have been approved: ask holders to share keys with it.
    if (unlockedDevice && S.channelId) { await keyring.sync(S.channelId).catch(() => {}); if (!keyring.current(S.channelId)?.key) await requestAndAwaitKey(S.channelId); updateComposer(); }
  }
}
function renderTyping() {
  const now = Date.now();
  for (const [k, v] of S.typing) if (v.until < now) S.typing.delete(k);
  const names = [...S.typing.values()].map((v) => v.name);
  $("typing").textContent = names.length ? names.slice(0, 3).join(", ") + (names.length > 3 ? " and others" : "") + (names.length === 1 ? " is typing…" : " are typing…") : "";
}
setInterval(renderTyping, 2000);
function notify(m, dm) {
  if (m.author_id === selfId || !("Notification" in globalThis) || Notification.permission !== "granted" || S.settings.status === "dnd") return;
  const mentioned = m._state === "ok" && new RegExp("@" + S.me.username + "\\b", "i").test(m._text);
  if (!dm && !mentioned) return;
  new Notification(displayName(m.author_id) ?? m.author_username ?? "Nexora", { body: m._state === "ok" ? m._text.slice(0, 200) : "New encrypted message", tag: m.channel_id });
}

// ------------------------------------------------------------------ servers
async function addServerDialog() {
  const box = modal(h("div", {}, h("h2", { text: "Add a server" }), h("p", { class: "muted", text: "Create your own space or join one with an invite code." })));
  const create = h("form", { onsubmit: (e) => { e.preventDefault(); run(async () => { const g = await request("/api/v10/guilds", "POST", { name: name.value }); closeModal(); await loadGuilds(); await selectGuild(g.id); }); } });
  const name = h("input", { id: "guild-name", maxLength: 100, required: true, placeholder: (S.me?.username ?? "My") + "'s server" });
  create.append(h("label", { htmlFor: "guild-name", text: "Server name" }), h("div", { class: "row" }, name, h("button", { type: "submit", text: "Create" })));
  const join = h("form", { onsubmit: (e) => { e.preventDefault(); run(() => joinWithCode(code.value)); } });
  const code = h("input", { id: "invite-code", autocomplete: "off", maxLength: 200, required: true, placeholder: "Invite code or link" });
  const preview = h("p", { class: "muted small" });
  code.addEventListener("change", () => run(async () => { const c = parseInvite(code.value); if (!c) return; const p = await request("/api/v1/invites/" + enc(c)); preview.textContent = `${p.guild.name} · ${p.member_count} member(s)` + (p.already_member ? " · already joined" : ""); }));
  join.append(h("label", { htmlFor: "invite-code", text: "Join with an invite" }), h("div", { class: "row" }, code, h("button", { type: "submit", class: "secondary", text: "Join" })), preview);
  box.append(create, join);
}
const parseInvite = (v) => (/([A-Za-z0-9_-]{32})\s*$/.exec(v.trim()) ?? [])[1];
async function joinWithCode(value) {
  const c = parseInvite(value);
  if (!c) throw Error("That does not look like an invite code.");
  const result = await request("/api/v1/invites/" + enc(c) + "/join", "POST");
  closeModal(); await loadGuilds(); await selectGuild(result.guild_id);
  toast(result.already_member ? "Already a member." : "Joined server.");
}
async function inviteDialog() {
  const v = await ask({ title: "Invite people", text: "Invite codes are shown once. Share them only with people you trust.", submit: "Create invite", fields: [
    { name: "max_uses", label: "Max uses", type: "select", value: "10", options: [["1", "1 use"], ["5", "5 uses"], ["10", "10 uses"], ["25", "25 uses"], ["100", "100 uses"]] },
    { name: "expires_hours", label: "Expires after", type: "select", value: "24", options: [["1", "1 hour"], ["6", "6 hours"], ["24", "1 day"], ["72", "3 days"], ["168", "7 days"]] }] });
  if (!v) return;
  const r = await request("/api/v1/guilds/" + enc(S.guildId) + "/invites", "POST", { max_uses: Number(v.max_uses), expires_hours: Number(v.expires_hours) });
  const link = location.origin + "/app?invite=" + r.code;
  modal(h("div", {}, h("h2", { text: "Invite created" }), h("p", { class: "muted", text: "Expires " + new Date(r.expires_at).toLocaleString() + " · " + r.max_uses + " use(s)" }),
    h("input", { value: r.code, readOnly: true, onfocus: (e) => e.target.select() }), h("p", { class: "small muted", text: link }),
    h("div", { class: "actions" }, h("button", { type: "button", text: "Copy code", onclick: () => run(async () => { await navigator.clipboard.writeText(r.code); toast("Copied."); }) }), h("button", { type: "button", class: "secondary", text: "Done", onclick: closeModal }))));
}
async function createChannelDialog(parentId, kind = "encrypted_text") {
  const cats = S.channels.filter((c) => c.kind === "category");
  const v = await ask({ title: kind === "category" ? "Create category" : "Create channel", submit: "Create", fields: [
    { name: "name", label: "Name (lowercase, digits, - and _)", required: true, pattern: "([a-z0-9_]|-)+", max: 80, placeholder: kind === "category" ? "text-channels" : "new-channel" },
    ...(kind === "category" ? [] : [
      { name: "kind", label: "Type", type: "select", value: "encrypted_text", options: [["encrypted_text", "Text"], ["announcement", "Announcement (moderators post)"]] },
      { name: "parent_id", label: "Category", type: "select", value: parentId ?? "", options: [["", "No category"], ...cats.map((c) => [c.id, c.name])] },
      { name: "topic", label: "Topic", max: 1024 }])] });
  if (!v) return;
  const body = { name: v.name.toLowerCase(), kind: kind === "category" ? "category" : v.kind, ...(v.topic ? { topic: v.topic } : {}), ...(v.parent_id ? { parent_id: v.parent_id } : {}) };
  const ch = await request("/api/v1/guilds/" + enc(S.guildId) + "/channels", "POST", body);
  await loadGuildDetail(); renderSidebar();
  if (ch.kind !== "category") await openChannel(ch);
}
async function channelSettings(c) {
  const v = await ask({ title: "Edit " + c.name, fields: [{ name: "name", label: "Name", value: c.name, required: true, pattern: "([a-z0-9_]|-)+", max: 80 }, ...(c.kind === "category" ? [] : [{ name: "topic", label: "Topic", value: c.topic, max: 1024, type: "textarea" }])] });
  if (!v) return;
  await request("/api/v1/channels/" + enc(c.id), "PATCH", v.topic === undefined ? { name: v.name } : v);
}
async function deleteChannel(c) {
  if (!(await confirmModal("Delete " + c.name, "This permanently deletes the channel and all of its encrypted messages.", "Delete"))) return;
  await request("/api/v1/channels/" + enc(c.id), "DELETE");
}
async function leaveGuild() {
  if (!(await confirmModal("Leave " + S.guild.name, "You will need a new invite to rejoin.", "Leave"))) return;
  await request("/api/v1/guilds/" + enc(S.guildId) + "/members/" + enc(selfId), "DELETE");
  await loadGuilds(); await selectHome();
}
async function editNickname() {
  const me = S.members.find((m) => m.id === selfId);
  const v = await ask({ title: "Server nickname", fields: [{ name: "nickname", label: "Nickname (empty to reset)", value: me?.nickname ?? "", max: 32 }] });
  if (v) await request("/api/v1/guilds/" + enc(S.guildId) + "/members/@me", "PATCH", { nickname: v.nickname || null });
}
async function setNickname(m) {
  const v = await ask({ title: "Nickname for " + m.username, fields: [{ name: "nickname", label: "Nickname (empty to reset)", value: m.nickname ?? "", max: 32 }] });
  if (v) await request("/api/v1/guilds/" + enc(S.guildId) + "/members/" + enc(m.id), "PATCH", { nickname: v.nickname || null });
}
async function kickMember(m) { if (await confirmModal("Kick " + m.username, "They can rejoin with a new invite.", "Kick")) await request("/api/v1/guilds/" + enc(S.guildId) + "/members/" + enc(m.id), "DELETE"); }
async function banMember(m) {
  const v = await ask({ title: "Ban " + m.username, text: "Banned users are removed and cannot rejoin until unbanned.", submit: "Ban", danger: true, fields: [{ name: "reason", label: "Reason (visible to moderators)", max: 512 }] });
  if (v) await request("/api/v1/guilds/" + enc(S.guildId) + "/bans/" + enc(m.id), "PUT", { reason: v.reason });
}
async function memberRolesDialog(m) {
  const roles = S.roles.filter((r) => !r.is_default);
  const box = modal(h("div", {}, h("h2", { text: "Roles for " + m.username }), roles.length ? null : h("p", { class: "muted", text: "This server has no roles yet. Create them in Server settings → Roles." })));
  for (const r of roles) {
    const cb = h("input", { type: "checkbox", checked: m.roles.includes(r.id), style: { width: "auto" }, onchange: () => run(async () => { await request(`/api/v1/guilds/${enc(S.guildId)}/members/${enc(m.id)}/roles/${enc(r.id)}`, cb.checked ? "PUT" : "DELETE"); }) });
    box.append(h("label", { class: "row", style: { textTransform: "none" } }, cb, h("span", { class: "swatch", style: { background: swatchColor(r.color) } }), r.name));
  }
  box.append(h("div", { class: "actions" }, h("button", { type: "button", text: "Done", onclick: closeModal })));
}

/** Server settings: overview, roles, members, invites, bans, bots, audit log. */
async function serverSettings(tab = "overview") {
  const g = S.guild;
  const tabs = [
    ["overview", "Overview", can(P.MANAGE_GUILD)], ["roles", "Roles", can(P.MANAGE_ROLES)], ["members", "Members", can(P.KICK_MEMBERS) || can(P.MANAGE_ROLES) || can(P.BAN_MEMBERS)],
    ["invites", "Invites", can(P.MANAGE_GUILD)], ["bans", "Bans", can(P.BAN_MEMBERS)], ["bots", "Bots", g.owner_id === selfId], ["audit", "Audit log", can(P.VIEW_AUDIT_LOG)],
  ].filter((x) => x[2]);
  if (!tabs.some((x) => x[0] === tab)) tab = tabs[0]?.[0];
  const pane = h("div", { class: "pane" });
  const nav = h("nav", {}, h("div", { class: "category", text: g.name }), tabs.map(([k, l]) => h("button", { type: "button", class: k === tab ? "selected" : "", text: l, onclick: () => run(() => serverSettings(k)) })), h("button", { type: "button", text: "Close", onclick: closeModal }));
  modal([nav, pane], { wide: true });
  const reload = () => run(() => serverSettings(tab));
  if (tab === "overview") {
    const form = h("form", { onsubmit: (e) => { e.preventDefault(); run(async () => { await request("/api/v1/guilds/" + enc(g.id), "PATCH", { name: name.value, description: desc.value }); toast("Saved."); await loadGuildDetail(); }); } });
    const name = h("input", { id: "gs-name", value: g.name, maxLength: 100, required: true }), desc = h("textarea", { id: "gs-desc", value: g.description ?? "", rows: 3, maxLength: 1000 });
    form.append(h("h2", { text: "Server overview" }), h("label", { htmlFor: "gs-name", text: "Name" }), name, h("label", { htmlFor: "gs-desc", text: "Description" }), desc, h("div", { class: "actions" }, h("button", { type: "submit", text: "Save changes" })));
    add(pane, form, h("p", { class: "small muted", text: `${g.member_count} member(s) · created ${new Date(g.created_at).toLocaleDateString()}` }));
    if (g.owner_id === selfId) add(pane, h("h3", { text: "Danger zone" }), h("div", { class: "row wrap" },
      h("button", { type: "button", class: "secondary", text: "Transfer ownership", onclick: () => run(async () => {
        const v = await ask({ title: "Transfer ownership", text: "You will lose owner rights.", submit: "Transfer", danger: true, fields: [{ name: "user", label: "New owner", type: "select", options: S.members.filter((m) => m.id !== selfId).map((m) => [m.id, m.username]) }] });
        if (v?.user) { await request("/api/v1/guilds/" + enc(g.id) + "/transfer", "POST", { user_id: v.user }); await loadGuildDetail(); toast("Ownership transferred."); }
      }) }),
      h("button", { type: "button", class: "danger", text: "Delete server", onclick: () => run(async () => {
        const v = await ask({ title: "Delete " + g.name, text: "This deletes every channel and message. Type the server name to confirm.", submit: "Delete forever", danger: true, fields: [{ name: "confirm", label: "Server name", required: true }] });
        if (v?.confirm !== g.name) { if (v) toast("Name did not match.", true); return; }
        await request("/api/v1/guilds/" + enc(g.id), "DELETE"); await loadGuilds(); await selectHome();
      }) })));
  } else if (tab === "roles") {
    const roles = await request("/api/v1/guilds/" + enc(g.id) + "/roles");
    add(pane, h("div", { class: "row" }, h("h2", { text: "Roles" }), h("span", { class: "spacer" }), h("button", { type: "button", text: "Create role", onclick: () => run(async () => { await request("/api/v1/guilds/" + enc(g.id) + "/roles", "POST", { name: "new role" }); reload(); }) })),
      h("p", { class: "muted small", text: "Members get the union of @everyone and their roles. Higher roles can manage lower ones; nobody can grant permissions they lack." }));
    for (const role of roles) {
      const bits = BigInt(role.permissions);
      const checks = PERMS.map((p) => { const cb = h("input", { type: "checkbox", checked: (bits & p.bit) !== 0n }); cb.dataset.bit = p.bit.toString(); return h("label", {}, cb, p.label); });
      const name = h("input", { value: role.name, maxLength: 100, disabled: role.is_default });
      const color = h("input", { type: "color", value: "#" + role.color.toString(16).padStart(6, "0"), style: { width: "60px", padding: "2px" }, disabled: role.is_default });
      const hoist = h("input", { type: "checkbox", checked: role.hoist, style: { width: "auto" }, disabled: role.is_default });
      const card = h("details", { class: "list-row", style: { display: "block" } }, h("summary", { class: "row" }, h("span", { class: "swatch", style: { background: swatchColor(role.color) } }), h("strong", { text: role.name }), h("span", { class: "small muted", text: role.is_default ? "applies to everyone" : "position " + role.position })),
        role.is_default ? null : h("div", { class: "row" }, name, color, h("label", { class: "row", style: { margin: 0, textTransform: "none" } }, hoist, "Show separately")),
        h("div", { class: "perm-grid" }, checks),
        h("div", { class: "actions" },
          role.is_default ? null : h("button", { type: "button", class: "danger", text: "Delete role", onclick: () => run(async () => { if (await confirmModal("Delete role " + role.name, "Members lose this role's permissions.", "Delete")) { await request(`/api/v1/guilds/${enc(g.id)}/roles/${enc(role.id)}`, "DELETE"); reload(); } }) }),
          h("button", { type: "button", text: "Save role", onclick: () => run(async () => {
            let perms = 0n; for (const l of checks) { const cb = l.querySelector("input"); if (cb.checked) perms |= BigInt(cb.dataset.bit); }
            await request(`/api/v1/guilds/${enc(g.id)}/roles/${enc(role.id)}`, "PATCH", { permissions: perms.toString(), ...(role.is_default ? {} : { name: name.value, color: parseInt(color.value.slice(1), 16), hoist: hoist.checked }) });
            toast("Role saved."); await loadGuildDetail(); renderMembers();
          }) })));
      add(pane, card);
    }
  } else if (tab === "members") {
    await loadGuildDetail();
    add(pane, h("h2", { text: "Members (" + S.members.length + ")" }));
    for (const m of S.members) add(pane, h("div", { class: "list-row" }, avatar(m.username, m.presence),
      h("div", { class: "meta" }, h("strong", { text: m.nickname || m.username }), h("div", { class: "small muted", text: "@" + m.username + " · joined " + new Date(m.joined_at).toLocaleDateString() + " · " + (m.roles.map((id) => S.roles.find((r) => r.id === id)?.name).filter(Boolean).join(", ") || "no roles") })),
      m.id === g.owner_id ? h("span", { class: "pill ok", text: "Owner" }) : h("button", { type: "button", class: "ghost", text: "⋯", onclick: (e) => memberMenu(e.clientX - 150, e.clientY, m) })));
  } else if (tab === "invites") {
    const invites = await request("/api/v1/guilds/" + enc(g.id) + "/invites");
    add(pane, h("div", { class: "row" }, h("h2", { text: "Active invites" }), h("span", { class: "spacer" }), h("button", { type: "button", text: "Create invite", onclick: () => run(inviteDialog) })),
      h("p", { class: "muted small", text: "Codes are stored only as hashes, so only the first characters are shown." }), invites.length ? null : h("p", { class: "muted", text: "No active invites." }),
      invites.map((i) => h("div", { class: "list-row" }, h("div", { class: "meta" }, h("code", { text: i.code_hint + "…" }), " ", h("span", { class: "small muted", text: `by ${i.created_by} · ${i.uses}/${i.max_uses} uses · expires ${new Date(i.expires_at).toLocaleString()}` })),
        h("button", { type: "button", class: "danger", text: "Revoke", onclick: () => run(async () => { await request(`/api/v1/guilds/${enc(g.id)}/invites/${enc(i.id)}`, "DELETE"); reload(); }) }))));
  } else if (tab === "bans") {
    const bans = await request("/api/v1/guilds/" + enc(g.id) + "/bans");
    add(pane, h("h2", { text: "Bans" }), bans.length ? null : h("p", { class: "muted", text: "Nobody is banned." }),
      bans.map((b) => h("div", { class: "list-row" }, avatar(b.username), h("div", { class: "meta" }, h("strong", { text: b.username }), h("div", { class: "small muted", text: (b.reason || "No reason") + " · " + new Date(b.created_at).toLocaleDateString() })),
        h("button", { type: "button", class: "secondary", text: "Unban", onclick: () => run(async () => { await request(`/api/v1/guilds/${enc(g.id)}/bans/${enc(b.user_id)}`, "DELETE"); reload(); }) }))));
  } else if (tab === "bots") {
    const [installed, apps] = await Promise.all([request("/api/v1/guilds/" + enc(g.id) + "/bots"), request("/api/v1/developer/apps")]);
    const select = h("select", {}, apps.map((a) => h("option", { value: a.id, text: a.name })));
    const events = h("input", { type: "checkbox", style: { width: "auto" } });
    add(pane, h("h2", { text: "Bots" }), h("p", { class: "muted small", text: "Bots never receive message content or ciphertext — only message metadata, and only with the event permission." }),
      installed.map((b) => h("div", { class: "list-row" }, h("div", { class: "meta" }, h("strong", { text: b.name }), h("div", { class: "small muted", text: b.can_read_events ? "Receives message metadata events" : "No event access" })),
        h("button", { type: "button", class: "danger", text: "Remove", onclick: () => run(async () => { await request(`/api/v1/guilds/${enc(g.id)}/bots/${enc(b.id)}`, "DELETE"); reload(); }) }))),
      apps.length ? h("div", {}, h("label", { text: "Install one of your developer apps" }), h("div", { class: "row" }, select, h("label", { class: "row", style: { margin: 0, textTransform: "none", whiteSpace: "nowrap" } }, events, "Metadata events"),
        h("button", { type: "button", text: "Install", onclick: () => run(async () => { await request("/api/v1/guilds/" + enc(g.id) + "/bots", "POST", { app_id: select.value, can_read_events: events.checked }); reload(); }) })))
        : h("p", { class: "muted", text: "Create a developer app in User settings → Developer to install a bot." }));
  } else if (tab === "audit") {
    const entries = await request("/api/v1/guilds/" + enc(g.id) + "/audit-log");
    add(pane, h("h2", { text: "Audit log" }), entries.length ? null : h("p", { class: "muted", text: "No entries yet." }),
      entries.map((e) => h("div", { class: "list-row" }, h("div", { class: "meta" }, h("strong", { text: e.actor_username ?? "deleted user" }), " ", h("code", { text: e.action }), " ", h("span", { class: "small muted", text: (displayName(e.target_id) ?? S.channels.find((c) => c.id === e.target_id)?.name ?? S.roles.find((r) => r.id === e.target_id)?.name ?? e.target_id ?? "") }),
        Object.keys(e.details ?? {}).length ? h("div", { class: "small muted", text: JSON.stringify(e.details) }) : null), h("span", { class: "small muted", text: fmtTime(e.created_at) }))));
  }
}

// ------------------------------------------------------------------ people
async function startDM(userId) {
  const dm = await request("/api/v1/users/@me/channels", "POST", { recipient_ids: [userId] });
  closeModal(); await loadDMs();
  await selectHome(); await openDM(S.dms.find((d) => d.guild_id === dm.guild_id) ?? dm);
}
async function newGroupDialog() {
  const friends = S.relationships.filter((r) => r.status === "friend");
  if (!friends.length) { toast("Add friends first to start a group conversation."); return; }
  const checks = friends.map((f) => { const cb = h("input", { type: "checkbox", value: f.id, style: { width: "auto" } }); return [cb, h("label", { class: "row", style: { textTransform: "none" } }, cb, avatar(f.username, f.presence), f.display_name || f.username)]; });
  const name = h("input", { maxLength: 100, placeholder: "Optional group name" });
  modal(h("form", { onsubmit: (e) => { e.preventDefault(); run(async () => {
    const ids = checks.filter(([cb]) => cb.checked).map(([cb]) => cb.value);
    if (!ids.length) throw Error("Pick at least one friend.");
    const dm = await request("/api/v1/users/@me/channels", "POST", { recipient_ids: ids, ...(name.value ? { name: name.value } : {}) });
    closeModal(); await loadDMs(); await openDM(S.dms.find((d) => d.guild_id === dm.guild_id) ?? dm);
  }); } }, h("h2", { text: "New conversation" }), h("label", { text: "Name" }), name, h("label", { text: "Friends (up to 9)" }), checks.map(([, l]) => l), h("div", { class: "actions" }, h("button", { type: "submit", text: "Create" }))));
}
async function blockUser(id) { if (await confirmModal("Block user", "They will not be able to message you or send friend requests.", "Block")) { await request("/api/v1/users/@me/relationships/" + enc(id), "PUT", { type: "blocked" }); await loadRelationships(); } }
async function profileDialog(userId) {
  const p = await request("/api/v1/users/" + enc(userId) + "/profile");
  const devices = await request("/api/v1/users/" + enc(userId) + "/devices").catch(() => []);
  const accent = "#" + Number(p.accent_color ?? 7331258).toString(16).padStart(6, "0");
  const deviceRows = await Promise.all(devices.map(async (d) => {
    if (userId === selfId) return h("div", { class: "list-row" }, h("div", { class: "meta" }, h("div", { class: "fingerprint", text: await safetyNumber(d.identity_key) }), h("span", { class: "pill ok", text: "Your device" })));
    const st = trust.status(d.id, d.identity_key);
    const label ={ verified: ["Verified", "ok"], pinned: ["Trusted on first use", "warn"], unknown: ["Not yet seen", "warn"], changed: ["KEY CHANGED", "bad"] }[st];
    return h("div", { class: "list-row" }, h("div", { class: "meta" }, h("div", { class: "fingerprint", text: await safetyNumber(d.identity_key) }), h("span", { class: "pill " + label[1], text: label[0] })),
      st === "verified" ? null : h("button", { type: "button", class: "secondary", text: st === "changed" ? "Accept new key" : "Mark verified", title: "Only after comparing this safety number with them in person or another trusted channel", onclick: () => run(async () => { trust.verify(d.id, d.identity_key); toast("Device marked as verified."); await profileDialog(userId); }) }));
  }));
  const rel = p.relationship;
  modal(h("div", { class: "profile-card" }, h("div", { class: "banner", style: { background: accent } }), avatar(p.username, p.presence, true),
    h("h2", { text: p.display_name || p.username, style: { marginBottom: "0" } }), h("div", { class: "muted", text: "@" + p.username + " · " + (presenceLabel[p.presence] ?? "") + (p.custom_status ? " · " + p.custom_status : "") }),
    p.bio ? h("p", { text: p.bio }) : null,
    p.social_links.length ? h("div", {}, h("h4", { text: "Links" }), p.social_links.map((l) => h("div", {}, h("a", { href: l.url, target: "_blank", rel: "noopener noreferrer", text: l.provider + (l.verified ? "" : " (unverified)") })))) : null,
    p.mutual_guilds.length ? h("p", { class: "small muted", text: "Mutual servers: " + p.mutual_guilds.map((g) => g.name).join(", ") }) : null,
    h("p", { class: "small muted", text: "Member since " + new Date(p.created_at).toLocaleDateString() }),
    devices.length ? h("div", {}, h("h4", { text: "Encryption devices — compare safety numbers" }), deviceRows) : null,
    userId === selfId ? null : h("div", { class: "actions" },
      h("button", { type: "button", text: "Message", onclick: () => run(() => startDM(userId)) }),
      rel === "friend" ? h("button", { type: "button", class: "secondary", text: "Remove friend", onclick: () => run(async () => { await request("/api/v1/users/@me/relationships/" + enc(userId), "DELETE"); await loadRelationships(); closeModal(); }) })
        : rel === "incoming" ? h("button", { type: "button", class: "secondary", text: "Accept request", onclick: () => run(async () => { await request("/api/v1/users/@me/relationships/" + enc(userId), "PUT", { type: "friend" }); await loadRelationships(); closeModal(); }) })
        : rel ? null : h("button", { type: "button", class: "secondary", text: "Add friend", onclick: () => run(async () => { await request("/api/v1/users/@me/relationships", "POST", { username: p.username }); await loadRelationships(); toast("Friend request sent."); closeModal(); }) }),
      rel === "blocked" ? h("button", { type: "button", class: "secondary", text: "Unblock", onclick: () => run(async () => { await request("/api/v1/users/@me/relationships/" + enc(userId), "DELETE"); await loadRelationships(); closeModal(); }) })
        : h("button", { type: "button", class: "danger", text: "Block", onclick: () => run(() => blockUser(userId)) }))));
}

// ------------------------------------------------------------------ user settings
// Held by reference: the section moves into the settings modal and back.
const templates = $("settings-templates"), encryptionSection = $("settings-encryption");
function restoreTemplates() { if (encryptionSection.parentElement !== templates) templates.append(encryptionSection); }
$("settings-button").addEventListener("click", () => run(() => userSettings()));
$("vault-button").addEventListener("click", () => run(() => userSettings("encryption")));
async function userSettings(tab = "account") {
  const tabs = [["account", "My account"], ["profile", "Profile"], ["security", "Security"], ["encryption", "Encryption & devices"], ["notifications", "Notifications"], ["developer", "Developer"], ...(S.me?.is_admin ? [["admin", "Instance admin"]] : [])];
  const pane = h("div", { class: "pane" });
  restoreTemplates();
  modal([h("nav", {}, h("div", { class: "category", text: "User settings" }), tabs.map(([k, l]) => h("button", { type: "button", class: k === tab ? "selected" : "", text: l, onclick: () => run(() => userSettings(k)) })),
    h("button", { type: "button", class: "danger", id: "logout", text: "Sign out", onclick: () => run(logout) }), h("button", { type: "button", text: "Close", onclick: closeModal })), pane], { wide: true });
  if (tab === "account") {
    const sessions = await request("/api/v1/auth/sessions");
    add(pane, h("h2", { text: "My account" }), h("div", { class: "row" }, avatar(S.me.username, null, true), h("div", {}, h("h3", { text: S.me.username, style: { margin: 0 } }), h("div", { class: "small muted fingerprint", text: S.me.id }))),
      h("h3", { text: "Sessions" }), h("p", { id: "session-count", class: "muted", text: sessions.length + " active session(s)." }),
      h("button", { type: "button", class: "danger", id: "logout-all", text: "Sign out all devices", onclick: () => run(async () => { if (!(await confirmModal("Sign out everywhere", "Every session, including this one, is revoked.", "Sign out all"))) return; await request("/api/v1/auth/logout-all", "POST"); signedOut("All sessions revoked. Please sign in again."); }) }),
      h("h3", { text: "Delete account" }), h("p", { class: "muted small", text: "Permanently deletes your account, your messages and your devices. Transfer or delete servers you own first." }),
      h("button", { type: "button", class: "danger", text: "Delete my account", onclick: () => run(async () => {
        const v = await ask({ title: "Delete account", text: "This cannot be undone.", submit: "Delete forever", danger: true, fields: [{ name: "password", label: "Account password", type: "password", required: true, min: 12 }] });
        if (!v) return;
        await request("/api/v1/users/@me", "DELETE", { password: v.password });
        signedOut("Your account was deleted.");
      }) }));
  } else if (tab === "profile") {
    const profile = await request("/api/v1/profiles/@me");
    const form = h("form", { id: "profile-form", onsubmit: (e) => { e.preventDefault(); run(async () => {
      await request("/api/v1/profiles/@me", "PUT", { display_name: dn.value, bio: bio.value });
      S.settings = await request("/api/v1/users/@me/settings", "PATCH", { accent_color: parseInt(accent.value.slice(1), 16) });
      toast("Profile saved."); renderUserPanel();
    }); } });
    const dn = h("input", { id: "display-name", value: profile.display_name, maxLength: 50 }), bio = h("textarea", { id: "bio", value: profile.bio, maxLength: 500, rows: 3 });
    const accent = h("input", { type: "color", value: "#" + Number(S.settings.accent_color ?? 7331258).toString(16).padStart(6, "0"), style: { width: "80px", padding: "2px" } });
    form.append(h("h2", { text: "Profile" }), h("label", { htmlFor: "display-name", text: "Display name" }), dn, h("label", { htmlFor: "bio", text: "About me" }), bio, h("label", { text: "Banner colour" }), accent, h("div", { class: "actions" }, h("button", { type: "submit", text: "Save profile" })));
    const provider = h("select", { id: "provider" }, ["twitch", "youtube", "github", "steam"].map((p) => h("option", { value: p, text: p[0].toUpperCase() + p.slice(1) })));
    const url = h("input", { id: "social-url", type: "url", placeholder: "https://...", required: true });
    const social = h("form", { id: "social-form", onsubmit: (e) => { e.preventDefault(); run(async () => { await request("/api/v1/profiles/@me/links", "PUT", { provider: provider.value, url: url.value }); toast("Unverified link saved."); await userSettings("profile"); }); } },
      h("h3", { text: "Linked accounts (unverified)" }), h("p", { class: "small muted", text: "Links are shown as unverified: Nexora does not yet confirm account ownership." }), h("div", { class: "row" }, provider, url, h("button", { type: "submit", text: "Add" })));
    add(pane, form, social, h("div", { id: "social-links" }, profile.social_links.map((l) => h("div", { class: "list-row" }, h("a", { class: "meta", href: l.url, target: "_blank", rel: "noopener noreferrer", text: l.provider + " (unverified)" }),
      h("button", { type: "button", class: "ghost", text: "Remove", onclick: () => run(async () => { await request("/api/v1/profiles/@me/links/" + l.provider, "DELETE"); await userSettings("profile"); }) })))));
  } else if (tab === "security") {
    add(pane, h("h2", { text: "Password" }), h("p", { class: "muted", text: "Changing your password signs out every other session." }),
      h("button", { type: "button", class: "secondary", text: "Change password", onclick: () => run(async () => {
        const v = await ask({ title: "Change password", fields: [{ name: "current_password", label: "Current password", type: "password", required: true, min: 12 }, { name: "new_password", label: "New password (12+ characters)", type: "password", required: true, min: 12, max: 256 }, { name: "confirm", label: "Confirm new password", type: "password", required: true, min: 12, max: 256 }] });
        if (!v) return;
        if (v.new_password !== v.confirm) throw new Error("New passwords do not match.");
        await request("/api/v1/auth/password", "POST", { current_password: v.current_password, new_password: v.new_password });
        toast("Password changed. Other sessions were signed out.");
      }) }));
    const passkeys = await request("/api/v1/auth/passkeys");
    add(pane, h("h2", { text: "Passkeys" }), h("p", { class: "muted", text: "Sign in without a password using your device's biometrics or a security key. Passkeys are phishing-resistant." }),
      passkeys.map((k) => h("div", { class: "list-row" }, h("div", { class: "meta" }, h("strong", { text: k.name }), h("div", { class: "small muted", text: "Added " + new Date(k.created_at).toLocaleDateString() + (k.last_used_at ? " · last used " + fmtTime(k.last_used_at) : "") })),
        h("button", { type: "button", class: "danger", text: "Remove", onclick: () => run(async () => { await request("/api/v1/auth/passkeys/" + enc(k.id), "DELETE"); await userSettings("security"); }) }))),
      h("button", { type: "button", class: "secondary", text: "Add a passkey", onclick: () => run(addPasskey) }));
    add(pane, h("h2", { text: "Two-factor authentication" }), h("p", { class: "muted", text: "Protect sign-in with an authenticator app (TOTP). You'll receive one-time recovery codes." }),
      h("button", { type: "button", text: "Enable authenticator app", onclick: () => run(async () => {
        const v = await ask({ title: "Confirm your password", fields: [{ name: "password", label: "Account password", type: "password", required: true, min: 12 }] });
        if (!v) return;
        const e = await request("/api/v1/auth/mfa/enroll", "POST", { password: v.password });
        const uri = `otpauth://totp/Nexora:${enc(S.me.username)}?secret=${e.secret}&issuer=Nexora&period=${e.period}&digits=${e.digits}&algorithm=${e.algorithm}`;
        const code = await ask({ title: "Add to your authenticator", text: "Enter this secret (or the otpauth URI) in your authenticator app, then type the 6-digit code it shows. Secret: " + e.secret, fields: [{ name: "uri", label: "otpauth URI", value: uri }, { name: "code", label: "6-digit code", required: true, pattern: "[0-9]{6}", max: 6 }], submit: "Verify" });
        if (!code) return;
        const done = await request("/api/v1/auth/mfa/confirm", "POST", { code: code.code });
        modal(h("div", {}, h("h2", { text: "Save your recovery codes" }), h("p", { class: "muted", text: done.warning }), h("pre", { text: done.recovery_codes.join("\n") }), h("div", { class: "actions" }, h("button", { type: "button", text: "I saved them", onclick: closeModal }))));
      }) }));
  } else if (tab === "encryption") {
    add(pane, encryptionSection);
    await renderDeviceList();
  } else if (tab === "notifications") {
    const perm = "Notification" in globalThis ? Notification.permission : "unsupported";
    add(pane, h("h2", { text: "Notifications" }), h("p", { class: "muted", text: "Desktop notifications for direct messages and @mentions while Nexora is in the background. Message text is decrypted locally for the notification only." }),
      h("p", { text: "Current permission: " + perm }), perm === "default" ? h("button", { type: "button", text: "Enable desktop notifications", onclick: () => run(async () => { await Notification.requestPermission(); await userSettings("notifications"); }) }) : null);
  } else if (tab === "admin") {
    await adminPanel(pane);
  } else if (tab === "developer") {
    const apps = await request("/api/v1/developer/apps");
    add(pane, h("div", { class: "row" }, h("h2", { text: "Developer applications" }), h("span", { class: "spacer" }), h("button", { type: "button", text: "New application", onclick: () => run(async () => {
      const v = await ask({ title: "New application", fields: [{ name: "name", label: "Name", required: true, min: 2, max: 80 }] });
      if (!v) return;
      const a = await request("/api/v1/developer/apps", "POST", v);
      await showToken(a.bot_token, a.warning); }) })),
      h("p", { class: "small muted", text: "Bot tokens authenticate with Authorization: Bot <token> and only see metadata. See examples/metadata-bot.mjs." }),
      apps.map((a) => h("div", { class: "list-row" }, h("div", { class: "meta" }, h("strong", { text: a.name }), h("div", { class: "small muted fingerprint", text: a.id })),
        h("button", { type: "button", class: "secondary", text: "Rotate token", onclick: () => run(async () => { if (!(await confirmModal("Rotate token", "The old token stops working immediately.", "Rotate"))) return; const r = await request("/api/v1/developer/apps/" + enc(a.id) + "/rotate-token", "POST"); await showToken(r.bot_token, r.warning); }) }),
        h("button", { type: "button", class: "danger", text: "Delete", onclick: () => run(async () => { if (await confirmModal("Delete " + a.name, "The bot is disconnected and removed from every server.", "Delete")) { await request("/api/v1/developer/apps/" + enc(a.id), "DELETE"); await userSettings("developer"); } }) }))));
  }
}
async function showToken(t, warning) {
  modal(h("div", {}, h("h2", { text: "Bot token" }), h("p", { class: "muted", text: warning }), h("input", { value: t, readOnly: true, onfocus: (e) => e.target.select() }),
    h("div", { class: "actions" }, h("button", { type: "button", text: "Copy", onclick: () => run(async () => { await navigator.clipboard.writeText(t); toast("Copied."); }) }), h("button", { type: "button", class: "secondary", text: "Done", onclick: () => run(() => userSettings("developer")) }))));
}
async function logout() {
  try { await request("/api/v1/auth/logout", "POST"); } finally { signedOut("Signed out."); }
}
async function renderDeviceList() {
  const list = $("device-list");
  if (!list) return;
  const devices = (await request("/api/v1/devices")).map((d) => ({ ...d, user_id: selfId }));
  const own = unlockedDevice ? await fingerprint(await publicBundle(unlockedDevice)) : null;
  // How other people's clients will see each of your devices (fresh trust store = first sight).
  const view = await evaluateDevices(devices, new TrustStore(null), null);
  const mine = devices.find((d) => d.identity_key === own);
  const canApprove = mine && ["pinned", "attested"].includes(view.get(mine.id));
  const label = { pinned: ["Primary device", "ok"], attested: ["Approved", "ok"], unattested: ["Waiting for approval", "warn"], invalid: ["No public key yet", "warn"] };
  renderBackupStatus();
  const rows = await Promise.all(devices.map(async (d) => h("div", { class: "list-row" },
    h("div", { class: "meta" }, h("strong", { text: d.name }), " ", d.identity_key === own ? h("span", { class: "pill ok", text: "this browser" }) : null, " ", h("span", { class: "pill " + (label[view.get(d.id)]?.[1] ?? "warn"), text: label[view.get(d.id)]?.[0] ?? view.get(d.id) }),
      h("div", { class: "fingerprint", text: "Safety number " + (await safetyNumber(d.identity_key)) }), h("div", { class: "small muted", text: "Added " + new Date(d.created_at).toLocaleString() })),
    view.get(d.id) === "unattested" && canApprove && d.id !== mine.id ? h("button", { type: "button", text: "Approve", onclick: () => run(() => approveDevice(d, mine)) }) : null,
    h("button", { type: "button", class: "danger", text: "Revoke", onclick: () => run(async () => { if (!(await confirmModal("Revoke " + d.name, "This device will stop receiving new room keys. Keys it already holds are not recalled.", "Revoke"))) return; await request("/api/v1/devices/" + enc(d.id), "DELETE"); await renderDeviceList(); }) }))));
  if (mine && view.get(mine.id) === "unattested") rows.unshift(h("div", { class: "warning", text: "This browser is waiting for approval. Open Settings → Encryption on one of your other devices and approve it (compare the safety number " + (await safetyNumber(mine.identity_key)) + "). Until then, other people's clients will not share keys with it." }));
  list.replaceChildren(...(rows.length ? rows : [h("p", { class: "muted", text: "No devices registered yet." })]));
}
$("device-enroll-form").addEventListener("submit", (event) => { event.preventDefault(); run(async () => {
  if (await loadDeviceVault()) {
    if (!(await confirmModal("Replace local device", "This browser already has a device vault. Replacing it makes messages encrypted only for the old device unreadable here.", "Replace"))) return;
  }
  const proof = $("device-proof").value, passphrase = $("device-vault-passphrase").value;
  if (passphrase.length < 16) throw new Error("Use a vault passphrase of at least 16 characters.");
  const device = await createDevice(), bundle = await publicBundle(device), id = await fingerprint(bundle);
  const vault = await encryptDeviceVault(device, passphrase);
  await request("/api/v1/devices", "POST", { name: $("device-name").value, identity_key: id, public_bundle: bundle, password: proof });
  await saveDeviceVault(vault);
  $("device-proof").value = ""; $("device-vault-passphrase").value = "";
  unlockedDevice = device; S.device = device; keyring.clear();
  $("device-vault-status").textContent = "Encrypted device created and unlocked. Safety number: " + (await safetyNumber(id));
  renderUserPanel(); await renderDeviceList(); await afterUnlock();
}); });
$("backup-setup").addEventListener("click", () => run(setupBackup));
$("backup-restore").addEventListener("click", () => run(restoreBackup));
$("device-unlock-form").addEventListener("submit", (event) => { event.preventDefault(); run(async () => {
  const vault = await loadDeviceVault(); if (!vault) throw new Error("No local device vault found. Create one below.");
  let device;
  try { device = await decryptDeviceVault(vault, $("device-unlock-passphrase").value); } catch { throw new Error("Wrong vault passphrase."); }
  unlockedDevice = device; S.device = device; keyring.clear();
  $("device-unlock-passphrase").value = "";
  const id = await fingerprint(await publicBundle(device));
  $("device-vault-status").textContent = "Unlocked. Safety number: " + (await safetyNumber(id));
  renderUserPanel(); await renderDeviceList(); await afterUnlock();
}); });
function promptUnlock() {
  const pass = h("input", { type: "password", required: true, autocomplete: "current-password", id: "quick-unlock" });
  modal(h("form", { onsubmit: (e) => { e.preventDefault(); run(async () => {
    const vault = await loadDeviceVault();
    try { unlockedDevice = await decryptDeviceVault(vault, pass.value); } catch { throw new Error("Wrong vault passphrase."); }
    S.device = unlockedDevice; keyring.clear(); closeModal(); renderUserPanel(); await afterUnlock(); toast("Encryption unlocked.");
  }); } }, h("h2", { text: "Unlock encryption" }), h("p", { class: "muted", text: "Enter this browser's device-vault passphrase to read and send encrypted messages. It never leaves this browser." }),
    h("label", { htmlFor: "quick-unlock", text: "Vault passphrase" }), pass, h("div", { class: "actions" }, h("button", { type: "button", class: "secondary", text: "Later", onclick: closeModal }), h("button", { type: "submit", text: "Unlock" }))));
}
async function afterUnlock() {
  await loadRecoveryKey();
  scheduleBackup(0);
  if (!S.channelId) return;
  await keyring.sync(S.channelId).catch((e) => toast("Encryption: " + e.message, true));
  for (const m of S.messages) { delete m._state; delete m._text; await decryptRow(m); }
  renderMessages(); updateComposer(); $("messages").scrollTop = $("messages").scrollHeight;
}

// ------------------------------------------------------------------ passkeys
const toB64 = (buf) => { let s = ""; for (const b of new Uint8Array(buf)) s += String.fromCharCode(b); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, ""); };
const fromB64 = (text) => Uint8Array.from(atob(text.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - text.length % 4) % 4)), (c) => c.charCodeAt(0));
async function addPasskey() {
  if (!globalThis.PublicKeyCredential) throw new Error("This browser does not support passkeys.");
  const v = await ask({ title: "Add a passkey", fields: [{ name: "password", label: "Account password", type: "password", required: true, min: 12 }, { name: "name", label: "Passkey name", value: "My passkey", max: 60 }] });
  if (!v) return;
  const o = await request("/api/v1/auth/passkeys/register/options", "POST", { password: v.password });
  const credential = await navigator.credentials.create({ publicKey: { ...o, challenge: fromB64(o.challenge), user: { ...o.user, id: fromB64(o.user.id) }, excludeCredentials: o.excludeCredentials.map((c) => ({ ...c, id: fromB64(c.id) })) } });
  if (!credential) return;
  await request("/api/v1/auth/passkeys/register", "POST", { name: v.name || "Passkey", credential: { id: credential.id, response: { clientDataJSON: toB64(credential.response.clientDataJSON), attestationObject: toB64(credential.response.attestationObject) } } });
  toast("Passkey added. You can now sign in with it.");
  await userSettings("security");
}

// ------------------------------------------------------------------ device approval (cross-signing)
async function approveDevice(target, mine) {
  const sn = await safetyNumber(target.identity_key);
  if (!(await confirmModal("Approve " + target.name, "Only approve a device you just set up yourself. Check that the new device shows this safety number: " + sn, "Approve"))) return;
  const signature = await attestDevice(unlockedDevice, selfId, target.id, target.identity_key);
  await request("/api/v1/devices/" + enc(target.id) + "/attestation", "PUT", { signer_device_id: mine.id, signature });
  toast("Device approved.");
  await userSettings("encryption");
  if (S.channelId) await keyring.sync(S.channelId).catch(() => {});
}
async function onDeviceAdded(d) {
  await renderDeviceList().catch(() => {});
  if (!unlockedDevice) { toast("A new device \"" + d.name + "\" was added to your account. Unlock encryption here to approve it."); return; }
  const own = await fingerprint(await publicBundle(unlockedDevice));
  if ((await request("/api/v1/devices")).some((x) => x.id === d.device_id && x.identity_key === own)) return; // that's us
  toast("New device \"" + d.name + "\" added to your account. If it was you, approve it in Settings → Encryption & devices.", true);
}

// ------------------------------------------------------------------ recovery-key backup
let recoveryKey = null, backupTimer = null, backupRunning = false;
const recoveryStorageKey = () => "nexora-recovery-v1:" + selfId;
async function loadRecoveryKey() {
  recoveryKey = null;
  const sealed = localStorage.getItem(recoveryStorageKey());
  if (sealed && unlockedDevice) { try { recoveryKey = await openForDevice(unlockedDevice, sealed); } catch { localStorage.removeItem(recoveryStorageKey()); } }
  renderBackupStatus();
}
async function rememberRecoveryKey(key) {
  recoveryKey = key;
  localStorage.setItem(recoveryStorageKey(), await sealForDevice(unlockedDevice, key));
  renderBackupStatus();
}
function renderBackupStatus() {
  const el = $("backup-status"); if (!el) return;
  el.textContent = !unlockedDevice ? "Unlock this device to manage key backup." : recoveryKey ? "Key backup is on: room keys from this browser are backed up, encrypted with your recovery key." : "Key backup is off. Without it, a lost device means lost message history.";
  $("backup-setup").textContent = recoveryKey ? "Create a new recovery key" : "Turn on key backup";
}
function scheduleBackup(delay = 3000) { clearTimeout(backupTimer); backupTimer = setTimeout(() => syncBackup().catch((e) => console.warn("Key backup:", e.message)), delay); }
/** Merges local and server backup both ways; version numbers prevent devices clobbering each other. */
async function syncBackup(attempt = 0) {
  if (!recoveryKey || !unlockedDevice || backupRunning) return;
  backupRunning = true;
  try {
    let remote = { version: 0, keys: {} };
    const b = await request("/api/v1/users/@me/key-backup");
    if (b.ciphertext) remote = { version: b.version, keys: await decryptBackup(b.ciphertext, recoveryKey, selfId) };
    const imported = await keyring.importKeys(remote.keys);
    const local = await keyring.exportKeys();
    const merged = structuredClone(remote.keys);
    let changed = false;
    for (const [c, epochs] of Object.entries(local)) for (const [e, k] of Object.entries(epochs)) if (!merged[c]?.[e]) { (merged[c] ??= {})[e] = k; changed = true; }
    if (changed) {
      try { await request("/api/v1/users/@me/key-backup", "PUT", { version: remote.version + 1, ciphertext: await encryptBackup(merged, recoveryKey, selfId) }); }
      catch (error) { if (/conflict/i.test(error.message) && attempt < 2) { backupRunning = false; return syncBackup(attempt + 1); } throw error; }
    }
    if (imported && S.channelId) await afterKeysImported();
  } finally { backupRunning = false; }
}
async function afterKeysImported() {
  for (const m of S.messages) { delete m._state; delete m._text; await decryptRow(m); }
  renderMessages(); updateComposer();
}
async function setupBackup() {
  if (!unlockedDevice) throw new Error("Unlock this device first.");
  const key = generateRecoveryKey();
  const ok = await ask({ title: "Your recovery key", text: "Write this down and keep it somewhere safe. It is the only way to restore your encrypted message history on a new device. Nexora cannot recover it for you.", submit: "I saved it", fields: [{ name: "key", label: "Recovery key", value: key }] });
  if (!ok) return;
  // A new recovery key re-encrypts everything this browser knows; other devices' keys merge in on their next sync.
  await rememberRecoveryKey(key);
  await request("/api/v1/users/@me/key-backup", "DELETE");
  await syncBackup();
  toast("Key backup is on.");
  await userSettings("encryption");
}
async function restoreBackup() {
  if (!unlockedDevice) throw new Error("Unlock this device first.");
  const v = await ask({ title: "Restore from recovery key", text: "Enter the recovery key you saved when you turned on key backup.", submit: "Restore", fields: [{ name: "key", label: "Recovery key", required: true, placeholder: "XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX" }] });
  if (!v) return;
  const key = normalizeRecoveryKey(v.key);
  const b = await request("/api/v1/users/@me/key-backup");
  if (!b.ciphertext) throw new Error("No key backup exists for this account yet.");
  const keys = await decryptBackup(b.ciphertext, key, selfId);
  const added = await keyring.importKeys(keys);
  await rememberRecoveryKey(key);
  toast("Restored " + added + " room key(s).");
  if (S.channelId) await afterKeysImported();
  await userSettings("encryption");
}

// ------------------------------------------------------------------ reports
async function reportDialog(type, id, plaintext = "") {
  const v = await ask({ title: "Report " + type, text: "Reports go to this instance's administrators. Messages are end-to-end encrypted, so admins only see what you choose to include.", submit: "Send report", fields: [
    { name: "reason", label: "What's wrong?", type: "textarea", max: 1000 },
    ...(plaintext ? [{ name: "include", label: "Include the message text as evidence", type: "checkbox", value: true }] : [])] });
  if (!v) return;
  if (!v.reason.trim()) throw new Error("Please describe the problem.");
  await request("/api/v1/reports", "POST", { target_type: type, target_id: id, reason: v.reason, evidence: v.include ? plaintext.slice(0, 4000) : "" });
  toast("Report sent. Thank you.");
}

// ------------------------------------------------------------------ instance administration
async function adminPanel(pane, section = "reports", status = "open") {
  const stats = await request("/api/v1/admin/stats");
  const nav = h("div", { class: "tabs" }, [["reports", "Reports"], ["users", "Users"], ["guilds", "Servers"]].map(([k, l]) => h("button", { type: "button", class: k === section ? "selected" : "", text: l, onclick: () => run(() => { pane.replaceChildren(); return adminPanel(pane, k); }) })));
  add(pane, h("h2", { text: "Instance administration" }),
    h("p", { class: "small muted", text: `${stats.users} users (${stats.suspended} suspended) · ${stats.active_users} with active sessions · ${stats.communities} servers · ${stats.messages} encrypted messages · ${stats.open_reports} open reports` }), nav);
  const reload = () => run(() => { pane.replaceChildren(); return adminPanel(pane, section, status); });
  if (section === "reports") {
    const reports = await request("/api/v1/admin/reports?status=" + status);
    add(pane, h("div", { class: "tabs", style: { margin: "10px 0" } }, ["open", "resolved", "dismissed"].map((s) => h("button", { type: "button", class: s === status ? "selected" : "", text: s, onclick: () => run(() => { pane.replaceChildren(); return adminPanel(pane, "reports", s); }) }))),
      reports.length ? null : h("p", { class: "muted", text: "No " + status + " reports." }),
      reports.map((r) => h("div", { class: "list-row", style: { display: "block" } },
        h("div", {}, h("span", { class: "pill warn", text: r.target_type }), " ", h("strong", { text: r.target_user ?? r.guild_name ?? r.target_id }), " ", h("span", { class: "small muted", text: "reported by " + (r.reporter ?? "deleted user") + " · " + fmtTime(r.created_at) + (r.guild_name ? " · in " + r.guild_name : "") })),
        h("p", { text: r.reason }),
        r.evidence ? h("pre", { text: "Reporter-supplied evidence (cannot be verified by the server):\n" + r.evidence }) : null,
        r.resolution_note ? h("p", { class: "small muted", text: "Note: " + r.resolution_note + (r.resolved_by ? " — " + r.resolved_by : "") }) : null,
        h("div", { class: "row wrap" },
          r.target_type === "message" ? h("button", { type: "button", class: "danger", text: "Delete message", onclick: () => run(async () => { await request("/api/v1/admin/messages/" + enc(r.target_id), "DELETE"); toast("Message deleted."); }) }) : null,
          r.target_user_id ? h("button", { type: "button", class: "danger", text: "Suspend " + (r.target_user ?? "user"), onclick: () => run(async () => { await adminSuspend(r.target_user_id, r.target_user); }) }) : null,
          r.guild_id && r.target_type === "guild" ? h("button", { type: "button", class: "danger", text: "Take down server", onclick: () => run(async () => { if (await confirmModal("Take down " + (r.guild_name ?? "server"), "Deletes the server and all of its messages for everyone.", "Take down")) { await request("/api/v1/admin/guilds/" + enc(r.guild_id), "DELETE"); toast("Server removed."); } }) }) : null,
          ...(status === "open" ? [["resolved", "Resolve"], ["dismissed", "Dismiss"]] : [["open", "Reopen"]]).map(([st, l]) => h("button", { type: "button", class: "secondary", text: l, onclick: () => run(async () => {
            const v = st === "open" ? { note: "" } : await ask({ title: l + " report", fields: [{ name: "note", label: "Note (optional)", max: 1000 }] });
            if (!v) return;
            await request("/api/v1/admin/reports/" + enc(r.id), "POST", { status: st, note: v.note }); reload();
          }) }))))));
  } else if (section === "users") {
    const search = h("input", { placeholder: "Search usernames", maxLength: 32 });
    const list = h("div");
    const load = () => run(async () => {
      const users = await request("/api/v1/admin/users?q=" + enc(search.value));
      fill(list, users.map((u) => h("div", { class: "list-row" }, avatar(u.username),
        h("div", { class: "meta" }, h("strong", { text: u.username }), u.is_admin ? h("span", { class: "pill ok", text: " admin " }) : null, u.suspended_at ? h("span", { class: "pill bad", text: " suspended " }) : null,
          h("div", { class: "small muted", text: "joined " + new Date(u.created_at).toLocaleDateString() + " · " + u.memberships + " memberships" + (u.suspension_reason ? " · " + u.suspension_reason : "") })),
        u.id === selfId ? null : u.suspended_at
          ? h("button", { type: "button", class: "secondary", text: "Unsuspend", onclick: () => run(async () => { await request("/api/v1/admin/users/" + enc(u.id) + "/unsuspend", "POST"); load(); }) })
          : h("button", { type: "button", class: "danger", text: "Suspend", onclick: () => run(async () => { await adminSuspend(u.id, u.username); load(); }) }),
        u.id === selfId ? null : h("button", { type: "button", class: "danger", text: "Delete", onclick: () => run(async () => {
          if (!(await confirmModal("Delete " + u.username, "Deletes the account, its messages and every server it owns.", "Delete account"))) return;
          await request("/api/v1/admin/users/" + enc(u.id), "DELETE"); load(); }) }))));
    });
    search.addEventListener("input", () => { clearTimeout(search._t); search._t = setTimeout(load, 300); });
    add(pane, h("div", { style: { margin: "10px 0" } }, search), list);
    load();
  } else if (section === "guilds") {
    const guilds = await request("/api/v1/admin/guilds");
    add(pane, h("div", { style: { marginTop: "10px" } }), guilds.map((g) => h("div", { class: "list-row" }, h("div", { class: "meta" }, h("strong", { text: g.name }), h("div", { class: "small muted", text: "owner " + g.owner + " · " + g.members + " members · " + g.open_reports + " open reports · created " + new Date(g.created_at).toLocaleDateString() })),
      h("button", { type: "button", class: "danger", text: "Take down", onclick: () => run(async () => { if (await confirmModal("Take down " + g.name, "Deletes the server and all of its messages for everyone.", "Take down")) { await request("/api/v1/admin/guilds/" + enc(g.id), "DELETE"); reload(); } }) }))));
  }
}
async function adminSuspend(id, name) {
  const v = await ask({ title: "Suspend " + (name ?? "user"), text: "They are signed out everywhere and cannot sign in until unsuspended.", submit: "Suspend", danger: true, fields: [{ name: "reason", label: "Reason (internal)", max: 500 }] });
  if (v) { await request("/api/v1/admin/users/" + enc(id) + "/suspend", "POST", { reason: v.reason }); toast("User suspended."); }
}

// ------------------------------------------------------------------ boot
const inviteParam = new URLSearchParams(location.search).get("invite");
updateComposer();
if (storedToken) { token = storedToken; run(async () => { await signedIn(); if (inviteParam) await joinWithCode(inviteParam).catch((e) => toast(e.message, true)); }).catch(() => signedOut()); }
else if (inviteParam) status("Sign in to accept your invite.");
