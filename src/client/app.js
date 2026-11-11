// QChat client UI and messaging logic.
import * as core from './core.js';
import { S as K, ME, DEV, hooks } from './core.js';
import * as db from './store.js';
import * as calls from './calls.js';
import * as live from './live.js';
import qrcode from 'qrcode-generator';
import { DONATE_BTC, validBtcAddress, groupAddress } from './donate.js';
import { analyzeUrl, analyzeMessage, analyzeFile, containsRecoveryKey, URL_RE } from '../shared/linksafety.js';
import { cleanText, looksLikeImpersonation } from '../shared/policy.js';
import { weakPin, PIN_RE } from '../shared/pin.js';
import * as C from '../shared/crypto.js';
import { $, $$, esc, clamp, clip, hashColor, nameColor, fmtTime, fmtDay, fmtListTime, fmtSize, fmtDur, fmtAgo, toast, mutex } from './util.js';

// ======================= state =======================
const A = {
  chats: {}, msgs: {}, blocked: new Set(), settings: { readReceipts: true, notifications: true, autoLock: 5 },
  presence: {}, typing: {}, statuses: {}, myStatus: [],
  current: null, filter: 'all', replyTo: null, editing: null, search: '',
};
const msgIndex = new Map();
const TTL_OPTIONS = [[0, 'Off'], [86400, '24 hours'], [604800, '7 days'], [7776000, '90 days']];
const ttlLabel = (s) => (TTL_OPTIONS.find((x) => x[0] === s) || [0, `${s}s`])[1];
const STATUS_TTL = 864e5;
const GROUP_MAX = 3500;   // members per group
const BIG_GROUP = 256;    // above this: no per-member receipts/typing, not used as a status audience
const CALL_MAX = 8;       // group calls are a direct mesh (see calls.js MAX_PARTICIPANTS)
const isBig = (chat) => chat?.type === 'group' && chat.members.length > BIG_GROUP;

// ======================= persistence =======================
const dirty = new Set(); let saveT;
function persist(key) { dirty.add(key); clearTimeout(saveT); saveT = setTimeout(flushPersist, 250); if (key !== 'settings') scheduleCloudBackup(); }
async function flushPersist() {
  const keys = [...dirty]; dirty.clear();
  for (const k of keys) {
    if (k === 'chats') await db.set('chats', A.chats);
    else if (k === 'settings') await db.set('settings', A.settings);
    else if (k === 'blocked') await db.set('blocked', [...A.blocked]);
    else if (k === 'statuses') await db.set('statuses', { others: A.statuses, mine: A.myStatus });
    else if (k.startsWith('msgs:')) { const id = k.slice(5); if (A.msgs[id]) await db.set(k, A.msgs[id]); else await db.del(k); }
  }
}
const mediaURLs = new Map();
async function putMedia(id, bytes, mime) { await db.putBytes('media:' + id, bytes, mime); }
async function mediaURL(id) {
  if (mediaURLs.has(id)) return mediaURLs.get(id);
  const r = await db.getBytes('media:' + id); if (!r) return null;
  const url = URL.createObjectURL(new Blob([r.bytes], { type: r.mime })); mediaURLs.set(id, url); return url;
}
const mediaBytes = async (id) => (await db.getBytes('media:' + id))?.bytes || null;
const delMedia = (id) => db.del('media:' + id);

// ======================= helpers =======================
function displayName(u) { if (u === ME()) return 'You'; return cleanText(K.contacts[u]?.displayName, 40) || u; }
const chatTitle = (c) => (c.type === 'dm' ? displayName(c.peer) : c.name);
function findMsg(id) { const c = msgIndex.get(id); return c ? findMsgIn(A.chats[c], id) : null; }
function findMsgIn(chat, id) { return chat ? (A.msgs[chat.id] || []).find((m) => m.id === id) : null; }
function chatRecipients(chat) {
  if (chat.type === 'dm') return A.blocked.has(chat.peer) ? [] : [chat.peer];
  return chat.left ? [] : chat.members.filter((u) => u !== ME());
}
const chatKeyFor = (p, from) => (p.g ? 'g:' + p.g : from === ME() ? (p.to ? 'dm:' + p.to : null) : 'dm:' + from);

function createDm(u, quiet) {
  const id = 'dm:' + u;
  if (!A.chats[id]) {
    A.chats[id] = { id, type: 'dm', peer: u, unread: 0, lastTs: Date.now(), ttl: 0, createdAt: Date.now() }; A.msgs[id] = [];
    if (!quiet) addSys(A.chats[id], '🔒 Messages and calls are end-to-end encrypted with a post-quantum double ratchet (ML-KEM-768 + ML-DSA-65). Not even QChat servers can read or listen to them.', 'e2e', 0);
    persist('chats'); core.wsSend({ t: 'watch', users: [u] });
  }
  return A.chats[id];
}
function addMessage(chat, m) {
  const list = (A.msgs[chat.id] ||= []);
  m.chat = chat.id; list.push(m);
  if (list.length > 1 && list[list.length - 2].ts > m.ts) list.sort((a, b) => a.ts - b.ts);
  msgIndex.set(m.id, chat.id);
  if (m.kind !== 'sys') chat.lastTs = Math.max(chat.lastTs || 0, m.ts);
  if (chat.archived && m.from !== ME() && !chat.muted && m.kind !== 'sys') chat.archived = false;
  persist('msgs:' + chat.id); persist('chats');
  renderChatList(); if (A.current === chat.id) scheduleRender(true);
}
function addSys(chat, text, variant = '', ts = Date.now()) { addMessage(chat, { id: C.randId(10), from: '', ts, kind: 'sys', text, variant }); }
function touchMsg(m) { persist('msgs:' + m.chat); if (A.current === m.chat) scheduleRender(false); renderChatList(); }
function wipeMsg(m) { m.deleted = true; m.text = ''; m.reactions = {}; if (m.media) { delMedia(m.media.id); m.media = null; } m.replyTo = null; }

async function sendEvent(chat, payload, opts = {}) {
  if (chat.type === 'group') payload.g = chat.gid; else payload.to = chat.peer;
  // group-wide events use sender keys: encrypted once, the same size for 3 or 3,500 members
  if (chat.type === 'group' && !opts.users && !opts.devices) return chat.left ? false : core.groupSend(chat.gid, chatRecipients(chat), payload, opts);
  return core.sendPayload(opts.users || chatRecipients(chat), payload, opts);
}
async function msgPayload(m) {
  const p = { type: 'msg', id: m.id, kind: m.kind, text: m.text, replyTo: m.replyTo, fwd: m.fwd, ttl: m.ttl, sentAt: m.ts };
  if (m.media) { const b = await mediaBytes(m.media.id); if (b) p.media = { data: C.b64(b), name: m.media.name, mime: m.media.mime, size: b.length, dur: m.media.dur }; }
  return p;
}
async function sendMessage(chat, { kind = 'text', text = '', media = null, replyTo = null, fwd = false }) {
  if (chat.type === 'group' && chat.left) return toast("You're no longer a member of this group");
  if (chat.type === 'dm' && A.blocked.has(chat.peer)) return toast('Unblock this contact to send messages');
  if (chat.type === 'dm' && K.contacts[chat.peer]?.keyChanged) { $('#keyBar').classList.add('flash'); setTimeout(() => $('#keyBar').classList.remove('flash'), 1200); return toast('Verify the new security code (or accept it) before sending'); }
  if (chat.stranger) { chat.stranger = false; persist('chats'); updateSafetyBars(chat); }
  const id = C.randId(12), ts = Date.now();
  const m = { id, from: ME(), ts, kind, text, replyTo, fwd, ttl: chat.ttl || 0, status: 'sending', reactions: {} };
  if (m.ttl) m.expireAt = ts + m.ttl * 1000;
  if (media) { const mid = C.randId(10); await putMedia(mid, media.bytes, media.mime); m.media = { id: mid, name: media.name, mime: media.mime, size: media.bytes.length, dur: media.dur }; }
  addMessage(chat, m);
  const ok = await sendEvent(chat, await msgPayload(m), { id, push: 'msg' }).catch((e) => { console.error(e); return false; });
  if (!ok) { m.status = 'failed'; touchMsg(m); }
}

// ======================= receiving =======================
const pendingGroup = {};
hooks.isBlocked = (u) => A.blocked.has(u);
hooks.isGroupMember = (g, u) => { const c = A.chats['g:' + g]; return !!c && !c.left && c.members.includes(u); };
hooks.onPayload = async (from, fd, ts, envId, p) => {
  const fromMe = from === ME();
  if (typeof p.type === 'string' && p.type.startsWith('live_')) return live.onSignal(from, fd, ts, p);
  switch (p.type) {
    case 'rtc': {
      const cid = chatKeyFor(p, from); const chat = cid && A.chats[cid];
      if (p.g && !chat) return;
      const users = p.g ? chat.members.filter((u) => u !== ME()) : [fromMe ? p.to : from];
      return calls.onSignal(from, fd, p, cid || 'dm:' + from, users);
    }
    case 'group': return onGroupMeta(from, ts, p);
    case 'status': case 'status_seen': case 'status_del': return onStatus(from, ts, p);
    case 'sync_req': if (fromMe && fd !== DEV()) onSyncRequest(fd, p); return;
    case 'sync_data': if (fromMe) await onSyncData(p); return;
    case 'retry': return onRetry(from, fd, p);
    case 'chat_state': if (fromMe) applyChatState(p); return;
  }
  const cid = chatKeyFor(p, from); if (!cid) return;
  let chat = A.chats[cid];
  if (p.g) {
    if (!chat) { (pendingGroup[p.g] ||= []).push([from, fd, ts, envId, p]); return; }
    if (!fromMe && !chat.members.includes(from)) return;
  } else if (!chat) { if (p.type !== 'msg') return; chat = createDm(fromMe ? p.to : from); if (!fromMe) { chat.stranger = true; persist('chats'); } }
  switch (p.type) {
    case 'msg': {
      if (findMsg(p.id)) return;
      const m = { id: p.id, from, ts: fromMe ? p.sentAt || ts : ts, kind: p.kind, text: clip(p.text, 20000), replyTo: p.replyTo || null, fwd: !!p.fwd, ttl: p.ttl || 0, reactions: {} };
      if (fromMe) m.status = 'sent';
      if (p.media?.data) { const mid = C.randId(10); await putMedia(mid, C.unb64(p.media.data), p.media.mime); m.media = { id: mid, name: clip(p.media.name, 200), mime: p.media.mime, size: p.media.size, dur: p.media.dur }; }
      if (m.ttl) m.expireAt = m.ts + m.ttl * 1000;
      addMessage(chat, m);
      if (!fromMe) {
        if (!isBig(chat)) queueReceipt(chat, from, m.id, 'delivered');
        if (isViewing(chat)) markRead(chat); else { chat.unread = (chat.unread || 0) + 1; persist('chats'); notify(chat, m); }
        if (A.typing[chat.id]) { clearTimeout(A.typing[chat.id][from]?.timer); delete A.typing[chat.id][from]; }
      }
      break;
    }
    case 'react': { const m = findMsgIn(chat, p.target); if (m) { if (p.emoji) m.reactions[from] = String(p.emoji).slice(0, 8); else delete m.reactions[from]; touchMsg(m); } break; }
    case 'edit': { const m = findMsgIn(chat, p.target); if (m && m.from === from && !m.deleted) { m.text = clip(p.text, 20000); m.edited = true; touchMsg(m); } break; }
    case 'del': { const m = findMsgIn(chat, p.target); if (m && m.from === from) { wipeMsg(m); touchMsg(m); } break; }
    case 'receipt': {
      if (fromMe) { // read on another of my devices
        if (p.kind !== 'read') break;
        const ids = new Set(p.ids || []);
        for (const m of A.msgs[chat.id] || []) if (ids.has(m.id) && m.from !== ME()) m.readSent = true;
        chat.unread = (A.msgs[chat.id] || []).filter((m) => m.from !== ME() && m.kind !== 'sys' && m.kind !== 'call' && !m.readSent).length;
        persist('msgs:' + chat.id); persist('chats'); renderChatList();
        break;
      }
      const rank = { sending: 0, failed: 0, sent: 1, delivered: 2, read: 3 };
      for (const id of (p.ids || []).slice(0, 500)) {
        const m = findMsgIn(chat, id); if (!m || m.from !== ME()) continue;
        if (chat.type === 'dm') { if (rank[p.kind] > rank[m.status || 'sent']) m.status = p.kind; }
        else {
          m.dlv = [...new Set([...(m.dlv || []), from])];
          if (p.kind === 'read') m.rd = [...new Set([...(m.rd || []), from])];
          const others = chat.members.filter((u) => u !== ME());
          if (others.every((u) => (m.rd || []).includes(u))) m.status = 'read';
          else if (others.every((u) => (m.dlv || []).includes(u))) m.status = 'delivered';
        }
        touchMsg(m);
      }
      break;
    }
    case 'cfg': {
      chat.ttl = TTL_OPTIONS.some((x) => x[0] === p.ttl) ? p.ttl : 0; persist('chats');
      addSys(chat, `${fromMe ? 'You' : displayName(from)} ${chat.ttl ? `turned on disappearing messages. New messages will disappear after ${ttlLabel(chat.ttl)}.` : 'turned off disappearing messages.'}`);
      if (A.current === chat.id) refreshHeader();
      break;
    }
    case 'leave': {
      if (chat.type !== 'group') break;
      if (!chat.members.includes(from)) break;
      chat.members = chat.members.filter((u) => u !== from); chat.admins = chat.admins.filter((u) => u !== from);
      if (fromMe) chat.left = true; else core.groupRotate(chat.gid); // the leaver can't read anything sent after this
      persist('chats'); addSys(chat, `${fromMe ? 'You' : displayName(from)} left`);
      if (A.current === chat.id) openChat(chat.id);
      break;
    }
  }
};

async function onGroupMeta(from, ts, p) {
  const cid = 'g:' + p.g; let chat = A.chats[cid];
  const members = [...new Set((p.members || []).map(String))].slice(0, GROUP_MAX);
  const admins = (p.admins || []).filter((u) => members.includes(u));
  const by = from === ME() ? 'You' : displayName(from);
  if (!chat) {
    if (!admins.includes(from) || !members.includes(ME())) return;
    chat = A.chats[cid] = { id: cid, type: 'group', gid: p.g, name: clip(p.name, 60) || 'Group', desc: clip(p.desc, 500), members, admins, ttl: p.ttl || 0, unread: 0, lastTs: ts, createdAt: ts };
    A.msgs[cid] = [];
    addSys(chat, from === ME() ? `You created group “${chat.name}”` : `${by} added you to “${chat.name}”`);
    addSys(chat, '🔒 Group messages are end-to-end encrypted with a post-quantum double ratchet.', 'e2e');
    if (from !== ME()) { chat.unread = 1; notify(chat, { from, kind: 'sys', text: 'added you to the group' }); }
  } else {
    if (!chat.admins.includes(from)) return;
    const added = members.filter((u) => !chat.members.includes(u)), removed = chat.members.filter((u) => !members.includes(u));
    if (p.name && p.name !== chat.name) addSys(chat, `${by} changed the group name to “${clip(p.name, 60)}”`);
    if (added.length > 20) addSys(chat, `${by} added ${added.length} people`); else for (const u of added) addSys(chat, `${by} added ${displayName(u)}`);
    if (removed.length > 20) addSys(chat, `${by} removed ${removed.length} people`); else for (const u of removed) addSys(chat, `${by} removed ${displayName(u)}`);
    if (removed.length) core.groupRotate(p.g); // new chain: removed people can't read what comes next
    if (added.length) core.groupMembersAdded(p.g); // new people only get messages from now on
    Object.assign(chat, { name: clip(p.name, 60) || chat.name, desc: clip(p.desc, 500), members, admins });
    chat.left = !members.includes(ME());
  }
  persist('chats'); renderChatList(); if (A.current === cid) openChat(cid);
  core.prefetch(members.filter((u) => u !== ME())); // names + keys, 500 per request
  const q = pendingGroup[p.g]; delete pendingGroup[p.g];
  if (q) for (const args of q) await hooks.onPayload(...args);
}

// ---------- decryption failures → ask the sender's device to resend over a fresh session ----------
const lastRetry = {};
hooks.onDecryptFail = (item, err) => {
  console.warn('decrypt failed', item.from, err.message);
  const key = item.from + ':' + item.fd;
  if (Date.now() - (lastRetry[key] || 0) < 20000) return;
  lastRetry[key] = Date.now();
  core.resetSendSession(item.from, item.fd);
  core.sendPayload([item.from], { type: 'retry', ids: [item.id], reset: true }, { devices: [{ u: item.from, d: item.fd }], self: false });
  const chat = A.chats['dm:' + item.from];
  if (chat && item.from !== ME()) addSys(chat, `⚠️ A message from ${displayName(item.from)} couldn't be decrypted on this device. It was requested again automatically.`);
};
async function onRetry(from, fd, p) {
  if (p.reset) await core.resetSendSession(from, fd);
  for (const id of (p.ids || []).slice(0, 20)) {
    const m = findMsg(id); if (!m || m.from !== ME() || m.deleted) continue;
    const chat = A.chats[m.chat];
    await sendEvent(chat, await msgPayload(m), { users: [from], devices: [{ u: from, d: fd }], self: from === ME() });
  }
}

// ---------- receipts / read ----------
const rcpt = {}; let rcptT;
function queueReceipt(chat, to, id, kind) {
  const k = `${chat.id}|${to}|${kind}`; (rcpt[k] ||= { chat, to, kind, ids: new Set() }).ids.add(id);
  clearTimeout(rcptT); rcptT = setTimeout(flushReceipts, 400);
}
function flushReceipts() {
  for (const [k, r] of Object.entries(rcpt)) {
    delete rcpt[k];
    const ids = [...r.ids];
    if (r.kind === 'delivered' && isBig(r.chat)) continue;
    if (r.kind === 'read' && isBig(r.chat)) { sendEvent(r.chat, { type: 'receipt', kind: 'read', ids }, { users: [] }); continue; } // only sync my devices
    if (r.kind === 'delivered') sendEvent(r.chat, { type: 'receipt', kind: 'delivered', ids }, { users: [r.to], self: false });
    else sendEvent(r.chat, { type: 'receipt', kind: 'read', ids }, { users: A.settings.readReceipts ? [r.to] : [] }); // always sync read state to my devices
  }
}
const isViewing = (chat) => A.current === chat.id && document.visibilityState === 'visible' && !$('#app').classList.contains('hidden');
function markRead(chat) {
  let changed = false;
  for (const m of A.msgs[chat.id] || []) {
    if (m.from !== ME() && m.kind !== 'sys' && m.kind !== 'call' && !m.readSent) { m.readSent = true; changed = true; if (!m.deleted) queueReceipt(chat, m.from, m.id, 'read'); }
  }
  if (chat.unread) { chat.unread = 0; changed = true; }
  if (changed) { persist('msgs:' + chat.id); persist('chats'); renderChatList(); }
}
document.addEventListener('visibilitychange', () => { const c = A.chats[A.current]; if (c && document.visibilityState === 'visible') markRead(c); });

// ---------- typing ----------
let typingSentAt = 0, typingOffT;
function sendTyping(on, kind = 'text') {
  const chat = A.chats[A.current]; if (!chat) return;
  const to = chatRecipients(chat); if (!to.length || isBig(chat)) return;
  core.wsSend({ t: 'typing', to, chat: chat.type === 'group' ? chat.id : '', on, kind });
}
function onComposerInput() {
  const now = Date.now();
  if (now - typingSentAt > 3000) { typingSentAt = now; sendTyping(true); }
  clearTimeout(typingOffT); typingOffT = setTimeout(() => { typingSentAt = 0; sendTyping(false); }, 4000);
}
function onTyping(m) {
  const cid = m.chat || 'dm:' + m.from; if (!A.chats[cid] || A.blocked.has(m.from)) return;
  const t = (A.typing[cid] ||= {});
  clearTimeout(t[m.from]?.timer);
  if (m.on) t[m.from] = { kind: m.kind, timer: setTimeout(() => { delete t[m.from]; refreshHeader(); renderChatList(); }, 6000) };
  else delete t[m.from];
  refreshHeader(); renderChatList();
}
function typingText(chat) {
  const t = A.typing[chat.id]; if (!t) return '';
  const who = Object.keys(t); if (!who.length) return '';
  const verb = Object.values(t).some((x) => x.kind === 'audio') ? 'recording audio…' : 'typing…';
  return chat.type === 'dm' ? verb : `${who.map(displayName).join(', ')} ${who.length > 1 ? 'are' : 'is'} ${verb}`;
}

// ---------- server events ----------
hooks.onServer = (m) => {
  switch (m.t) {
    case 'sent': { const msg = findMsg(m.id); if (msg && (msg.status === 'sending' || msg.status === 'failed')) { msg.status = 'sent'; touchMsg(msg); } break; }
    case 'presence': A.presence[m.username] = { online: m.online, lastSeen: m.lastSeen }; refreshHeader(); renderChatList(); break;
    case 'profile_update': case 'profile_ok': renderMe(); renderChatList(); refreshHeader(); break;
    case 'typing': onTyping(m); break;
    case 'disconnected': setBanner(true); break;
    case 'kicked': showKicked(m.reason); break;
    case 'devices_changed': if (m.username === ME()) { renderMe(); checkNewDevices(); } break;
    case 'push_ok': K.pushOn = m.on; break;
    case 'security_alert': onSecurityAlerts([m.alert]); break;
    case 'security_alerts': onSecurityAlerts(m.alerts, true); break;
    case 'error': if (m.error === 'display_name_not_allowed') toast('That display name looks like an official account — please choose another.', 5000); break;
    case 'report_ok': break;
    case 'pin_ok': renderMe(); break;
  }
};
// ---------- account security alerts pushed by the server's intrusion detection ----------
const ALERT_TEXT = {
  account_takeover_attempt: (a) => `Someone tried to add a device to your account with a WRONG recovery key (attempt ${a.detail?.attempt || 1}). They were blocked.`,
  account_locked: () => 'Your account was locked for 15 minutes after repeated takeover attempts. Your recovery key was never exposed.',
  device_linked: (a) => `A new device was linked to your account: ${a.detail?.name || 'unknown device'}. If this wasn't you, remove it in Settings → Linked devices.`,
  bad_device_signature: () => 'A forged login for your account was blocked.',
  pin_failed: (a) => `Someone entered a WRONG login PIN for your account (${a.detail?.left} attempt${a.detail?.left === 1 ? '' : 's'} left before PIN login is disabled). If this wasn't you, change your PIN in Settings.`,
  pin_wiped: () => 'PIN login was disabled after 10 wrong PINs. Your account is safe — set a new PIN in Settings (your recovery key still works).',
  pin_changed: () => 'Your login PIN was changed on another device. If this wasn\'t you, change it now and review your linked devices.',
  pin_removed: () => 'PIN login was turned off on another device.',
};
async function onSecurityAlerts(list, quiet) {
  const seen = new Set((await db.get('secAlertIds')) || []); let fresh = 0;
  A.secAlerts = (await db.get('secAlerts')) || [];
  for (const a of list || []) {
    if (!a || seen.has(a.id) || !ALERT_TEXT[a.type]) continue;
    if (a.type === 'device_linked' && a.detail?.device === DEV()) { seen.add(a.id); continue; }
    seen.add(a.id); fresh++; A.secAlerts.unshift({ ...a, text: ALERT_TEXT[a.type](a) });
    toast('🛡️ ' + ALERT_TEXT[a.type](a), 9000);
    notify(null, { from: ME(), kind: 'text', text: '🛡️ ' + ALERT_TEXT[a.type](a) });
  }
  A.secAlerts = A.secAlerts.slice(0, 30);
  await db.set('secAlertIds', [...seen].slice(-200)); await db.set('secAlerts', A.secAlerts);
}

// Alert on every device linked to this account (anyone holding the recovery key could link one).
async function checkNewDevices() {
  const now = core.myDevices(); const known = new Set((await db.get('knownDevices')) || now.map((d) => d.device));
  const fresh = now.filter((d) => !known.has(d.device) && !d.current);
  await db.set('knownDevices', now.map((d) => d.device));
  for (const d of fresh) {
    toast(`🔐 New device linked to your account: ${d.name || 'Unknown device'}`, 8000);
    notify(null, { from: ME(), kind: 'text', text: `New device linked: ${d.name || 'Unknown device'}. If this wasn't you, remove it in Settings → Devices and move to a new account.` });
  }
}
hooks.onKeyChange = (u) => {
  const chat = A.chats['dm:' + u];
  if (K.contacts[u]) { K.contacts[u].keyChanged = true; db.set('contacts', K.contacts); }
  if (chat && A.current === chat.id) updateSafetyBars(chat);
  if (chat) addSys(chat, `🔐 ${displayName(u)}'s security code changed (new account key). Verify it in contact info.`);
};
hooks.onReady = () => {
  setBanner(false); renderMe(); checkNewDevices();
  const watch = new Set(Object.values(A.chats).filter((c) => c.type === 'dm').map((c) => c.peer));
  core.wsSend({ t: 'watch', users: [...watch] });
  for (const u of watch) if (!K.contacts[u] || Date.now() - (K.contacts[u].fetched || 0) > 10 * 60e3) core.refreshUser(u);
  if (A.settings.pushWanted && !K.pushOn) enablePush(true);
  if (K.me && K.me.pinSet === false && !A.pinNudged && $('#modal').classList.contains('hidden') && !$('#app').classList.contains('hidden')) { A.pinNudged = true; setTimeout(() => $('#modal').classList.contains('hidden') && pinDialog(true), 1500); }
};
function setBanner(on) { $('#connBanner').classList.toggle('hidden', !on || !K.me); }

// disappearing messages + status expiry
setInterval(() => {
  const now = Date.now();
  for (const [cid, list] of Object.entries(A.msgs)) {
    const keep = list.filter((m) => !m.expireAt || m.expireAt > now);
    if (keep.length !== list.length) {
      for (const m of list) if (m.expireAt && m.expireAt <= now) { if (m.media) delMedia(m.media.id); msgIndex.delete(m.id); }
      A.msgs[cid] = keep; persist('msgs:' + cid); if (A.current === cid) scheduleRender(false); renderChatList();
    }
  }
  let changed = false;
  for (const [u, list] of Object.entries(A.statuses)) { const k = list.filter((s) => s.expireAt > now); if (k.length !== list.length) { for (const s of list) if (s.expireAt <= now && s.media) delMedia(s.media.id); A.statuses[u] = k; changed = true; } if (!k.length) delete A.statuses[u]; }
  const mine = A.myStatus.filter((s) => s.expireAt > now); if (mine.length !== A.myStatus.length) { A.myStatus = mine; changed = true; }
  if (changed) { persist('statuses'); renderStatusBadge(); }
}, 10000);

// ======================= notifications =======================
function notify(chat, m) {
  if (!A.settings.notifications || chat?.muted || (chat && isViewing(chat))) return;
  if (!('Notification' in window) || Notification.permission !== 'granted') return;
  const body = (chat?.type === 'group' ? displayName(m.from) + ': ' : '') + previewText(m);
  try { const n = new Notification(chat ? chatTitle(chat) : 'QChat', { body, tag: chat?.id, icon: 'icon.svg' }); n.onclick = () => { window.focus(); if (chat) openChat(chat.id); n.close(); }; } catch {}
}
function previewText(m) {
  if (!m) return '';
  if (m.deleted) return '🚫 This message was deleted';
  if (m.kind === 'image') return '📷 Photo' + (m.text ? ' · ' + m.text : '');
  if (m.kind === 'video') return '🎥 Video';
  if (m.kind === 'audio') return '🎤 Voice message' + (m.media?.dur ? ` (${fmtDur(m.media.dur)})` : '');
  if (m.kind === 'file') return '📄 ' + (m.media?.name || 'File');
  return m.text || '';
}
const b64uToU8 = (s) => C.unb64url(s);
async function enablePush(silent) {
  try {
    if (!('serviceWorker' in navigator) || !('PushManager' in window)) throw new Error('Push is not supported in this browser');
    if (Notification.permission !== 'granted' && (await Notification.requestPermission()) !== 'granted') throw new Error('Notification permission denied');
    const reg = await navigator.serviceWorker.ready;
    const sub = (await reg.pushManager.getSubscription()) || (await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: b64uToU8(K.vapid) }));
    core.wsSend({ t: 'push_sub', sub: sub.toJSON() });
    A.settings.pushWanted = true; persist('settings');
    return true;
  } catch (e) { if (!silent) toast(e.message); return false; }
}
async function disablePush() {
  A.settings.pushWanted = false; persist('settings'); core.wsSend({ t: 'push_sub', sub: null });
  try { const reg = await navigator.serviceWorker.ready; (await reg.pushManager.getSubscription())?.unsubscribe(); } catch {}
}

// ======================= rendering =======================
function avatarHTML(who, cls = '', online = false) {
  let color, label;
  if (who?.type === 'group') { color = hashColor(who.gid); label = '👥'; }
  else {
    const u = typeof who === 'string' ? who : who?.username;
    const prof = u === ME() ? K.me : K.contacts[u];
    color = prof?.avatar?.color || hashColor(u);
    label = esc(prof?.avatar?.emoji) || esc((prof?.displayName || u || '?').trim()[0]?.toUpperCase() || '?');
  }
  return `<div class="avatar ${cls}" style="background:${color}">${label}${online ? '<span class="dot-online"></span>' : ''}</div>`;
}
function renderMe() { if (!K.me) return; $('#meAvatar').innerHTML = avatarHTML(ME(), 'sm'); $('#welcomeUser').textContent = '@' + ME(); $('#lockBtn').classList.toggle('hidden', !A.hasPasscode); }

let listRAF;
function renderChatList() { cancelAnimationFrame(listRAF); listRAF = requestAnimationFrame(_renderChatList); }
function _renderChatList() {
  const q = A.search.trim().toLowerCase().replace(/^@/, '');
  let chats = Object.values(A.chats).filter((c) => {
    if (A.filter === 'archived') return c.archived; if (c.archived && !q) return false;
    if (A.filter === 'unread' && !c.unread) return false;
    if (A.filter === 'groups' && c.type !== 'group') return false;
    if (q) return chatTitle(c).toLowerCase().includes(q) || (c.peer || '').includes(q);
    return true;
  });
  chats.sort((a, b) => (b.pinned ? 1 : 0) - (a.pinned ? 1 : 0) || (b.lastTs || 0) - (a.lastTs || 0));
  $('#chatList').innerHTML = chats.map((c) => {
    const list = A.msgs[c.id] || []; const last = [...list].reverse().find((m) => m.kind !== 'sys') || list[list.length - 1];
    const typing = typingText(c);
    let lastTxt = typing ? esc(typing) : last ? (last.kind === 'sys' ? esc(last.text) : (last.from === ME() && last.kind !== 'call' ? ticks(last) + ' ' : c.type === 'group' && last.kind !== 'call' ? esc(displayName(last.from)) + ': ' : '') + esc(last.kind === 'call' ? last.text : previewText(last))) : '';
    const online = c.type === 'dm' && A.presence[c.peer]?.online;
    return `<li class="chat-item ${A.current === c.id ? 'active' : ''}" data-id="${esc(c.id)}">
      ${avatarHTML(c.type === 'group' ? c : c.peer, '', online)}
      <div class="ci-body"><div class="ci-top"><span class="ci-name">${esc(chatTitle(c))}</span><span class="ci-time ${c.unread ? 'unread' : ''}">${last ? fmtListTime(last.ts) : ''}</span></div>
      <div class="ci-bottom"><span class="ci-last ${typing ? 'typing' : ''}">${lastTxt}</span>${c.muted ? '🔕' : ''}${c.pinned ? '<span class="pin">📌</span>' : ''}${c.unread ? `<span class="badge">${c.unread}</span>` : ''}</div></div></li>`;
  }).join('');
  $('#emptyList').classList.toggle('hidden', !!chats.length || !!q || A.filter !== 'all');
  if (q && !chats.length && /^[a-z0-9_.]{3,24}$/.test(q)) $('#chatList').innerHTML = `<li class="chat-item" data-start="${esc(q)}"><div class="avatar" style="background:${hashColor(q)}">@</div><div class="ci-body"><div class="ci-name">Start chat with @${esc(q)}</div><div class="ci-last">Press to look up this username</div></div></li>`;
  const total = Object.values(A.chats).reduce((n, c) => n + (c.unread && !c.muted ? c.unread : 0), 0);
  document.title = total ? `(${total}) QChat` : 'QChat';
}
function ticks(m) {
  if (m.from !== ME() || m.kind === 'sys' || m.kind === 'call') return '';
  const s = m.status || 'sent';
  if (s === 'failed') return '<span class="ticks" title="Not sent — tap to retry" data-resend="' + esc(m.id) + '">⚠️</span>';
  if (s === 'sending') return '<span class="ticks" title="Sending">🕓</span>';
  if (s === 'sent') return '<span class="ticks" title="Sent">✓</span>';
  return `<span class="ticks ${s === 'read' ? 'read' : ''}" title="${s === 'read' ? 'Read' : 'Delivered'}">✓✓</span>`;
}
function fmtLastSeen(p) {
  if (!p) return ''; if (p.online) return 'online'; if (!p.lastSeen) return '';
  return `last seen ${fmtDay(p.lastSeen).toLowerCase()} at ${fmtTime(p.lastSeen)}`;
}
function refreshHeader() {
  const chat = A.chats[A.current]; if (!chat) return;
  $('#chatName').innerHTML = esc(chatTitle(chat)) + (chat.type === 'dm' ? ` <span class="handle">@${esc(chat.peer)}</span>` + (K.contacts[chat.peer]?.verified ? ' ✅' : '') : '');
  $('#chatAvatar').outerHTML = avatarHTML(chat.type === 'group' ? chat : chat.peer).replace('class="avatar', 'id="chatAvatar" class="avatar');
  const sub = $('#chatSub'); const typing = typingText(chat);
  sub.classList.toggle('typing', !!typing);
  if (typing) sub.textContent = typing;
  else if (chat.type === 'dm') sub.textContent = A.blocked.has(chat.peer) ? 'blocked' : (fmtLastSeen(A.presence[chat.peer]) || '@' + chat.peer);
  else sub.textContent = chat.left ? "You're not a member" : chat.members.map(displayName).join(', ');
  const canCall = !(chat.type === 'group' && (chat.left || chat.members.length > CALL_MAX)) && !(chat.type === 'dm' && A.blocked.has(chat.peer));
  $('#voiceCallBtn').classList.toggle('hidden', !canCall); $('#videoCallBtn').classList.toggle('hidden', !canCall);
}
const fmt = (h) => h.replace(/(^|\s)\*([^*\n]+)\*(?=\s|$)/g, '$1<b>$2</b>').replace(/(^|\s)_([^_\n]+)_(?=\s|$)/g, '$1<i>$2</i>').replace(/(^|\s)~([^~\n]+)~(?=\s|$)/g, '$1<s>$2</s>');
// Links never open directly: every one is analysed on-device and opens through a safety check.
function linkify(text, ctx = {}, found) {
  let out = '', last = 0;
  for (const m of String(text).matchAll(URL_RE)) {
    out += fmt(esc(text.slice(last, m.index))); last = m.index + m[0].length;
    const a = analyzeUrl(m[1], ctx); found?.push(a);
    const icon = a.level === 'danger' ? '🚫 ' : a.level === 'caution' ? '⚠️ ' : '';
    out += `<a class="lnk lvl-${a.level}" href="#" data-url="${esc(m[1])}" title="${esc(a.host)}">${icon}${esc(m[1])}</a>`;
  }
  return out + fmt(esc(text.slice(last)));
}
const linkCtx = (m, chat) => ({ stranger: m.from !== ME() && !!chat?.stranger });
function linkDialog(raw, ctx) {
  const a = analyzeUrl(raw, ctx);
  const title = a.level === 'danger' ? '🚫 This link looks dangerous' : a.level === 'caution' ? '⚠️ Check this link before opening' : '🔗 You are leaving QChat';
  openModal(`<h3>${title}</h3>
    <p class="muted small">It will open:</p><div class="link-host lvl-${a.level}">${esc(a.host || '?')}</div>
    <div class="link-full"><code>${esc(a.href || raw)}</code></div>
    ${a.reasons.length ? `<ul class="link-reasons">${a.reasons.map((r) => `<li>${esc(r)}</li>`).join('')}</ul>` : '<p class="muted small">No warning signs found — but only open links from people you trust.</p>'}
    <p class="muted small">QChat checked this link on your device. Never enter your recovery key, passcode or bank details on a site you reached from a message.</p>
    ${a.level === 'danger' ? '<label class="switch"><span>I understand this may be a scam</span><input type="checkbox" id="lkAck"/></label>' : ''}
    <div class="modal-actions"><button class="btn" id="lkCopy">Copy link</button><button class="btn primary" data-close>Don't open</button>
      ${a.href?.startsWith('http') ? `<a class="btn ${a.level === 'danger' ? 'danger disabled' : ''}" id="lkOpen" href="${esc(a.href)}" target="_blank" rel="noopener noreferrer nofollow">Open anyway</a>` : ''}</div>`, (card) => {
    $('#lkCopy', card).onclick = () => navigator.clipboard?.writeText(a.href || raw).then(() => toast('Copied'), () => {});
    const open = $('#lkOpen', card); if (!open) return;
    open.onclick = (e) => { if (open.classList.contains('disabled')) { e.preventDefault(); return; } closeModal(); };
    $('#lkAck', card) && ($('#lkAck', card).onchange = (e) => open.classList.toggle('disabled', !e.target.checked));
  });
}
const onlyEmoji = (t) => t && t.length <= 12 && /^(\p{Extended_Pictographic}|\p{Emoji_Component}|‍|️|\s)+$/u.test(t) && !/^[\d#*\s]+$/.test(t);
function msgHTML(m, chat, prev) {
  let out = '';
  if (m.ts && (!prev?.ts || new Date(prev.ts).toDateString() !== new Date(m.ts).toDateString())) out += `<div class="day">${fmtDay(m.ts)}</div>`;
  if (m.kind === 'sys') return out + `<div class="sys ${m.variant || ''}">${esc(m.text)}</div>`;
  if (m.kind === 'call') return out + `<div class="sys">${esc(m.text)} · ${fmtTime(m.ts)}</div>`;
  const mine = m.from === ME();
  let body = '';
  if (chat.type === 'group' && !mine && (!prev || prev.from !== m.from || prev.kind === 'sys')) body += `<div class="sender" style="color:${nameColor(m.from)}">${esc(displayName(m.from))} <span class="muted" style="font-weight:400">@${esc(m.from)}</span></div>`;
  if (m.deleted) body += `<div class="text deleted">🚫 ${mine ? 'You deleted this message' : 'This message was deleted'}</div>`;
  else {
    if (m.fwd) body += `<div class="fwd">↪ Forwarded</div>`;
    if (m.replyTo) body += `<div class="quote" data-jump="${esc(m.replyTo.id)}"><b>${esc(displayName(m.replyTo.from))}</b>${esc(m.replyTo.preview)}</div>`;
    if (m.media) {
      const md = m.media;
      if (m.kind === 'image') body += `<img class="media" data-mid="${esc(md.id)}" alt="${esc(md.name)}" />`;
      else if (m.kind === 'video') body += `<video class="media" data-mid="${esc(md.id)}" controls preload="metadata"></video>`;
      else if (m.kind === 'audio') body += `<audio data-mid="${esc(md.id)}" controls preload="metadata"></audio>`;
      else {
        const risk = mine ? { level: 'ok' } : analyzeFile(md.name, md.mime);
        body += `<a class="file risk-${risk.level}" data-mid="${esc(md.id)}" ${risk.level !== 'ok' ? `data-risk="${esc(risk.reason)}"` : ''} download="${esc(md.name)}"><span class="fi">${risk.level === 'danger' ? '⚠️' : '📄'}</span><span>${esc(md.name)}<small>${fmtSize(md.size || 0)} · ${esc((md.mime || '').split('/')[1] || 'file')}</small></span></a>`;
        if (risk.level === 'danger') body += `<div class="msg-warn">⚠️ ${esc(risk.reason)}</div>`;
      }
    }
    if (m.text) {
      const found = [];
      body += `<div class="text ${!m.media && onlyEmoji(m.text) ? 'big-emoji' : ''}">${linkify(m.text, linkCtx(m, chat), found)}</div>`;
      const bad = found.find((a) => a.level === 'danger');
      if (bad && !mine) body += `<div class="msg-warn">🚫 Suspicious link: ${esc(bad.reasons[0])}</div>`;
      if (!mine) { const s = analyzeMessage(m.text); if (s.asksForSecrets) body += '<div class="msg-warn">⚠️ Never share your recovery key, passcode or any code. QChat will never ask for them.</div>'; else if (s.claimsOfficial) body += '<div class="msg-warn">⚠️ QChat staff never message users. This account is not official.</div>'; }
    }
  }
  const r = Object.values(m.reactions || {});
  const reactHTML = r.length ? `<div class="reactions" data-reacts="${esc(m.id)}">${[...new Set(r)].slice(0, 4).join('')}${r.length > 1 ? ' ' + r.length : ''}</div>` : '';
  const meta = `<span class="meta">${m.ttl ? '<span class="timer" title="Disappearing">⏱</span>' : ''}${m.edited && !m.deleted ? 'edited · ' : ''}${fmtTime(m.ts)}${ticks(m)}</span>`;
  return out + `<div class="msg ${mine ? 'out' : 'in'} ${r.length ? 'has-react' : ''}" data-id="${esc(m.id)}"><button class="caret" data-menu="${esc(m.id)}">⌄</button>${body}${meta}${reactHTML}</div>`;
}
let renderRAF, renderStick = false;
function scheduleRender(stick) { renderStick = renderStick || stick; cancelAnimationFrame(renderRAF); renderRAF = requestAnimationFrame(renderMessages); }
function renderMessages() {
  const chat = A.chats[A.current]; if (!chat) return;
  const box = $('#messages');
  const nearBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 120;
  const q = ($('#inChatSearchInput').value || '').toLowerCase();
  let list = A.msgs[chat.id] || [];
  if (q) list = list.filter((m) => (m.text || '').toLowerCase().includes(q) || (m.media?.name || '').toLowerCase().includes(q));
  box.innerHTML = list.map((m, i) => msgHTML(m, chat, list[i - 1])).join('') || (q ? '<div class="sys">No matching messages</div>' : '');
  hydrateMedia(box);
  if (renderStick || nearBottom) box.scrollTop = box.scrollHeight;
  renderStick = false;
}
function hydrateMedia(root) {
  for (const el of $$('[data-mid]', root)) {
    mediaURL(el.dataset.mid).then((url) => {
      if (!url) return;
      if (el.tagName === 'A') { if (el.dataset.risk) el.dataset.href = url; else el.href = url; } else el.src = url;
      if (el.tagName === 'IMG') el.onload = () => { const b = $('#messages'); if (b.scrollHeight - b.scrollTop - b.clientHeight < 400) b.scrollTop = b.scrollHeight; };
    });
  }
}

// ======================= chat view =======================
function openChat(id) {
  const chat = A.chats[id]; if (!chat) return;
  if (A.current && A.current !== id) { const prev = A.chats[A.current]; if (prev) { prev.draft = $('#msgInput').value; persist('chats'); } }
  A.current = id; A.replyTo = null; A.editing = null; updateReplyBar();
  $('#welcome').classList.add('hidden'); $('#chatView').classList.remove('hidden'); $('#app').classList.add('in-chat');
  $('#inChatSearch').classList.add('hidden'); $('#inChatSearchInput').value = '';
  $('#msgInput').value = chat.draft || ''; autoGrow(); updateSendBtn();
  const blocked = chat.type === 'dm' && A.blocked.has(chat.peer);
  $('#blockedBar').classList.toggle('hidden', !blocked);
  $('#composer').classList.toggle('hidden', blocked || !!chat.left);
  updateSafetyBars(chat);
  refreshHeader(); scheduleRender(true); markRead(chat); renderChatList();
  if (chat.type === 'dm') core.refreshUser(chat.peer).then(refreshHeader);
  if (matchMedia('(min-width: 761px)').matches) $('#msgInput').focus();
}
function updateSafetyBars(chat) {
  const c = chat.type === 'dm' ? K.contacts[chat.peer] : null;
  $('#strangerBar').classList.toggle('hidden', !(chat.type === 'dm' && chat.stranger && !A.blocked.has(chat.peer)));
  if (chat.stranger) $('#strangerText').innerHTML = `⚠️ <b>@${esc(chat.peer)}</b> isn't in your chats. Be careful with links, and never share your recovery key or passcode.${c && looksLikeImpersonation(c.displayName) ? ' <b>This name imitates an official account.</b>' : ''}`;
  $('#keyBar').classList.toggle('hidden', !c?.keyChanged);
  if (c?.keyChanged) $('#keyText').innerHTML = `🔐 <b>${esc(displayName(chat.peer))}</b>'s security code changed. That happens when they reset their account — or if someone is trying to intercept your chat. Verify before sending.`;
}
function closeChat() { A.current = null; $('#app').classList.remove('in-chat'); $('#chatView').classList.add('hidden'); $('#welcome').classList.remove('hidden'); renderChatList(); }
function autoGrow() { const t = $('#msgInput'); t.style.height = 'auto'; t.style.height = Math.min(t.scrollHeight, 140) + 'px'; }
function updateSendBtn() { $('#sendBtn').textContent = $('#msgInput').value.trim() || A.editing ? '➤' : '🎤'; }
function updateReplyBar() {
  const bar = $('#replyBar');
  if (A.editing) { bar.classList.remove('hidden'); $('#replyPreview').innerHTML = `<b>Editing message</b>${esc(A.editing.text)}`; }
  else if (A.replyTo) { bar.classList.remove('hidden'); $('#replyPreview').innerHTML = `<b>${esc(displayName(A.replyTo.from))}</b>${esc(A.replyTo.preview)}`; }
  else bar.classList.add('hidden');
}
async function submitComposer() {
  const chat = A.chats[A.current]; if (!chat) return;
  const input = $('#msgInput'); const text = input.value.trim();
  if (!text) { if (!A.editing) startRecording(); return; }
  if (containsRecoveryKey(text) && !(await confirmDialog('🛑 That looks like your recovery key!', 'Anyone who gets it can take over your account and read new messages. QChat staff will NEVER ask for it — if someone did, it is a scam.', 'Send anyway', true))) return;
  input.value = ''; autoGrow(); chat.draft = '';
  clearTimeout(typingOffT); typingSentAt = 0; sendTyping(false);
  if (A.editing) {
    const m = A.editing; A.editing = null; updateReplyBar(); updateSendBtn();
    if (text === m.text) return;
    m.text = text; m.edited = true; touchMsg(m);
    return sendEvent(chat, { type: 'edit', target: m.id, text });
  }
  const replyTo = A.replyTo; A.replyTo = null; updateReplyBar(); updateSendBtn();
  await sendMessage(chat, { text, replyTo });
}

// ---------- attachments ----------
const MAX_FILE = 10 * 1024 * 1024;
function readFileBytes(f) { return f.arrayBuffer().then((b) => new Uint8Array(b)); }
async function prepFile(f) {
  let bytes = await readFileBytes(f), mime = f.type || 'application/octet-stream', name = f.name || 'file';
  let kind = mime.startsWith('image/') ? 'image' : mime.startsWith('video/') ? 'video' : mime.startsWith('audio/') ? 'audio' : 'file';
  if (kind === 'image' && bytes.length > 1.2e6 && !/gif|svg/.test(mime)) { const r = await compressImage(f); if (r) { bytes = r; mime = 'image/jpeg'; name = name.replace(/\.\w+$/, '') + '.jpg'; } }
  if (kind === 'image' && /svg/.test(mime)) kind = 'file';
  return { bytes, mime, name, kind };
}
async function sendFiles(files) {
  const chat = A.chats[A.current]; if (!chat) return;
  for (const f of files) {
    const { bytes, mime, name, kind } = await prepFile(f);
    if (bytes.length > MAX_FILE) { toast(`${name} is larger than 10 MB`); continue; }
    const caption = files.length === 1 ? $('#msgInput').value.trim() : '';
    if (caption) { $('#msgInput').value = ''; autoGrow(); updateSendBtn(); }
    await sendMessage(chat, { kind, text: caption, media: { bytes, mime, name } });
  }
}
function compressImage(file, max = 1600, q = 0.82) {
  return new Promise((res) => {
    const img = new Image(); const url = URL.createObjectURL(file);
    img.onload = () => {
      const scale = Math.min(1, max / Math.max(img.width, img.height));
      const c = document.createElement('canvas'); c.width = Math.round(img.width * scale); c.height = Math.round(img.height * scale);
      c.getContext('2d').drawImage(img, 0, 0, c.width, c.height); URL.revokeObjectURL(url);
      c.toBlob(async (b) => res(b ? new Uint8Array(await b.arrayBuffer()) : null), 'image/jpeg', q);
    };
    img.onerror = () => res(null); img.src = url;
  });
}

// ---------- voice notes ----------
let rec = null;
async function startRecording() {
  if (!navigator.mediaDevices?.getUserMedia || !window.MediaRecorder) return toast('Voice messages need microphone support (and HTTPS)');
  let stream; try { stream = await navigator.mediaDevices.getUserMedia({ audio: true }); } catch { return toast('Microphone permission denied'); }
  const mime = ['audio/webm;codecs=opus', 'audio/webm', 'audio/mp4', 'audio/ogg'].find((t) => MediaRecorder.isTypeSupported(t)) || '';
  const mr = new MediaRecorder(stream, mime ? { mimeType: mime } : undefined);
  const chunks = []; const start = Date.now();
  mr.ondataavailable = (e) => e.data.size && chunks.push(e.data);
  rec = { mr, stream, chunks, start, timer: setInterval(() => { $('#recTime').textContent = fmtDur((Date.now() - start) / 1000); if (Date.now() - start > 5 * 60e3) stopRecording(true); }, 250) };
  mr.start(250);
  $('#composer').classList.add('hidden'); $('#recordingBar').classList.remove('hidden'); $('#recTime').textContent = '0:00';
  sendTyping(true, 'audio');
}
async function stopRecording(send) {
  if (!rec) return; const r = rec; rec = null;
  clearInterval(r.timer); sendTyping(false);
  const done = new Promise((res) => (r.mr.onstop = res)); r.mr.stop(); await done;
  r.stream.getTracks().forEach((t) => t.stop());
  $('#recordingBar').classList.add('hidden'); $('#composer').classList.remove('hidden');
  if (!send) return;
  const dur = (Date.now() - r.start) / 1000; if (dur < 0.7) return toast('That recording was too short');
  const blob = new Blob(r.chunks, { type: r.mr.mimeType || 'audio/webm' });
  const chat = A.chats[A.current]; if (!chat) return;
  await sendMessage(chat, { kind: 'audio', media: { bytes: new Uint8Array(await blob.arrayBuffer()), mime: blob.type, name: 'voice-message', dur } });
}

// ---------- message menu ----------
const QUICK_REACTS = ['👍', '❤️', '😂', '😮', '😢', '🙏'];
function openMsgMenu(id, x, y) {
  const m = findMsg(id); const chat = A.chats[A.current]; if (!m || !chat || m.kind === 'sys' || m.kind === 'call') return;
  const mine = m.from === ME(); const age = Date.now() - m.ts;
  const items = [];
  if (!m.deleted) items.push(['reply', '↩ Reply']);
  if (!m.deleted && m.text) items.push(['copy', '⧉ Copy text']);
  if (!m.deleted) items.push(['forward', '↪ Forward']);
  if (!m.deleted && m.media) items.push(['save', '⬇ Save file']);
  if (mine && !m.deleted && m.kind === 'text' && age < 15 * 60e3) items.push(['edit', '✎ Edit']);
  if (mine && chat.type === 'group') items.push(['info', 'ⓘ Message info']);
  items.push(['delme', '🗑 Delete for me', 'danger']);
  if (mine && !m.deleted && age < 48 * 3600e3) items.push(['delall', '🗑 Delete for everyone', 'danger']);
  const menu = $('#ctxMenu');
  menu.innerHTML = (m.deleted ? '' : `<div class="react-row">${QUICK_REACTS.map((e) => `<button data-react="${e}">${e}</button>`).join('')}<button data-react="+">＋</button></div>`) +
    items.map(([a, l, c]) => `<button class="item ${c || ''}" data-act="${a}">${l}</button>`).join('');
  menu.classList.remove('hidden');
  const r = menu.getBoundingClientRect();
  menu.style.left = clamp(x, 6, innerWidth - r.width - 6) + 'px'; menu.style.top = clamp(y, 6, innerHeight - r.height - 6) + 'px';
  menu.onclick = async (e) => {
    const b = e.target.closest('button'); if (!b) return; menu.classList.add('hidden');
    if (b.dataset.react) { if (b.dataset.react === '+') return pickEmoji((em) => react(chat, m, em)); return react(chat, m, b.dataset.react); }
    const act = b.dataset.act;
    if (act === 'reply') { A.editing = null; A.replyTo = { id: m.id, from: m.from, preview: previewText(m).slice(0, 120) }; updateReplyBar(); $('#msgInput').focus(); }
    if (act === 'copy') navigator.clipboard?.writeText(m.text).then(() => toast('Copied'));
    if (act === 'forward') forwardDialog(m);
    if (act === 'save') { const url = await mediaURL(m.media.id); const a = document.createElement('a'); a.href = url; a.download = m.media.name || 'file'; a.click(); }
    if (act === 'edit') { A.replyTo = null; A.editing = m; $('#msgInput').value = m.text; autoGrow(); updateReplyBar(); updateSendBtn(); $('#msgInput').focus(); }
    if (act === 'info') msgInfo(chat, m);
    if (act === 'delme') { A.msgs[chat.id] = A.msgs[chat.id].filter((x) => x !== m); if (m.media) delMedia(m.media.id); msgIndex.delete(m.id); persist('msgs:' + chat.id); scheduleRender(false); renderChatList(); }
    if (act === 'delall') { if (!(await confirmDialog('Delete for everyone?', 'This message will be deleted on all devices in this chat.', 'Delete', true))) return; wipeMsg(m); touchMsg(m); sendEvent(chat, { type: 'del', target: m.id }); }
  };
}
function react(chat, m, emoji) {
  const next = m.reactions[ME()] === emoji ? null : emoji;
  if (next) m.reactions[ME()] = next; else delete m.reactions[ME()];
  touchMsg(m); sendEvent(chat, { type: 'react', target: m.id, emoji: next });
}
document.addEventListener('click', (e) => { if (!e.target.closest('#ctxMenu')) $('#ctxMenu').classList.add('hidden'); if (!e.target.closest('#emojiPanel, #emojiBtn, [data-pick-emoji]')) $('#emojiPanel').classList.add('hidden'); });

// ---------- emoji ----------
const EMOJI = '😀😃😄😁😆😅😂🤣🥲😊😇🙂🙃😉😌😍🥰😘😗😋😛😜🤪😝🤑🤗🤭🤫🤔🤐🤨😐😑😶😏😒🙄😬😮‍💨🤥😔😪🤤😴😷🤒🤕🤢🤮🥵🥶🥴😵🤯🤠🥳🥸😎🤓🧐😕😟🙁😮😯😲😳🥺😦😧😨😰😥😢😭😱😖😣😞😓😩😫🥱😤😡😠🤬😈💀💩🤡👻👽🤖😺😸😹😻😼😽🙀😿😾🙈🙉🙊💋💌💘💝💖💗💓💞💕💟❣️💔❤️🧡💛💚💙💜🤎🖤🤍💯💢💥💫💦💨💬💭💤👋🤚🖐️✋🖖👌🤌🤏✌️🤞🤟🤘🤙👈👉👆👇☝️👍👎✊👊🤛🤜👏🙌👐🤲🤝🙏✍️💅🤳💪🧠👀👶🧒👦👧🧑👱👨🧔👩🧓👴👵🙍🙎🙅🙆💁🙋🧏🙇🤦🤷🎉🎊🎈🎁🎂🍰☕🍵🍺🍻🥂🍷🍕🍔🍟🌭🍿🥗🍎🍌🍉🍓🍒🍑🥭🍍🥥🥝🌍🌎🌏🌙⭐🌟✨⚡🔥🌈☀️⛅🌧️❄️⛄🌊🐶🐱🐭🐹🐰🦊🐻🐼🐨🐯🦁🐮🐷🐸🐵🐔🐧🐦🦄🐝🦋🐢🐍🐙🐬🐳⚽🏀🏈⚾🎾🏐🎮🎯🎵🎶🎤🎧📷📱💻⌚📞✈️🚗🏠🏝️📚✏️📌📎🔒🔑🔐✅❌⚠️❓❗➡️⬅️🆗🆒🆕'.match(/\p{Extended_Pictographic}(‍\p{Extended_Pictographic}|️)*️?/gu);
let emojiCb = null;
function pickEmoji(cb) { emojiCb = cb; const p = $('#emojiPanel'); if (!p.childElementCount) p.innerHTML = EMOJI.map((e) => `<button>${e}</button>`).join(''); p.classList.remove('hidden'); }
$('#emojiPanel').addEventListener('click', (e) => {
  const b = e.target.closest('button'); if (!b) return;
  if (emojiCb) { const cb = emojiCb; emojiCb = null; $('#emojiPanel').classList.add('hidden'); return cb(b.textContent); }
  const t = $('#msgInput'); const s = t.selectionStart ?? t.value.length;
  t.value = t.value.slice(0, s) + b.textContent + t.value.slice(t.selectionEnd ?? s); t.focus(); t.selectionStart = t.selectionEnd = s + b.textContent.length; autoGrow(); updateSendBtn();
});

// ======================= modals =======================
function openModal(html, mount) {
  $('#modalCard').innerHTML = html; $('#modal').classList.remove('hidden');
  mount?.($('#modalCard'));
  const first = $('#modalCard input:not([type=checkbox]):not([type=file]), #modalCard textarea'); if (first) setTimeout(() => first.focus(), 30);
}
function closeModal() { $('#modal').classList.add('hidden'); $('#modalCard').innerHTML = ''; }
$('#modal').addEventListener('mousedown', (e) => { if (e.target.id === 'modal') closeModal(); });
$('#modal').addEventListener('click', (e) => { if (e.target.closest('[data-close]')) closeModal(); });
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') { closeModal(); $('#ctxMenu').classList.add('hidden'); $('#lightbox').classList.add('hidden'); closeStatusViewer(); } });
function confirmDialog(title, text, okLabel = 'OK', danger = false) {
  return new Promise((res) => openModal(`<h3>${esc(title)}</h3><p class="muted">${esc(text)}</p><div class="modal-actions"><button class="btn" id="cfNo">Cancel</button><button class="btn ${danger ? 'danger' : 'primary'}" id="cfYes">${esc(okLabel)}</button></div>`, (c) => {
    $('#cfNo', c).onclick = () => { closeModal(); res(false); }; $('#cfYes', c).onclick = () => { closeModal(); res(true); };
  }));
}

function userCard(u) { const c = K.contacts[u] || {}; return `<li>${avatarHTML(u)}<div class="grow"><b>${esc(c.displayName || u)}</b><small>@${esc(u)} · ${esc(c.about || '')}</small></div></li>`; }
function newChatDialog(prefill = '') {
  openModal(`<h3>New chat</h3><p class="muted">People can only be found by their exact username.</p>
    <div class="field"><input id="ncUser" placeholder="@username" autocomplete="off" spellcheck="false" value="${esc(prefill)}"/></div>
    <ul class="list" id="ncResult"></ul><p class="error" id="ncErr"></p>
    <div class="modal-actions"><button class="btn" data-close>Cancel</button><button class="btn primary" id="ncGo">Find</button></div>`, (card) => {
    const go = async () => {
      const u = $('#ncUser', card).value.trim().toLowerCase().replace(/^@/, '');
      $('#ncErr', card).textContent = ''; $('#ncResult', card).innerHTML = '';
      if (u === ME()) return ($('#ncErr', card).textContent = "That's you! Share your username with friends.");
      if (!/^[a-z0-9_.]{3,24}$/.test(u)) return ($('#ncErr', card).textContent = 'Usernames are 3–24 characters: a-z, 0-9, _ or .');
      const p = await core.refreshUser(u);
      if (p === undefined) return ($('#ncErr', card).textContent = 'Network problem — try again.');
      if (!p) return ($('#ncErr', card).textContent = `No one is using @${u}.`);
      $('#ncResult', card).innerHTML = userCard(u);
      $('#ncGo', card).textContent = 'Message'; $('#ncGo', card).onclick = () => { closeModal(); const c = createDm(u); renderChatList(); openChat(c.id); };
    };
    $('#ncGo', card).onclick = go;
    $('#ncUser', card).addEventListener('keydown', (e) => { if (e.key === 'Enter') go(); });
    $('#ncUser', card).addEventListener('input', () => { $('#ncGo', card).textContent = 'Find'; $('#ncGo', card).onclick = go; });
    if (prefill) go();
  });
}
function memberPicker(card, list, max = GROUP_MAX - 1) {
  const SHOW = 200;
  const render = () => {
    $('#mpList', card).innerHTML = list.slice(-SHOW).reverse().map((u) => `<li>${avatarHTML(u, 'sm')}<div class="grow"><b>${esc(displayName(u))}</b><small>@${esc(u)}</small></div><button class="icon-btn" data-rm="${esc(u)}">✕</button></li>`).join('')
      + (list.length > SHOW ? `<li class="muted small">…and ${list.length - SHOW} more</li>` : '');
    $('#mpCount', card).textContent = list.length ? `${list.length} selected` : '';
  };
  const add = async () => {
    const inp = $('#mpUser', card); $('#mpErr', card).textContent = '';
    // one username, or many pasted at once (commas, spaces or new lines)
    const names = [...new Set(inp.value.toLowerCase().split(/[\s,;]+/).map((x) => x.replace(/^@/, '')).filter(Boolean))].filter((u) => u !== ME() && !list.includes(u));
    if (!names.length) return (inp.value = '');
    const bad = names.filter((u) => !/^[a-z0-9_.]{3,24}$/.test(u));
    let ok = names.filter((u) => !bad.includes(u));
    if (list.length + ok.length > max) { $('#mpErr', card).textContent = `A group can have up to ${GROUP_MAX.toLocaleString()} members.`; ok = ok.slice(0, Math.max(0, max - list.length)); }
    $('#mpAdd', card).disabled = true; $('#mpAdd', card).textContent = ok.length > 1 ? 'Checking…' : 'Add';
    try {
      if (ok.length === 1) { const p = await core.refreshUser(ok[0]); if (p === undefined) { $('#mpErr', card).textContent = 'Network problem — try again.'; return; } if (!p) ok = []; }
      else await core.prefetch(ok);
    } finally { $('#mpAdd', card).disabled = false; $('#mpAdd', card).textContent = 'Add'; }
    const found = ok.filter((u) => K.contacts[u]?.aik), missing = names.filter((u) => !found.includes(u));
    list.push(...found); inp.value = missing.join(', '); render();
    if (missing.length && !$('#mpErr', card).textContent) $('#mpErr', card).textContent = missing.length === 1 ? `@${missing[0]} not found` : `${missing.length} usernames not found (left in the box)`;
  };
  $('#mpAdd', card).onclick = add;
  $('#mpUser', card).addEventListener('keydown', (e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); add(); } });
  $('#mpList', card).onclick = (e) => { const b = e.target.closest('[data-rm]'); if (b) { list.splice(list.indexOf(b.dataset.rm), 1); render(); } };
  render();
}
const pickerHTML = (label = 'Add members by username') => `<div class="field"><span>${label} <small class="muted">— paste many at once, separated by commas or new lines (up to ${GROUP_MAX.toLocaleString()})</small></span><div class="row"><textarea id="mpUser" class="grow" rows="1" placeholder="@username" autocomplete="off" spellcheck="false"></textarea><button class="btn" id="mpAdd" type="button">Add</button></div></div><p class="error" id="mpErr"></p><div class="muted small" id="mpCount"></div><ul class="list" id="mpList"></ul>`;
function newGroupDialog() {
  const members = [];
  openModal(`<h3>New group</h3><div class="field"><span>Group name</span><input id="ngName" maxlength="60" placeholder="e.g. Family 🌍"/></div>${pickerHTML()}
    <div class="modal-actions"><button class="btn" data-close>Cancel</button><button class="btn primary" id="ngCreate">Create group</button></div>`, (card) => {
    memberPicker(card, members);
    $('#ngCreate', card).onclick = async () => {
      const name = $('#ngName', card).value.trim();
      if (!name) return toast('Give the group a name');
      if (!members.length) return toast('Add at least one member');
      const gid = C.randId(12); const cid = 'g:' + gid;
      const chat = A.chats[cid] = { id: cid, type: 'group', gid, name, desc: '', members: [ME(), ...members], admins: [ME()], ttl: 0, unread: 0, lastTs: Date.now(), createdAt: Date.now() };
      A.msgs[cid] = []; addSys(chat, `You created group “${name}”`); addSys(chat, '🔒 Group messages are end-to-end encrypted with a post-quantum double ratchet.', 'e2e');
      closeModal(); renderChatList(); openChat(cid);
      await pushGroupMeta(chat, [], members);
    };
  });
}
async function pushGroupMeta(chat, extraTo = [], added = []) {
  const meta = { type: 'group', name: chat.name, desc: chat.desc, members: chat.members, admins: chat.admins, ttl: chat.ttl };
  if (chat.members.length <= BIG_GROUP) {
    const users = [...new Set([...chat.members, ...extraTo])].filter((u) => u !== ME());
    return sendEvent(chat, meta, { users });
  }
  // big group: people who were just added/removed get it pairwise (they don't share the group key); everyone else via the group key
  const direct = [...new Set([...extraTo, ...added])].filter((u) => u !== ME());
  if (direct.length) await sendEvent(chat, { ...meta }, { users: direct, self: false });
  return sendEvent(chat, { ...meta });
}
const ttlSelect = (cur) => `<select id="ttlSel">${TTL_OPTIONS.map(([v, l]) => `<option value="${v}" ${v === (cur || 0) ? 'selected' : ''}>${l}</option>`).join('')}</select>`;
function setTtl(chat, ttl) {
  chat.ttl = ttl; persist('chats');
  addSys(chat, ttl ? `You turned on disappearing messages. New messages will disappear after ${ttlLabel(ttl)}.` : 'You turned off disappearing messages.');
  sendEvent(chat, { type: 'cfg', ttl });
}
function syncChatState(chat) { core.sendPayload([], { type: 'chat_state', id: chat.id, pinned: !!chat.pinned, muted: !!chat.muted, archived: !!chat.archived }); }
function applyChatState(p) { const c = A.chats[p.id]; if (!c) return; Object.assign(c, { pinned: !!p.pinned, muted: !!p.muted, archived: !!p.archived }); persist('chats'); renderChatList(); }
function chatToggles(chat, card, pfx) {
  for (const [key, el] of [['muted', pfx + 'Mute'], ['pinned', pfx + 'Pin'], ['archived', pfx + 'Arch']]) {
    const box = $('#' + el, card); if (box) box.onchange = (e) => { chat[key] = e.target.checked; persist('chats'); renderChatList(); syncChatState(chat); };
  }
}

function contactInfo(u) {
  const c = K.contacts[u] || { displayName: u };
  const chat = A.chats['dm:' + u];
  const sn = c.aik ? C.safetyNumber(ME(), C.b64(K.keys.aikPk), u, c.aik) : null;
  const blocked = A.blocked.has(u);
  const devs = Object.values(c.devices || {});
  openModal(`<div class="profile-head">${avatarHTML(u, 'big')}<h3 style="margin:0">${esc(c.displayName || u)} ${c.verified ? '✅' : ''}</h3><div class="muted">@${esc(u)} · ${esc(fmtLastSeen(A.presence[u]) || '')}</div><p>${esc(c.about || '')}</p></div>
    <div class="section-title">Encryption</div>
    <p class="muted small">Compare this safety number with ${esc(c.displayName || u)} in person or on a video call. If it matches, nobody — not even the server — can intercept your chats. It covers all of their ${devs.length} device${devs.length === 1 ? '' : 's'}.</p>
    ${sn ? `<div class="safety">${sn.map((x) => `<span>${x}</span>`).join('')}</div>` : '<p class="muted">Keys not loaded yet.</p>'}
    <div class="switch"><span>Verified ${c.verified ? '✅' : ''}</span><button class="btn" id="ciVerify">${c.verified ? 'Clear verified' : 'Mark as verified'}</button></div>
    ${chat ? `<div class="section-title">Chat settings</div>
    <div class="switch"><span>Disappearing messages</span>${ttlSelect(chat.ttl)}</div>
    <div class="switch"><span>Mute notifications</span><input type="checkbox" id="ciMute" ${chat.muted ? 'checked' : ''}/></div>
    <div class="switch"><span>Pin chat</span><input type="checkbox" id="ciPin" ${chat.pinned ? 'checked' : ''}/></div>
    <div class="switch"><span>Archive chat</span><input type="checkbox" id="ciArch" ${chat.archived ? 'checked' : ''}/></div>` : ''}
    <div class="modal-actions"><button class="btn danger" id="ciReport">Report</button><button class="btn danger" id="ciBlock">${blocked ? 'Unblock' : 'Block'} @${esc(u)}</button>
      ${chat ? '<button class="btn danger" id="ciClear">Clear chat</button><button class="btn danger" id="ciDelete">Delete chat</button>' : ''}
      <button class="btn primary" data-close>Done</button></div>`, (card) => {
    $('#ciVerify', card).onclick = () => { c.verified = !c.verified; if (c.verified) c.keyChanged = false; K.contacts[u] = c; db.set('contacts', K.contacts); if (chat) addSys(chat, c.verified ? `You marked ${c.displayName || u} as verified ✅` : `You cleared verification for ${c.displayName || u}`); refreshHeader(); contactInfo(u); };
    $('#ciBlock', card).onclick = () => { toggleBlock(u); contactInfo(u); };
    $('#ciReport', card).onclick = () => reportDialog(u);
    if (chat) {
      $('#ttlSel', card).onchange = (e) => setTtl(chat, Number(e.target.value));
      chatToggles(chat, card, 'ci');
      $('#ciClear', card).onclick = async () => { if (await confirmDialog('Clear chat?', 'All messages in this chat will be removed from this device.', 'Clear', true)) clearChat(chat); };
      $('#ciDelete', card).onclick = async () => { if (await confirmDialog('Delete chat?', 'The chat and its messages will be removed from this device.', 'Delete', true)) deleteChat(chat); };
    }
  });
}
function reportDialog(u) {
  openModal(`<h3>Report @${esc(u)}</h3>
    <p class="muted small">Your messages stay end-to-end encrypted — the report only tells the server <b>who</b> you're reporting and why. Accounts reported by several people are restricted automatically.</p>
    <div class="field"><span>Reason</span><select id="rpReason"><option value="scam">Scam / phishing</option><option value="spam">Spam</option><option value="impersonation">Pretending to be someone else / official</option><option value="harassment">Harassment</option><option value="other">Other</option></select></div>
    <div class="switch"><span>Also block @${esc(u)}</span><input type="checkbox" id="rpBlock" checked/></div>
    <div class="modal-actions"><button class="btn" data-close>Cancel</button><button class="btn danger" id="rpGo">Report</button></div>`, (card) => {
    $('#rpGo', card).onclick = () => {
      core.wsSend({ t: 'report', username: u, reason: $('#rpReason', card).value });
      if ($('#rpBlock', card).checked && !A.blocked.has(u)) toggleBlock(u);
      const chat = A.chats['dm:' + u]; if (chat) { chat.stranger = false; persist('chats'); if (A.current === chat.id) openChat(chat.id); }
      closeModal(); toast(`Reported @${u}. Thank you for keeping QChat safe.`);
    };
  });
}
function toggleBlock(u) {
  if (A.blocked.has(u)) A.blocked.delete(u); else A.blocked.add(u);
  persist('blocked');
  if (A.current === 'dm:' + u) openChat(A.current);
  toast(A.blocked.has(u) ? `Blocked @${u}` : `Unblocked @${u}`);
}
function clearChat(chat) { for (const m of A.msgs[chat.id] || []) { if (m.media) delMedia(m.media.id); msgIndex.delete(m.id); } A.msgs[chat.id] = []; persist('msgs:' + chat.id); scheduleRender(false); renderChatList(); }
function deleteChat(chat) { clearChat(chat); delete A.chats[chat.id]; delete A.msgs[chat.id]; persist('chats'); persist('msgs:' + chat.id); if (A.current === chat.id) closeChat(); renderChatList(); }

function memberRows(chat, amAdmin, q) {
  const SHOW = 200; q = q.toLowerCase().replace(/^@/, '');
  const list = (q ? chat.members.filter((u) => u.includes(q) || displayName(u).toLowerCase().includes(q)) : [...chat.admins.filter((u) => chat.members.includes(u)), ...chat.members.filter((u) => !chat.admins.includes(u))]);
  return list.slice(0, SHOW).map((u) => `<li>${avatarHTML(u, 'sm')}<div class="grow"><b>${esc(displayName(u))}</b><small>@${esc(u)}</small></div>${chat.admins.includes(u) ? '<span class="tag">admin</span>' : ''}
      ${amAdmin && u !== ME() ? `<button class="icon-btn" title="${chat.admins.includes(u) ? 'Dismiss admin' : 'Make admin'}" data-admin="${esc(u)}">⭐</button><button class="icon-btn" title="Remove" data-kick="${esc(u)}">✕</button>` : ''}
      ${u !== ME() ? `<button class="icon-btn" title="Message" data-dm="${esc(u)}">💬</button>` : ''}</li>`).join('') + (list.length > SHOW ? `<li class="muted small">…and ${(list.length - SHOW).toLocaleString()} more — search to find someone</li>` : '');
}
function groupInfo(chat) {
  const amAdmin = chat.admins.includes(ME()) && !chat.left;
  openModal(`<div class="profile-head">${avatarHTML(chat, 'big')}
    ${amAdmin ? `<div class="field"><input id="giName" value="${esc(chat.name)}" maxlength="60"/></div><div class="field"><textarea id="giDesc" rows="2" placeholder="Group description">${esc(chat.desc || '')}</textarea></div>` : `<h3 style="margin:0">${esc(chat.name)}</h3><p class="muted">${esc(chat.desc || '')}</p>`}
    <div class="muted">Group · ${chat.members.length.toLocaleString()} of ${GROUP_MAX.toLocaleString()} members</div></div>
    <div class="section-title">Members</div>
    ${chat.members.length > 30 ? `<div class="field"><input id="giFind" placeholder="Search ${chat.members.length.toLocaleString()} members" autocomplete="off" spellcheck="false"/></div>` : ''}
    <ul class="list" id="giMembers">${memberRows(chat, amAdmin, '')}</ul>
    ${amAdmin ? pickerHTML('Add more members') : ''}
    <div class="section-title">Settings</div>
    <div class="switch"><span>Disappearing messages</span>${ttlSelect(chat.ttl)}</div>
    <div class="switch"><span>Mute notifications</span><input type="checkbox" id="giMute" ${chat.muted ? 'checked' : ''}/></div>
    <div class="switch"><span>Pin chat</span><input type="checkbox" id="giPin" ${chat.pinned ? 'checked' : ''}/></div>
    <div class="modal-actions">${chat.left ? '<button class="btn danger" id="giDelete">Delete group</button>' : '<button class="btn danger" id="giLeave">Exit group</button>'}
      ${amAdmin ? '<button class="btn primary" id="giSave">Save</button>' : '<button class="btn primary" data-close>Done</button>'}</div>`, (card) => {
    const pendingAdd = [];
    if ($('#giFind', card)) $('#giFind', card).oninput = (e) => { $('#giMembers', card).innerHTML = memberRows(chat, amAdmin, e.target.value.trim()); };
    if (amAdmin) memberPicker(card, pendingAdd, GROUP_MAX - chat.members.length);
    $('#ttlSel', card).onchange = (e) => setTtl(chat, Number(e.target.value));
    chatToggles(chat, card, 'gi');
    card.addEventListener('click', async (e) => {
      const b = e.target.closest('button'); if (!b) return;
      if (b.dataset.dm) { closeModal(); const c = createDm(b.dataset.dm); renderChatList(); openChat(c.id); }
      if (b.dataset.kick) { const u = b.dataset.kick; if (!(await confirmDialog('Remove member?', `Remove ${displayName(u)} from “${chat.name}”?`, 'Remove', true))) return groupInfo(chat); chat.members = chat.members.filter((x) => x !== u); chat.admins = chat.admins.filter((x) => x !== u); persist('chats'); addSys(chat, `You removed ${displayName(u)}`); await core.groupRotate(chat.gid); await pushGroupMeta(chat, [u]); groupInfo(chat); }
      if (b.dataset.admin) { const u = b.dataset.admin; chat.admins = chat.admins.includes(u) ? chat.admins.filter((x) => x !== u) : [...chat.admins, u]; persist('chats'); await pushGroupMeta(chat); groupInfo(chat); }
    });
    $('#giSave', card) && ($('#giSave', card).onclick = async () => {
      const name = $('#giName', card).value.trim() || chat.name, desc = $('#giDesc', card).value.trim();
      if (name !== chat.name) addSys(chat, `You changed the group name to “${name}”`);
      const added = pendingAdd.filter((u) => !chat.members.includes(u)).slice(0, GROUP_MAX - chat.members.length);
      chat.members.push(...added);
      if (added.length > 20) addSys(chat, `You added ${added.length} people`); else for (const u of added) addSys(chat, `You added ${displayName(u)}`);
      Object.assign(chat, { name, desc }); persist('chats'); refreshHeader(); renderChatList(); closeModal();
      if (added.length) await core.groupMembersAdded(chat.gid);
      await pushGroupMeta(chat, [], added);
    });
    $('#giLeave', card) && ($('#giLeave', card).onclick = async () => {
      if (!(await confirmDialog('Exit group?', `You'll stop receiving messages from “${chat.name}”.`, 'Exit', true))) return;
      await sendEvent(chat, { type: 'leave' });
      chat.members = chat.members.filter((u) => u !== ME()); chat.admins = chat.admins.filter((u) => u !== ME()); chat.left = true;
      persist('chats'); addSys(chat, 'You left'); openChat(chat.id);
    });
    $('#giDelete', card) && ($('#giDelete', card).onclick = () => { deleteChat(chat); closeModal(); });
  });
}
function msgInfo(chat, m) {
  const others = chat.members.filter((u) => u !== ME());
  const row = (u) => `<li>${avatarHTML(u, 'sm')}<div class="grow"><b>${esc(displayName(u))}</b></div></li>`;
  const rd = others.filter((u) => (m.rd || []).includes(u)), dl = others.filter((u) => (m.dlv || []).includes(u) && !rd.includes(u));
  openModal(`<h3>Message info</h3><div class="section-title">Read by</div><ul class="list">${rd.map(row).join('') || '<li class="muted">—</li>'}</ul>
    <div class="section-title">Delivered to</div><ul class="list">${dl.map(row).join('') || '<li class="muted">—</li>'}</ul><div class="modal-actions"><button class="btn primary" data-close>Close</button></div>`);
}
function forwardDialog(m) {
  const chats = Object.values(A.chats).filter((c) => !c.left).sort((a, b) => (b.lastTs || 0) - (a.lastTs || 0));
  openModal(`<h3>Forward to…</h3><ul class="list">${chats.map((c) => `<li class="pick" data-fw="${esc(c.id)}">${avatarHTML(c.type === 'group' ? c : c.peer, 'sm')}<div class="grow"><b>${esc(chatTitle(c))}</b></div></li>`).join('')}</ul><div class="modal-actions"><button class="btn" data-close>Cancel</button></div>`, (card) => {
    card.onclick = async (e) => {
      const li = e.target.closest('[data-fw]'); if (!li) return;
      const chat = A.chats[li.dataset.fw]; closeModal();
      let media = null;
      if (m.media) { const bytes = await mediaBytes(m.media.id); if (bytes) media = { bytes, mime: m.media.mime, name: m.media.name, dur: m.media.dur }; }
      await sendMessage(chat, { kind: m.kind, text: m.text, media, fwd: true });
      toast('Forwarded to ' + chatTitle(chat));
    };
  });
}

// ======================= settings =======================
const AVATAR_COLORS = ['#25a18e', '#e76f51', '#2a9d8f', '#e9c46a', '#8e7dbe', '#3a86ff', '#ef476f', '#06d6a0', '#ff8800', '#6d6875'];
function settingsDialog() {
  const me = K.me; const av = { ...(me.avatar || { color: hashColor(ME()), emoji: '' }) };
  const devs = core.myDevices();
  openModal(`<div class="profile-head"><div id="sAv">${avatarHTML(ME(), 'big')}</div><div class="muted">@${esc(ME())}</div></div>
    <div class="section-title">Profile</div>
    <div class="field"><span>Display name</span><input id="sName" maxlength="40" value="${esc(me.displayName)}"/></div>
    <div class="field"><span>About</span><input id="sAbout" maxlength="140" value="${esc(me.about)}"/></div>
    <div class="field"><span>Avatar emoji (optional)</span><div class="row"><input id="sEmoji" maxlength="4" value="${esc(av.emoji || '')}" style="width:80px"/><button class="btn" id="sPickEmoji" data-pick-emoji type="button">Pick</button></div></div>
    <div class="field"><span>Avatar color</span><div class="colors">${AVATAR_COLORS.map((c) => `<button type="button" data-color="${c}" style="background:${c}" class="${c === av.color ? 'sel' : ''}"></button>`).join('')}</div></div>
    <div class="switch"><span>Your link: <code>${esc(myLink())}</code></span><button class="btn" id="sShare">Share</button></div>
    <div class="switch"><span>🧡 Support QChat with a Bitcoin donation</span><button class="btn" id="sDonate">Donate</button></div>
    <div class="section-title">Privacy</div>
    <div class="switch"><span>Hide my online status &amp; last seen</span><input type="checkbox" id="sHide" ${me.hideLastSeen ? 'checked' : ''}/></div>
    <div class="switch"><span>Send read receipts (blue ticks)</span><input type="checkbox" id="sRead" ${A.settings.readReceipts ? 'checked' : ''}/></div>
    <div class="switch"><span>Blocked contacts (${A.blocked.size})</span><button class="btn" id="sBlocked">Manage</button></div>
    <div class="section-title">Notifications</div>
    <div class="switch"><span>Notifications while QChat is open</span><input type="checkbox" id="sNotif" ${A.settings.notifications && 'Notification' in window && Notification.permission === 'granted' ? 'checked' : ''}/></div>
    <div class="switch"><span>Push notifications when QChat is closed<small class="muted block">Only “new message from @user” — never the content</small></span><input type="checkbox" id="sPush" ${K.pushOn ? 'checked' : ''}/></div>
    <div class="section-title">Security</div>
    <div class="switch"><span>App passcode${A.hasPasscode ? ' ✅' : ''}<small class="muted block">Encrypts everything stored on this device with a key derived from your passcode (Argon2id)</small></span><button class="btn" id="sPass">${A.hasPasscode ? 'Change / remove' : 'Set passcode'}</button></div>
    ${A.hasPasscode ? `<div class="switch"><span>Auto-lock after</span><select id="sAutoLock">${[[0, 'Never'], [1, '1 minute'], [5, '5 minutes'], [15, '15 minutes'], [60, '1 hour']].map(([v, l]) => `<option value="${v}" ${v === A.settings.autoLock ? 'selected' : ''}>${l}</option>`).join('')}</select></div>` : ''}
    <div class="field"><span>Linked devices (${devs.length}/5)</span><ul class="list" id="sDevices">${devs.map((d) => `<li><span class="fi">${/Android|iOS/.test(d.name) ? '📱' : '💻'}</span><div class="grow"><b>${esc(d.name || 'Device')}</b><small>${d.current ? 'This device' : 'Added ' + fmtDay(d.created)} · ${esc(d.device.slice(0, 8))}</small></div>${d.current ? '' : `<button class="btn danger" data-rmdev="${esc(d.device)}">Remove</button>`}</li>`).join('')}</ul>
      <small class="muted">To add a device, open QChat there and log in with your username + recovery key. Your chat history can be copied from this device.</small></div>
    <div class="switch"><span>Login PIN${K.me?.pinSet ? ' ✅' : ' ⚠️ not set'}<small class="muted block">Log in on any device with your username + 6-digit PIN. 10 wrong tries disable it.</small></span><span class="row">${K.me?.pinSet ? '<button class="btn" id="sPinChange">Change</button><button class="btn danger" id="sPinOff">Turn off</button>' : '<button class="btn primary" id="sPinChange">Set up PIN</button>'}</span></div>
    <div class="row"><button class="btn" id="sShowKey">Show recovery key</button></div>
    <div class="field"><span>Security activity</span><ul class="list sec-list">${(A.secAlerts || []).slice(0, 8).map((a) => `<li><span class="fi">🛡️</span><div class="grow">${esc(a.text)}<small>${fmtAgo(a.ts)}</small></div></li>`).join('') || '<li class="muted">No suspicious activity detected.</li>'}</ul></div>
    <div class="section-title">Backup</div>
    <div class="switch"><span>Automatic encrypted backup<small class="muted block">Your chats are backed up to the server end-to-end encrypted with your account key — only you can open them. They come back when you log in on a new device. ${A.settings.cloudBackupAt ? 'Last backup ' + fmtAgo(A.settings.cloudBackupAt) + '.' : 'Not backed up yet.'}</small></span><span class="row"><button class="btn" id="sBackupNow">Back up now</button><input type="checkbox" id="sCloud" ${A.settings.cloudBackup === false ? '' : 'checked'}/></span></div>
    <p class="muted small">Or keep your own copy, encrypted with your recovery key:</p>
    <div class="row"><button class="btn" id="sExport">Export encrypted backup</button><label class="btn">Import backup<input type="file" id="sImport" accept=".qcb" hidden/></label></div>
    <div class="section-title">Account</div>
    <div class="row"><button class="btn danger" id="sLogout">Log out of this device</button><button class="btn danger" id="sDelete">Delete account</button></div>
    <div class="modal-actions"><button class="btn" data-close>Cancel</button><button class="btn primary" id="sSave">Save</button></div>`, (card) => {
    const refreshAv = () => { $('#sAv', card).innerHTML = `<div class="avatar big" style="background:${av.color}">${esc(av.emoji) || esc((($('#sName', card).value || ME())[0] || '?').toUpperCase())}</div>`; };
    card.querySelectorAll('[data-color]').forEach((b) => (b.onclick = () => { av.color = b.dataset.color; card.querySelectorAll('[data-color]').forEach((x) => x.classList.toggle('sel', x === b)); refreshAv(); }));
    $('#sEmoji', card).oninput = (e) => { av.emoji = [...e.target.value].slice(0, 2).join(''); refreshAv(); };
    $('#sName', card).oninput = refreshAv;
    $('#sPickEmoji', card).onclick = () => pickEmoji((em) => { av.emoji = em; $('#sEmoji', card).value = em; refreshAv(); });
    $('#sBlocked', card).onclick = blockedDialog;
    $('#sShare', card).onclick = shareDialog;
    $('#sDonate', card).onclick = donateDialog;
    $('#sPush', card).onchange = async (e) => { if (e.target.checked) { if (!(await enablePush())) e.target.checked = false; else toast('Push notifications on'); } else disablePush(); };
    $('#sPass', card).onclick = passcodeDialog;
    $('#sAutoLock', card) && ($('#sAutoLock', card).onchange = (e) => { A.settings.autoLock = Number(e.target.value); persist('settings'); db.setPlain('autoLock', A.settings.autoLock); });
    $('#sDevices', card).onclick = async (e) => {
      const b = e.target.closest('[data-rmdev]'); if (!b) return;
      if (!(await confirmDialog('Remove device?', 'That device will be logged out and its local data becomes unreadable to the account.', 'Remove', true))) return settingsDialog();
      await core.removeDevice(b.dataset.rmdev); closeModal(); toast('Device removed and signed out'); setTimeout(() => core.refreshUser(ME()), 600);
    };
    $('#sPinChange', card).onclick = () => pinDialog();
    $('#sPinOff', card) && ($('#sPinOff', card).onclick = async () => { if (!(await confirmDialog('Turn off PIN login?', 'You will need your recovery key to log in on new devices.', 'Turn off', true))) return; await core.clearPin(); toast('PIN login turned off'); });
    $('#sShowKey', card).onclick = async () => {
      if (!(await confirmDialog('Show recovery key?', 'Anyone who sees it can take over your account.', 'Show'))) return;
      openModal(`<h3>Recovery key</h3><p class="muted">Use with your username to log in on a new device or restore a backup.</p><pre class="keybox">${esc(core.recoveryKey())}</pre><div class="modal-actions"><button class="btn primary" data-close>Done</button></div>`);
    };
    $('#sExport', card).onclick = exportBackup;
    $('#sBackupNow', card).onclick = async (e) => { e.target.disabled = true; e.target.textContent = 'Backing up…'; const ok = await uploadCloudBackup().catch(() => false); e.target.disabled = false; e.target.textContent = 'Back up now'; toast(ok ? 'Backed up ✅ (end-to-end encrypted)' : 'Backup failed — check your connection'); };
    $('#sCloud', card).onchange = async (e) => {
      A.settings.cloudBackup = e.target.checked; persist('settings');
      if (!e.target.checked) { if (await confirmDialog('Delete your server backup?', 'Turning this off also deletes the encrypted copy on the server. If you then lose this device without another one linked, your chats can’t be recovered.', 'Turn off & delete', true)) core.wsSend({ t: 'backup_delete' }); else { A.settings.cloudBackup = true; e.target.checked = true; persist('settings'); } }
      else scheduleCloudBackup(1000);
    };
    $('#sImport', card).onchange = (e) => { const f = e.target.files[0]; if (f) importBackup(f); };
    $('#sLogout', card).onclick = async () => { if (await confirmDialog('Log out?', 'Your account, chats and media are kept. On this device they stay encrypted and locked until you log back in with your username + PIN (or recovery key). New messages wait for you.', 'Log out')) logOut(); };
    $('#sDelete', card).onclick = async () => { if (prompt(`Deleting your account permanently erases your chats, your encrypted backup on the server and this device's data, and frees the username. Type ${ME()} to confirm.`) !== ME()) return; core.wsSend({ t: 'delete_account' }); await wipeAndReload(); };
    $('#sSave', card).onclick = async () => {
      core.wsSend({ t: 'profile', displayName: $('#sName', card).value, about: $('#sAbout', card).value, avatar: av, hideLastSeen: $('#sHide', card).checked });
      A.settings.readReceipts = $('#sRead', card).checked;
      const wantN = $('#sNotif', card).checked;
      if (wantN && 'Notification' in window && Notification.permission !== 'granted') await Notification.requestPermission();
      A.settings.notifications = wantN; persist('settings'); closeModal(); toast('Saved');
    };
  });
}
function pinDialog(nudge) {
  openModal(`<h3>${K.me?.pinSet ? 'Change your login PIN' : '🔑 Set up a login PIN'}</h3>
    <p class="muted small">${nudge ? 'You don\'t have a login PIN yet. ' : ''}With your username and a 6-digit PIN you can log back in on any device without your recovery key. Your other devices are alerted whenever the PIN is used wrongly or changed.</p>
    <div class="field"><span>New PIN</span><input id="pd1" class="pin-input" type="password" inputmode="numeric" maxlength="6" autocomplete="one-time-code" data-lpignore="true" data-1p-ignore/></div>
    <div class="field"><span>Repeat PIN</span><input id="pd2" class="pin-input" type="password" inputmode="numeric" maxlength="6" autocomplete="one-time-code" data-lpignore="true" data-1p-ignore/></div>
    <p class="error" id="pdErr"></p>
    <div class="modal-actions"><button class="btn" data-close>${nudge ? 'Later' : 'Cancel'}</button><button class="btn primary" id="pdSave">Save PIN</button></div>`, (card) => {
    $('#pdSave', card).onclick = async () => {
      const a = $('#pd1', card).value.trim(), b = $('#pd2', card).value.trim();
      const weak = weakPin(a); if (weak) return ($('#pdErr', card).textContent = weak);
      if (a !== b) return ($('#pdErr', card).textContent = "PINs don't match");
      $('#pdSave', card).disabled = true; $('#pdErr', card).textContent = 'Securing your PIN…';
      const r = await core.setPin(a).catch(() => null);
      if (!r?.enabled) { $('#pdSave', card).disabled = false; return ($('#pdErr', card).textContent = 'Could not save — try again.'); }
      closeModal(); toast('Login PIN saved ✅');
    };
  });
}
function passcodeDialog() {
  openModal(`<h3>${A.hasPasscode ? 'Change passcode' : 'Set a passcode'}</h3>
    <p class="muted">QChat will ask for it when you open the app. If you forget it, log out and restore with your recovery key + a backup.</p>
    <div class="field"><span>New passcode (min 4 characters)</span><input type="password" id="pc1" autocomplete="new-password"/></div>
    <div class="field"><span>Repeat</span><input type="password" id="pc2" autocomplete="new-password"/></div>
    <p class="error" id="pcErr"></p>
    <div class="modal-actions">${A.hasPasscode ? '<button class="btn danger" id="pcRemove">Remove passcode</button>' : ''}<button class="btn" data-close>Cancel</button><button class="btn primary" id="pcSave">Save</button></div>`, (card) => {
    $('#pcSave', card).onclick = async () => {
      const a = $('#pc1', card).value, b = $('#pc2', card).value;
      if (a.length < 4) return ($('#pcErr', card).textContent = 'Use at least 4 characters');
      if (a !== b) return ($('#pcErr', card).textContent = "Passcodes don't match");
      $('#pcSave', card).disabled = true; $('#pcErr', card).textContent = 'Deriving key…';
      await db.setPasscode(a); A.hasPasscode = true; A.settings.autoLock ||= 5; persist('settings'); db.setPlain('autoLock', A.settings.autoLock);
      closeModal(); renderMe(); toast('Passcode set — local data is now locked with it');
    };
    $('#pcRemove', card) && ($('#pcRemove', card).onclick = async () => { await db.setPasscode(null); A.hasPasscode = false; closeModal(); renderMe(); toast('Passcode removed'); });
  });
}
function blockedDialog() {
  const list = [...A.blocked];
  openModal(`<h3>Blocked contacts</h3><ul class="list">${list.map((u) => `<li>${avatarHTML(u, 'sm')}<div class="grow"><b>${esc(displayName(u))}</b><small>@${esc(u)}</small></div><button class="btn" data-ub="${esc(u)}">Unblock</button></li>`).join('') || '<li class="muted">Nobody blocked.</li>'}</ul><div class="modal-actions"><button class="btn primary" data-close>Done</button></div>`, (card) => {
    card.onclick = (e) => { const b = e.target.closest('[data-ub]'); if (b) { toggleBlock(b.dataset.ub); blockedDialog(); } };
  });
}
async function wipeAndReload() { core.disconnect(); await db.wipe(); location.hash = ''; location.reload(); }
function showKicked(reason) {
  const text = reason === 'removed' ? 'This device was removed from your account. Local data has been erased.' : reason === 'deleted' ? 'This account was deleted.' : 'This device opened QChat in another tab.';
  if (reason === 'removed' || reason === 'deleted') { core.disconnect(); db.wipe(); }
  openModal(`<h3>Signed out</h3><p class="muted">${esc(text)}</p><div class="modal-actions"><button class="btn primary" id="kReload">OK</button></div>`, (card) => { $('#kReload', card).onclick = () => location.reload(); });
}

// ======================= history: sync to a new device, encrypted backup =======================
async function snapshot({ withMedia, maxMedia = 5e6 }) {
  const verified = Object.fromEntries(Object.entries(K.contacts).filter(([, c]) => c.verified).map(([u, c]) => [u, c.aik]));
  const out = { chats: A.chats, blocked: [...A.blocked], settings: A.settings, verified, msgs: A.msgs, media: {} };
  if (withMedia) for (const list of Object.values(A.msgs)) for (const m of list) if (m.media && (m.media.size || 0) <= maxMedia) { const b = await mediaBytes(m.media.id); if (b) out.media[m.media.id] = C.b64(b); }
  return out;
}
async function mergeSnapshot(s) {
  let added = 0;
  for (const [id, c] of Object.entries(s.chats || {})) if (!A.chats[id]) { A.chats[id] = { ...c, unread: 0 }; persist('chats'); }
  for (const [cid, list] of Object.entries(s.msgs || {})) {
    if (!A.chats[cid]) continue;
    const have = new Set((A.msgs[cid] ||= []).map((m) => m.id));
    for (const m of list) if (!have.has(m.id)) { if (m.kind === 'sys' && m.variant === 'e2e' && A.msgs[cid].some((x) => x.variant === 'e2e')) continue; A.msgs[cid].push({ ...m, readSent: true }); msgIndex.set(m.id, cid); added++; }
    A.msgs[cid].sort((a, b) => a.ts - b.ts); persist('msgs:' + cid);
  }
  const mimes = new Map(); for (const list of Object.values(A.msgs)) for (const m of list) if (m.media) mimes.set(m.media.id, m.media.mime);
  for (const [id, data] of Object.entries(s.media || {})) await putMedia(id, C.unb64(data), mimes.get(id) || 'application/octet-stream');
  for (const u of s.blocked || []) A.blocked.add(u); persist('blocked');
  for (const [u, aik] of Object.entries(s.verified || {})) { const c = K.contacts[u] || (await core.refreshUser(u)); if (c && c.aik === aik) { c.verified = true; db.set('contacts', K.contacts); } }
  renderChatList(); if (A.current) scheduleRender(false);
  core.wsSend({ t: 'watch', users: Object.values(A.chats).filter((c) => c.type === 'dm').map((c) => c.peer) });
  return added;
}
async function onSyncRequest(fd, p) {
  const dev = core.myDevices().find((d) => d.device === fd);
  const ok = await confirmDialog('Copy history to your new device?', `“${p.name || dev?.name || 'New device'}” was just linked to your account. Send it your chats and messages (end-to-end encrypted)?`, 'Copy history');
  if (!ok) return;
  toast('Sending history…', 5000);
  const snap = await snapshot({ withMedia: true, maxMedia: 3e6 });
  const parts = []; let cur = { msgs: {}, media: {} }, size = 0;
  const flush = () => { if (size) { parts.push(cur); cur = { msgs: {}, media: {} }; size = 0; } };
  for (const [cid, list] of Object.entries(snap.msgs)) for (const m of list) { (cur.msgs[cid] ||= []).push(m); size += JSON.stringify(m).length; if (size > 3e6) flush(); }
  for (const [id, d] of Object.entries(snap.media)) { cur.media[id] = d; size += d.length; if (size > 3e6) flush(); }
  flush();
  const sid = C.randId(6);
  const total = parts.length + 1;
  await core.sendPayload([], { type: 'sync_data', sid, part: 0, total, chats: snap.chats, blocked: snap.blocked, verified: snap.verified }, { devices: [{ u: ME(), d: fd }] });
  for (let i = 0; i < parts.length; i++) await core.sendPayload([], { type: 'sync_data', sid, part: i + 1, total, ...parts[i] }, { devices: [{ u: ME(), d: fd }] });
  toast('History sent to your new device');
}
async function onSyncData(p) {
  await mergeSnapshot(p);
  toast(p.part + 1 >= p.total ? 'Chat history copied ✅' : `Copying history… ${p.part + 1}/${p.total}`, 3000);
}
const BACKUP_MAGIC = C.te.encode('QCB1');
async function exportBackup() {
  toast('Preparing backup…');
  const snap = await snapshot({ withMedia: true, maxMedia: 15e6 });
  const body = C.te.encode(JSON.stringify({ v: 1, user: ME(), at: Date.now(), ...snap }));
  const { iv, ct } = await C.aesEncrypt(K.keys.backupKey, body, C.te.encode('qchat-backup-v1|' + ME()));
  const blob = new Blob([BACKUP_MAGIC, iv, ct], { type: 'application/octet-stream' });
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `qchat-${ME()}-${new Date().toISOString().slice(0, 10)}.qcb`; a.click();
  toast('Backup downloaded (encrypted)');
}
async function importBackup(file) {
  const buf = new Uint8Array(await file.arrayBuffer());
  if (C.td.decode(buf.subarray(0, 4)) !== 'QCB1') return toast('Not a QChat backup file');
  try {
    const pt = await C.aesDecrypt(K.keys.backupKey, buf.subarray(4, 16), buf.subarray(16), C.te.encode('qchat-backup-v1|' + ME()));
    const snap = JSON.parse(C.td.decode(pt));
    const n = await mergeSnapshot(snap); closeModal(); toast(`Backup restored — ${n} messages added`);
  } catch { toast('This backup belongs to a different account (or is damaged)'); }
}

// ---------- automatic end-to-end encrypted backup on the server ----------
// The same snapshot as an exported backup, encrypted with the account's backup key (from the recovery key seeds).
// The server stores ciphertext only. It comes back when you log in on a new device or after clearing the browser.
const CLOUD_MAX = 18e6; let cloudT = null, cloudLast = 0, cloudBusy = false;
const cloudAad = () => C.te.encode('qchat-cloud-v1|' + ME());
function scheduleCloudBackup(delay = 20000) {
  if (!K.id || A.settings.cloudBackup === false) return;
  const memOnly = db.isMemoryOnly(); // nothing survives a reload here, so back up sooner
  if (memOnly) delay = Math.min(delay, 3000);
  clearTimeout(cloudT); cloudT = setTimeout(() => uploadCloudBackup().catch((e) => console.warn('backup', e)), Math.max(delay, cloudLast + (memOnly ? 15000 : 60000) - Date.now()));
}
async function uploadCloudBackup() {
  if (!K.id || cloudBusy || A.settings.cloudBackup === false) return false;
  cloudBusy = true;
  try {
    await flushPersist();
    const snap = await snapshot({ withMedia: true, maxMedia: 2e6 });
    let body = JSON.stringify({ v: 1, user: ME(), at: Date.now(), ...snap });
    if (body.length > CLOUD_MAX) { // too big: drop the largest media until it fits (messages always come first)
      const ids = Object.keys(snap.media).sort((a, b) => snap.media[b].length - snap.media[a].length);
      while (body.length > CLOUD_MAX && ids.length) { delete snap.media[ids.shift()]; body = JSON.stringify({ v: 1, user: ME(), at: Date.now(), ...snap }); }
    }
    const { iv, ct } = await C.aesEncrypt(K.keys.backupKey, C.te.encode(body), cloudAad());
    const r = await core.rpc({ t: 'backup_put', iv: C.b64(iv), ct: C.b64(ct) }, 'backup_ok', 60000);
    cloudLast = Date.now();
    if (r?.ok) { A.settings.cloudBackupAt = r.at || Date.now(); persist('settings'); return true; }
    return false;
  } finally { cloudBusy = false; }
}
async function restoreCloudBackup() {
  const r = await core.rpc({ t: 'backup_get' }, 'backup', 60000);
  if (!r || r.none || !r.ct) return 0;
  try {
    const pt = await C.aesDecrypt(K.keys.backupKey, C.unb64(r.iv), C.unb64(r.ct), cloudAad());
    const n = await mergeSnapshot(JSON.parse(C.td.decode(pt)));
    if (n) toast(`Restored ${n} messages from your encrypted backup ✅`, 5000);
    return n;
  } catch (e) { console.warn('backup restore failed', e); return 0; }
}

// ---------- log out: keep everything, locked ----------
async function logOut() {
  toast('Saving your chats…', 4000);
  clearTimeout(cloudT);
  await uploadCloudBackup().catch(() => false); // latest copy on the server too
  await flushPersist();
  core.disconnect();
  await db.signOut(K.keys.backupKey, ME());
  location.hash = ''; location.reload();
}

// ======================= status (24-hour stories) =======================
const STATUS_BGS = ['#5b2bb5', '#3a86ff', '#8e7dbe', '#ef476f', '#ff8800', '#264653', '#e76f51'];
const statusAudience = () => { // people you chat with directly or share a group with
  const s = new Set();
  for (const c of Object.values(A.chats)) { if (c.type === 'dm') s.add(c.peer); else if (!c.left && !isBig(c)) c.members.forEach((u) => s.add(u)); }
  s.delete(ME()); for (const u of A.blocked) s.delete(u); return [...s];
};
async function postStatus(s) {
  const id = C.randId(10), ts = Date.now();
  const mine = { id, kind: s.kind, text: s.text || '', bg: s.bg, ts, expireAt: ts + STATUS_TTL, views: {} };
  const payload = { type: 'status', id, kind: s.kind, text: s.text || '', bg: s.bg, ts };
  if (s.media) { const mid = C.randId(10); await putMedia(mid, s.media.bytes, s.media.mime); mine.media = { id: mid, mime: s.media.mime }; payload.media = { data: C.b64(s.media.bytes), mime: s.media.mime }; }
  A.myStatus.push(mine); persist('statuses'); renderStatusBadge();
  await core.sendPayload(statusAudience(), payload, { id });
  toast('Status shared with your contacts');
}
async function onStatus(from, ts, p) {
  const fromMe = from === ME();
  if (p.type === 'status') {
    const s = { id: String(p.id), kind: p.kind === 'image' ? 'image' : 'text', text: clip(p.text, 700), bg: STATUS_BGS.includes(p.bg) ? p.bg : STATUS_BGS[0], ts: Math.min(p.ts || ts, ts), expireAt: Math.min(p.ts || ts, ts) + STATUS_TTL, seen: false };
    if (s.expireAt < Date.now()) return;
    if (p.media?.data) { const mid = C.randId(10); await putMedia(mid, C.unb64(p.media.data), p.media.mime); s.media = { id: mid, mime: p.media.mime }; }
    if (fromMe) { if (!A.myStatus.some((x) => x.id === s.id)) A.myStatus.push({ ...s, views: {} }); }
    else { const list = (A.statuses[from] ||= []); if (!list.some((x) => x.id === s.id)) list.push(s); }
  } else if (p.type === 'status_seen') {
    const s = A.myStatus.find((x) => x.id === p.id); if (s && !fromMe) s.views[from] = ts;
  } else if (p.type === 'status_del') {
    if (fromMe) A.myStatus = A.myStatus.filter((x) => x.id !== p.id);
    else if (A.statuses[from]) A.statuses[from] = A.statuses[from].filter((x) => x.id !== p.id);
  }
  persist('statuses'); renderStatusBadge();
}
function renderStatusBadge() { const n = Object.values(A.statuses).filter((l) => l.some((s) => !s.seen)).length; const b = $('#statusBtn'); b.dataset.count = n || ''; b.classList.toggle('has-new', n > 0); b.classList.toggle('has-live', Object.keys(live.lives).length > 0); }
function statusDialog() {
  const people = Object.entries(A.statuses).filter(([, l]) => l.length).sort((a, b) => (a[1].every((s) => s.seen) - b[1].every((s) => s.seen)) || b[1].at(-1).ts - a[1].at(-1).ts);
  const liveNow = Object.entries(live.lives);
  openModal(`<h3>Status</h3>
    <div id="stLive">${liveNow.length ? `<div class="section-title">🔴 Live now</div><ul class="list">${liveNow.map(([u, l]) => `<li class="pick" data-watch="${esc(u)}"><div class="ring live-ring">${avatarHTML(u, 'sm')}</div><div class="grow"><b>${esc(displayName(u))}</b><small>${esc(l.title || 'Live video')} · started ${fmtAgo(l.started)}</small></div><span class="live-badge">LIVE</span></li>`).join('')}</ul>` : ''}</div>
    <button class="btn live-btn" id="stGoLive">🔴 Go live</button>
    <ul class="list"><li class="pick" id="stMine">${avatarHTML(ME())}<div class="grow"><b>My status</b><small>${A.myStatus.length ? `${A.myStatus.length} update${A.myStatus.length > 1 ? 's' : ''} · ${fmtAgo(A.myStatus.at(-1).ts)}` : 'Tap below to add a status update'}</small></div></li></ul>
    <div class="row"><button class="btn" id="stText">✏️ Text status</button><label class="btn">📷 Photo status<input type="file" id="stPhoto" accept="image/*" hidden/></label></div>
    <p class="muted small">Visible for 24 hours to the people you chat with. End-to-end encrypted.</p>
    <div class="section-title">Recent updates</div>
    <ul class="list">${people.map(([u, l]) => `<li class="pick" data-st="${esc(u)}"><div class="ring ${l.every((s) => s.seen) ? 'seen' : ''}">${avatarHTML(u, 'sm')}</div><div class="grow"><b>${esc(displayName(u))}</b><small>${fmtAgo(l.at(-1).ts)}</small></div></li>`).join('') || '<li class="muted">No updates from your contacts yet.</li>'}</ul>
    <div class="modal-actions"><button class="btn primary" data-close>Close</button></div>`, (card) => {
    $('#stMine', card).onclick = () => { if (A.myStatus.length) { closeModal(); viewStatuses(ME(), A.myStatus); } };
    $('#stText', card).onclick = textStatusDialog;
    $('#stPhoto', card).onchange = async (e) => {
      const f = e.target.files[0]; if (!f) return;
      const bytes = (await compressImage(f, 1280, 0.8)) || (await readFileBytes(f));
      if (bytes.length > 8e6) return toast('Image too large');
      closeModal(); await postStatus({ kind: 'image', media: { bytes, mime: 'image/jpeg' }, text: '' });
    };
    card.querySelectorAll('[data-st]').forEach((li) => (li.onclick = () => { closeModal(); viewStatuses(li.dataset.st, A.statuses[li.dataset.st]); }));
    card.querySelectorAll('[data-watch]').forEach((li) => (li.onclick = () => { closeModal(); live.watch(li.dataset.watch); }));
    $('#stGoLive', card).onclick = goLiveDialog;
  });
}
function goLiveDialog() {
  const audience = statusAudience();
  openModal(`<h3>🔴 Go live</h3>
    <p class="muted small">Stream your camera to your contacts (${audience.length}). They'll get a notification and can join, comment and send hearts. Video, audio and comments are end-to-end encrypted with post-quantum keys. Up to 20 viewers at once.</p>
    <div class="field"><span>Title (optional)</span><input id="glTitle" maxlength="80" placeholder="What's happening?"/></div>
    <div class="modal-actions"><button class="btn" data-close>Cancel</button><button class="btn primary" id="glGo">Start live video</button></div>`, (card) => {
    const go = () => { const t = $('#glTitle', card).value; closeModal(); live.goLive(t, audience, window.__QCHAT_PREVIEW ? window.__qchatLiveSim?.(ME(), true) : null); };
    $('#glGo', card).onclick = go; $('#glTitle', card).onkeydown = (e) => { if (e.key === 'Enter') go(); };
  });
}

// ======================= donate =======================
function donateDialog() {
  const addr = DONATE_BTC;
  if (!validBtcAddress(addr)) return toast('Donations are unavailable right now');
  openModal(`<h3>🧡 Support QChat</h3>
    <p class="muted small">QChat has no ads and never sells data. If it's useful to you, a Bitcoin donation helps keep the servers running.</p>
    <div class="qr">${qrSvg('bitcoin:' + addr)}</div>
    <div class="donate-addr"><span class="muted small">Bitcoin (BTC) address</span><code id="dnAddr">${esc(groupAddress(addr))}</code></div>
    <p class="donate-warn small">🛡️ This is the <b>only</b> QChat donation address, and it's built into the app. QChat will never message you asking for crypto — anyone in a chat who does is a scammer. Check the first and last characters in your wallet before sending, and only send Bitcoin (BTC) to it.</p>
    <div class="modal-actions"><button class="btn" id="dnCopy">Copy address</button><a class="btn" id="dnWallet" href="bitcoin:${addr}">Open in wallet</a><button class="btn primary" data-close>Done</button></div>`, (card) => {
    $('#dnCopy', card).onclick = () => navigator.clipboard?.writeText(addr).then(() => toast('Bitcoin address copied'), () => toast('Copy the address above'));
  });
}

// ======================= share my link =======================
const myLink = () => `${window.__QCHAT_PREVIEW ? 'https://your-qchat-domain' : location.origin}/@${ME()}`;
function qrSvg(text) { const q = qrcode(0, 'M'); q.addData(text); q.make(); return q.createSvgTag({ cellSize: 6, margin: 3, scalable: true }); }
function shareDialog() {
  const link = myLink();
  openModal(`<h3>🔗 Share my link</h3>
    <p class="muted small">Anyone who opens this link (or scans the QR code) can start an end-to-end encrypted chat with you. No phone number or email is shared — only your username.</p>
    <div class="qr">${qrSvg(link)}</div>
    <div class="share-link"><code id="shLink">${esc(link)}</code></div>
    ${window.__QCHAT_PREVIEW ? '<p class="muted small">⚠️ Preview: the server lives only in this tab, so the link works once you deploy the full app on your own domain.</p>' : ''}
    <div class="modal-actions"><button class="btn" id="shCopy">Copy link</button>${navigator.share ? '<button class="btn" id="shShare">Share…</button>' : ''}<button class="btn primary" data-close>Done</button></div>`, (card) => {
    $('#shCopy', card).onclick = () => navigator.clipboard?.writeText(`Chat with me privately on QChat (post-quantum encrypted): ${link}`).then(() => toast('Link copied'), () => toast('Copy the link above'));
    $('#shShare', card) && ($('#shShare', card).onclick = () => navigator.share({ title: 'Chat with me on QChat', text: `I'm @${ME()} on QChat — private, post-quantum encrypted chat.`, url: link }).catch(() => {}));
  });
}
// Opening https://host/@username starts a chat with that person (after sign-up/login if needed)
const inviteFromUrl = () => { const m = location.pathname.match(/^\/@([a-z0-9_.]{3,24})$/i); return m ? m[1].toLowerCase() : null; };
try { const inv = inviteFromUrl(); if (inv) sessionStorage.setItem('qchat-invite', inv); } catch {}
function consumeInvite() {
  let u = null; try { u = sessionStorage.getItem('qchat-invite'); sessionStorage.removeItem('qchat-invite'); } catch {}
  if (inviteFromUrl()) history.replaceState(null, '', '/');
  if (!u || u === ME()) return;
  if (A.chats['dm:' + u]) return openChat('dm:' + u);
  setTimeout(() => newChatDialog(u), 400);
}

// ======================= live UI =======================
let liveTimer;
function liveTick(started) { clearInterval(liveTimer); const f = () => ($('#liveTime').textContent = fmtDur((Date.now() - started) / 1000)); f(); liveTimer = setInterval(f, 1000); }
live.setLiveUI({
  name: displayName,
  open({ role, user, title, stream, started, connecting }) {
    const v = $('#liveView'); v.classList.remove('hidden'); v.classList.toggle('is-host', role === 'host'); v.classList.toggle('connecting', !!connecting);
    $('#liveHost').innerHTML = `${avatarHTML(user, 'sm')}<div><b>${esc(role === 'host' ? 'You' : displayName(user))}</b><small>${esc(title || 'Live video')}</small></div>`;
    $('#liveComments').innerHTML = ''; $('#liveViewers').textContent = '0';
    const vid = $('#liveVideo'); vid.srcObject = stream || null; vid.muted = role === 'host'; vid.classList.toggle('mirror', role === 'host');
    liveTick(started || Date.now()); $('#liveInput').value = '';
  },
  update({ title, started, viewers, connecting }) {
    if (title !== undefined) $('#liveHost small').textContent = title || 'Live video';
    if (started) liveTick(started);
    if (viewers !== undefined) $('#liveViewers').textContent = viewers;
    if (connecting !== undefined) $('#liveView').classList.toggle('connecting', connecting);
  },
  setRemote(stream) { const vid = $('#liveVideo'); vid.srcObject = stream; vid.muted = false; vid.play?.().catch(() => {}); $('#liveView').classList.remove('connecting'); },
  setLocal(stream, facing) { const vid = $('#liveVideo'); vid.srcObject = stream; vid.classList.toggle('mirror', facing === 'user'); },
  setViewers(n) { $('#liveViewers').textContent = n; },
  comment(c, quiet) {
    const box = $('#liveComments'); const el = document.createElement('div');
    el.className = 'lc' + (c.join ? ' join' : '') + (c.sys ? ' sys' : '') + (quiet ? ' quiet' : '');
    el.innerHTML = c.sys ? esc(c.text) : c.join ? `👋 <b>${esc(displayName(c.from))}</b> joined` : `${avatarHTML(c.from, 'xs')}<div><b>${esc(c.from === ME() ? 'You' : displayName(c.from))}</b> ${esc(c.text)}</div>`;
    box.appendChild(el);
    while (box.children.length > 7) box.firstElementChild.remove();
  },
  heart() {
    const h = document.createElement('span'); h.className = 'lh';
    h.textContent = ['❤️', '💚', '💙', '💜', '🧡', '😍'][Math.floor(Math.random() * 6)];
    h.style.setProperty('--dx', (Math.random() * 60 - 30).toFixed(0) + 'px'); h.style.right = (18 + Math.random() * 30).toFixed(0) + 'px';
    $('#liveHearts').appendChild(h); setTimeout(() => h.remove(), 2600);
  },
  close({ role, duration, viewers, comments }) {
    clearInterval(liveTimer); $('#liveView').classList.add('hidden'); $('#liveVideo').srcObject = null; $('#liveHearts').innerHTML = '';
    if (role === 'host') toast(`Live ended · ${fmtDur(duration / 1000)} · ${viewers} viewer${viewers === 1 ? '' : 's'} · ${comments} comments`, 5000);
  },
  ended(u) { toast(`${displayName(u)}'s live has ended`); },
  listChanged() { renderStatusBadge(); if ($('#stLive') && !$('#modal').classList.contains('hidden')) statusDialog(); },
  notifyLive(u, l) { toast(`🔴 ${displayName(u)} is live${l.title ? ': ' + l.title : ''} — open Status ⭕ to watch`, 6000); notify(null, { from: u, kind: 'text', text: `🔴 ${displayName(u)} started a live video` }); },
  simStream: (u) => window.__qchatLiveSim?.(u, false),
});
$('#liveForm').onsubmit = (e) => { e.preventDefault(); const t = $('#liveInput').value; $('#liveInput').value = ''; live.comment(t); };
$('#liveHeart').onclick = () => live.heart();
$('#liveClose').onclick = () => (live.liveInfo().host ? confirmDialog('End live video?', 'Your viewers will be disconnected.', 'End live', true).then((y) => y && live.endLive()) : live.leave());
$('#liveFlip').onclick = () => live.flipCamera();
$('#liveMic').onclick = (e) => { const on = live.toggleMic(); if (on !== null) e.currentTarget.classList.toggle('off', !on); };
$('#liveVideo').addEventListener('dblclick', () => live.heart());
function textStatusDialog() {
  let bg = STATUS_BGS[0];
  openModal(`<h3>Text status</h3><div class="status-compose" id="stPrev" style="background:${bg}"><textarea id="stInput" maxlength="700" placeholder="Type a status"></textarea></div>
    <div class="colors" style="margin-top:10px">${STATUS_BGS.map((c) => `<button type="button" data-bg="${c}" style="background:${c}" class="${c === bg ? 'sel' : ''}"></button>`).join('')}</div>
    <div class="modal-actions"><button class="btn" data-close>Cancel</button><button class="btn primary" id="stPost">Share</button></div>`, (card) => {
    card.querySelectorAll('[data-bg]').forEach((b) => (b.onclick = () => { bg = b.dataset.bg; $('#stPrev', card).style.background = bg; card.querySelectorAll('[data-bg]').forEach((x) => x.classList.toggle('sel', x === b)); }));
    $('#stPost', card).onclick = async () => { const text = $('#stInput', card).value.trim(); if (!text) return; closeModal(); await postStatus({ kind: 'text', text, bg }); };
  });
}
let sv = null;
function viewStatuses(user, list) {
  if (!list?.length) return;
  const start = Math.max(0, list.findIndex((s) => !s.seen));
  sv = { user, list, i: start, timer: null };
  $('#statusViewer').classList.remove('hidden'); showStatusItem();
}
async function showStatusItem() {
  if (!sv) return; clearTimeout(sv.timer);
  const s = sv.list[sv.i]; if (!s) return closeStatusViewer();
  const mine = sv.user === ME();
  const v = $('#statusViewer');
  const url = s.media ? await mediaURL(s.media.id) : null;
  v.innerHTML = `<div class="sv-bars">${sv.list.map((_, i) => `<div class="sv-bar"><div class="${i < sv.i ? 'full' : i === sv.i ? 'run' : ''}"></div></div>`).join('')}</div>
    <div class="sv-head">${avatarHTML(sv.user, 'sm')}<div class="grow"><b>${esc(mine ? 'My status' : displayName(sv.user))}</b><small>${fmtAgo(s.ts)}</small></div>${mine ? '<button class="icon-btn" id="svDel" title="Delete">🗑</button>' : ''}<button class="icon-btn" id="svClose">✕</button></div>
    <div class="sv-body" style="background:${s.kind === 'text' ? s.bg : '#000'}">${s.kind === 'image' ? `<img src="${url || ''}" alt=""/>` : `<div class="sv-text">${linkify(s.text)}</div>`}</div>
    ${mine ? `<div class="sv-foot">👁 ${Object.keys(s.views || {}).length} view${Object.keys(s.views || {}).length === 1 ? '' : 's'}${Object.keys(s.views || {}).length ? ': ' + Object.keys(s.views).map((u) => esc(displayName(u))).join(', ') : ''}</div>`
      : `<div class="sv-foot"><input id="svReply" placeholder="Reply…"/><button class="btn primary" id="svSend">Send</button></div>`}
    <button class="sv-nav prev" id="svPrev"></button><button class="sv-nav next" id="svNext"></button>`;
  if (!mine && !s.seen) { s.seen = true; persist('statuses'); renderStatusBadge(); if (A.settings.readReceipts) core.sendPayload([sv.user], { type: 'status_seen', id: s.id }, { self: false }); }
  $('#svClose').onclick = closeStatusViewer;
  $('#svPrev').onclick = () => { sv.i = Math.max(0, sv.i - 1); showStatusItem(); };
  $('#svNext').onclick = () => { sv.i++; showStatusItem(); };
  if (mine) $('#svDel').onclick = () => { core.sendPayload(statusAudience(), { type: 'status_del', id: s.id }); A.myStatus = A.myStatus.filter((x) => x.id !== s.id); persist('statuses'); closeStatusViewer(); };
  else {
    const input = $('#svReply');
    input.onfocus = () => clearTimeout(sv.timer);
    const send = async () => { const text = input.value.trim(); if (!text) return; const chat = createDm(sv.user); await sendMessage(chat, { text, replyTo: { id: 'status:' + s.id, from: sv.user, preview: '📢 Status: ' + (s.kind === 'text' ? s.text.slice(0, 80) : 'Photo') } }); toast('Reply sent'); closeStatusViewer(); };
    $('#svSend').onclick = send; input.onkeydown = (e) => { if (e.key === 'Enter') send(); };
  }
  sv.timer = setTimeout(() => { if (sv) { sv.i++; showStatusItem(); } }, 6000);
}
function closeStatusViewer() { if (!sv) return; clearTimeout(sv.timer); sv = null; $('#statusViewer').classList.add('hidden'); $('#statusViewer').innerHTML = ''; }

// ======================= calls UI =======================
calls.setCallUI({
  show(c, status, incoming) {
    const v = $('#callView'); v.classList.remove('hidden');
    v.classList.toggle('audio-only', !c.video); v.classList.toggle('has-video', !!c.video);
    const chat = A.chats[c.chatId];
    $('#callAvatar').outerHTML = avatarHTML(chat?.type === 'group' ? chat : c.peerUser || c.caller?.u).replace('class="avatar', 'id="callAvatar" class="avatar');
    $('#callName').textContent = chat ? chatTitle(chat) : displayName(c.peerUser);
    $('#callStatus').textContent = status;
    $('#acceptBtn').classList.toggle('hidden', !incoming); $('#camBtn').classList.toggle('hidden', !c.video || incoming); $('#muteBtn').classList.toggle('hidden', incoming);
    $('#muteBtn').classList.remove('off'); $('#camBtn').classList.remove('off');
    $('#localVideo').srcObject = c.local || null;
    this.render(c);
  },
  render(c) {
    const grid = $('#callGrid');
    const peers = [...c.peers.values()];
    for (const t of $$('.tile', grid)) if (!c.peers.has(t.dataset.pid)) t.remove();
    for (const p of peers) {
      let t = grid.querySelector(`.tile[data-pid="${CSS.escape(p.id)}"]`);
      if (!t) { t = document.createElement('div'); t.className = 'tile'; t.dataset.pid = p.id; t.innerHTML = `<video autoplay playsinline></video>${avatarHTML(p.u, 'big')}<div class="tile-name">${esc(displayName(p.u))}</div>`; grid.appendChild(t); }
      const vid = t.querySelector('video'); if (p.stream && vid.srcObject !== p.stream) vid.srcObject = p.stream;
      t.classList.toggle('connected', p.connected);
    }
    grid.dataset.n = peers.length;
    $('#callView').classList.toggle('has-peers', peers.length > 0);
    clearTimeout(this.t);
    if (c.connectedAt) { const tick = () => { if (!calls.callInfo()) return; $('#callStatus').textContent = `🔒 PQ-encrypted · ${fmtDur((Date.now() - c.connectedAt) / 1000)}${c.g ? ` · ${peers.length + 1} people` : ''}`; this.t = setTimeout(tick, 1000); }; tick(); }
  },
  hide() { clearTimeout(this.t); $('#callView').classList.add('hidden'); $('#callGrid').innerHTML = ''; $('#localVideo').srcObject = null; },
  log(c, reason) {
    const chat = A.chats[c.chatId] || (c.peerUser ? createDm(c.peerUser) : null); if (!chat) return;
    const type = c.video ? 'video' : 'voice';
    const dur = c.connectedAt ? fmtDur((Date.now() - c.connectedAt) / 1000) : null;
    let text;
    if (c.g) text = dur ? `📞 Group ${type} call · ${dur}` : c.role === 'callee' ? `📵 Missed group ${type} call` : `📞 Group ${type} call · ${reason || 'No answer'}`;
    else text = dur ? `${c.role === 'caller' ? '📞 Outgoing' : '📞 Incoming'} ${type} call · ${dur}` : c.role === 'callee' ? `📵 ${reason === 'Declined' ? 'Declined' : 'Missed'} ${type} call` : `📞 ${type[0].toUpperCase() + type.slice(1)} call · ${reason || 'Cancelled'}`;
    addMessage(chat, { id: C.randId(10), from: c.role === 'caller' ? ME() : c.caller?.u || '', ts: Date.now(), kind: 'call', text });
    if (reason && !['Missed', 'Declined', 'Call ended', 'No answer'].includes(reason)) toast(reason);
  },
  ringNotify(c, from) { notify(A.chats[c.chatId] || createDm(from), { from, kind: 'text', text: `📞 Incoming ${c.video ? 'video' : 'voice'} call` }); },
});
function startCallHere(video) {
  const chat = A.chats[A.current]; if (!chat) return;
  calls.startCall(chat, video, chatRecipients(chat));
}
$('#voiceCallBtn').onclick = () => startCallHere(false);
$('#videoCallBtn').onclick = () => startCallHere(true);
$('#acceptBtn').onclick = () => calls.accept();
$('#hangBtn').onclick = () => calls.hangUp();
$('#muteBtn').onclick = (e) => { const on = calls.toggle('audio'); if (on !== null) e.currentTarget.classList.toggle('off', !on); };
$('#camBtn').onclick = (e) => { const on = calls.toggle('video'); if (on !== null) e.currentTarget.classList.toggle('off', !on); };

// ======================= wiring =======================
$('#newChatBtn').onclick = () => newChatDialog();
$('#shareBtn').onclick = shareDialog;
$('#donateBtn').onclick = donateDialog;
for (const el of document.querySelectorAll('[data-donate]')) el.onclick = (e) => { e.preventDefault(); donateDialog(); };
$('#welcomeShare').onclick = shareDialog;
$('#newGroupBtn').onclick = newGroupDialog;
$('#statusBtn').onclick = statusDialog;
$('#settingsBtn').onclick = settingsDialog;
$('#meAvatar').onclick = settingsDialog;
$('#lockBtn').onclick = () => location.reload();
$('#backBtn').onclick = closeChat;
$('#chatTitleBox').onclick = () => { const c = A.chats[A.current]; if (c) c.type === 'dm' ? contactInfo(c.peer) : groupInfo(c); };
$('#chatInfoBtn').onclick = () => $('#chatTitleBox').click();
$('.chat-head').addEventListener('click', (e) => { if (e.target.closest('#chatAvatar')) $('#chatTitleBox').click(); });
$('#searchInChatBtn').onclick = () => { $('#inChatSearch').classList.toggle('hidden'); $('#inChatSearchInput').focus(); };
$('#inChatSearchInput').oninput = () => scheduleRender(false);
$('#inChatSearchClose').onclick = () => { $('#inChatSearchInput').value = ''; $('#inChatSearch').classList.add('hidden'); scheduleRender(true); };
$('#chatSearch').oninput = (e) => { A.search = e.target.value; renderChatList(); };
$('#chatSearch').onkeydown = (e) => { if (e.key === 'Enter') $('#chatList .chat-item')?.click(); };
$$('.filters .chip').forEach((b) => (b.onclick = () => { A.filter = b.dataset.filter; $$('.filters .chip').forEach((x) => x.classList.toggle('active', x === b)); renderChatList(); }));
$('#chatList').onclick = (e) => { const li = e.target.closest('.chat-item'); if (!li) return; if (li.dataset.start) return newChatDialog(li.dataset.start); openChat(li.dataset.id); };
$('#chatList').oncontextmenu = (e) => {
  const li = e.target.closest('.chat-item[data-id]'); if (!li) return; e.preventDefault();
  const chat = A.chats[li.dataset.id]; const menu = $('#ctxMenu');
  menu.innerHTML = [['pin', chat.pinned ? 'Unpin chat' : 'Pin chat'], ['mute', chat.muted ? 'Unmute' : 'Mute notifications'], ['arch', chat.archived ? 'Unarchive' : 'Archive chat'], ['read', 'Mark as read'], ['del', 'Delete chat', 'danger']].map(([a, l, c]) => `<button class="item ${c || ''}" data-act="${a}">${l}</button>`).join('');
  menu.classList.remove('hidden'); menu.style.left = Math.min(e.clientX, innerWidth - 200) + 'px'; menu.style.top = Math.min(e.clientY, innerHeight - 220) + 'px';
  menu.onclick = async (ev) => {
    const a = ev.target.closest('[data-act]')?.dataset.act; menu.classList.add('hidden');
    if (a === 'pin') chat.pinned = !chat.pinned; if (a === 'mute') chat.muted = !chat.muted; if (a === 'arch') chat.archived = !chat.archived;
    if (a === 'read') markRead(chat);
    if (a === 'del') { if (await confirmDialog('Delete chat?', 'The chat will be removed from this device.', 'Delete', true)) deleteChat(chat); return; }
    persist('chats'); renderChatList(); if (['pin', 'mute', 'arch'].includes(a)) syncChatState(chat);
  };
};
const msgInput = $('#msgInput');
msgInput.addEventListener('input', () => { autoGrow(); updateSendBtn(); onComposerInput(); });
msgInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) { e.preventDefault(); if (msgInput.value.trim()) submitComposer(); }
  if (e.key === 'Escape' && (A.replyTo || A.editing)) { if (A.editing) msgInput.value = ''; A.replyTo = null; A.editing = null; updateReplyBar(); updateSendBtn(); }
});
msgInput.addEventListener('paste', (e) => { const files = [...(e.clipboardData?.files || [])]; if (files.length) { e.preventDefault(); sendFiles(files); } });
$('#sendBtn').onclick = submitComposer;
$('#replyCancel').onclick = () => { if (A.editing) msgInput.value = ''; A.replyTo = null; A.editing = null; updateReplyBar(); updateSendBtn(); };
$('#emojiBtn').onclick = () => { if ($('#emojiPanel').classList.contains('hidden')) pickEmoji(null); else $('#emojiPanel').classList.add('hidden'); };
$('#attachBtn').onclick = () => $('#fileInput').click();
$('#fileInput').onchange = (e) => { sendFiles([...e.target.files]); e.target.value = ''; };
$('#recCancel').onclick = () => stopRecording(false);
$('#recSend').onclick = () => stopRecording(true);
$('#unblockBtn').onclick = () => { const c = A.chats[A.current]; if (c) toggleBlock(c.peer); };
$('#strangerOk').onclick = () => { const c = A.chats[A.current]; if (c) { c.stranger = false; persist('chats'); updateSafetyBars(c); scheduleRender(false); } };
$('#strangerReport').onclick = () => { const c = A.chats[A.current]; if (c) reportDialog(c.peer); };
$('#keyVerify').onclick = () => { const c = A.chats[A.current]; if (c) contactInfo(c.peer); };
$('#keyAccept').onclick = async () => { const c = A.chats[A.current]; if (!c) return; if (!(await confirmDialog('Accept the new security code?', 'Only do this if you\'re confident it\'s really them (e.g. they told you they reinstalled). Comparing safety numbers is safer.', 'Accept'))) return; K.contacts[c.peer].keyChanged = false; db.set('contacts', K.contacts); addSys(c, `You accepted ${displayName(c.peer)}'s new security code without verifying it.`); updateSafetyBars(c); };
const msgsBox = $('#messages');
msgsBox.addEventListener('dragover', (e) => e.preventDefault());
msgsBox.addEventListener('drop', (e) => { e.preventDefault(); if (e.dataTransfer.files.length) sendFiles([...e.dataTransfer.files]); });
msgsBox.addEventListener('click', async (e) => {
  const rs = e.target.closest('[data-resend]'); if (rs) { const m = findMsg(rs.dataset.resend); if (m) { m.status = 'sending'; touchMsg(m); const ok = await sendEvent(A.chats[m.chat], await msgPayload(m), { id: m.id, push: 'msg' }); if (!ok) { m.status = 'failed'; touchMsg(m); } } return; }
  const lk = e.target.closest('a[data-url]'); if (lk) { e.preventDefault(); const m = findMsg(lk.closest('.msg')?.dataset.id); return linkDialog(lk.dataset.url, m ? linkCtx(m, A.chats[m.chat]) : {}); }
  const rf = e.target.closest('a.file[data-risk]'); if (rf) { e.preventDefault(); if (await confirmDialog('Download this file?', rf.dataset.risk, 'Download anyway', true)) { const a = document.createElement('a'); a.href = rf.dataset.href; a.download = rf.getAttribute('download'); a.click(); } return; }
  const caret = e.target.closest('[data-menu]'); if (caret) { e.stopPropagation(); const r = caret.getBoundingClientRect(); return openMsgMenu(caret.dataset.menu, r.left, r.bottom); }
  const q = e.target.closest('[data-jump]'); if (q) { const el = msgsBox.querySelector(`.msg[data-id="${CSS.escape(q.dataset.jump)}"]`); if (el) { el.scrollIntoView({ block: 'center', behavior: 'smooth' }); el.classList.remove('flash'); void el.offsetWidth; el.classList.add('flash'); } return; }
  const rx = e.target.closest('[data-reacts]'); if (rx) { const m = findMsg(rx.dataset.reacts); return toast(Object.entries(m.reactions).map(([u, em]) => `${em} ${displayName(u)}`).join('\n'), 4000); }
  const img = e.target.closest('img.media'); if (img) { const lb = $('#lightbox'); lb.innerHTML = `<img src="${img.src}" alt=""/>`; lb.classList.remove('hidden'); }
});
msgsBox.addEventListener('contextmenu', (e) => { const el = e.target.closest('.msg[data-id]'); if (!el) return; e.preventDefault(); openMsgMenu(el.dataset.id, e.clientX, e.clientY); });
msgsBox.addEventListener('dblclick', (e) => { const el = e.target.closest('.msg[data-id]'); if (!el || e.target.closest('a,audio,video')) return; const m = findMsg(el.dataset.id); if (m && !m.deleted) react(A.chats[A.current], m, '❤️'); });
$('#lightbox').onclick = () => $('#lightbox').classList.add('hidden');

// ======================= onboarding / lock / boot =======================
function show(id) { for (const s of ['#onboard', '#lockScreen', '#app']) $(s).classList.toggle('hidden', s !== id); }
$$('.tab').forEach((t) => (t.onclick = () => {
  $$('.tab').forEach((x) => x.classList.toggle('active', x === t));
  $('#createForm').classList.toggle('hidden', t.dataset.tab !== 'create');
  $('#restoreForm').classList.toggle('hidden', t.dataset.tab !== 'restore');
  $('#obError').textContent = '';
}));
const setObBusy = (b) => $$('.ob-form button').forEach((x) => (x.disabled = b));
let recoveryShown = null;
async function beginEnroll(identity, opts) {
  await db.createKeys();
  core.loadIdentity(identity);
  try {
    await core.enrollDevice(opts);
    await db.set('identity', identity);
    return true;
  } catch (e) {
    $('#obError').textContent = e.message; setObBusy(false); K.id = null; await db.wipe(); await db.openDb(); return false;
  }
}
$('#createForm').onsubmit = async (e) => {
  e.preventDefault(); $('#obError').textContent = '';
  const f = e.target; const user = f.username.value.trim().toLowerCase().replace(/^@/, '');
  if (!/^[a-z0-9_.]{3,24}$/.test(user)) return ($('#obError').textContent = 'Username must be 3–24 characters: a-z, 0-9, _ or .');
  if (!(await releaseSignedOut(user))) return;
  setObBusy(true); $('#obError').textContent = 'Generating post-quantum keys…';
  await new Promise((r) => setTimeout(r, 30));
  const seeds = C.newAccountSeeds();
  const ok = await beginEnroll(core.newIdentity(user, seeds), { register: true, profile: { displayName: f.displayName.value.trim() || user } });
  if (!ok) return;
  $('#obError').textContent = ''; setObBusy(false);
  recoveryShown = C.makeRecoveryKey(seeds);
  $('#createForm').classList.add('hidden'); $('.tabs').classList.add('hidden');
  $('#obKey').classList.remove('hidden'); $('#obKeyText').textContent = recoveryShown;
};
$('#toggleKeyLogin').onclick = () => {
  const useKey = $('#keyLoginField').classList.toggle('hidden') === false;
  $('#pinLoginField').classList.toggle('hidden', useKey);
  $('#toggleKeyLogin').textContent = useKey ? 'Remember your PIN? Log in with it instead' : 'Forgot your PIN? Recover your account with your recovery key';
  $('#obError').textContent = '';
};
// ---------- signed out: the account's data is still here, locked ----------
let signedOut = null; // username whose (locked) data is on this device
function showSignedOut(user) {
  signedOut = user; show('#onboard');
  $$('.tab').find((t) => t.dataset.tab === 'restore')?.click();
  $('#restoreForm [name=username]').value = user;
  $('#obWelcome').classList.remove('hidden');
  $('#obWelcome').innerHTML = `👋 Welcome back, <b>@${esc(user)}</b>. Your chats are saved on this device (encrypted) — log in to open them.`;
  setTimeout(() => $('#restoreForm [name=pin]').focus(), 50);
}
/** Before creating or logging into a different account on a device that holds a signed-out account's data. */
async function releaseSignedOut(user) {
  if (!signedOut || signedOut === user) return true;
  const ok = await confirmDialog(`Remove @${signedOut} from this device?`, `This device still holds @${signedOut}'s chats (encrypted). Continuing removes them from this device only — the account and its encrypted server backup are kept, and @${signedOut} can log back in anytime.`, 'Continue', true);
  if (!ok) return false;
  await db.wipe(); await db.openDb(); signedOut = null; $('#obWelcome').classList.add('hidden');
  return true;
}
/** Logging back in to the account whose data is on this device: unlock it, no new device needed. */
async function resumeSignedOut(user, seeds) {
  const keys = C.accountKeys(seeds);
  if (!(await db.signIn(keys.backupKey, user))) return false;
  const id = await db.get('identity');
  if (!id || id.user !== user || id.aikSeed !== C.b64(seeds.aikSeed)) { await db.wipe(); await db.openDb(); signedOut = null; return false; }
  signedOut = null; $('#obWelcome').classList.add('hidden'); $('#obError').textContent = '';
  await startApp(); toast('Welcome back! Your chats are right where you left them.', 4000);
  return true;
}

$('#restoreForm').onsubmit = async (e) => {
  e.preventDefault(); $('#obError').textContent = '';
  const f = e.target; const user = f.username.value.trim().toLowerCase().replace(/^@/, '');
  if (!/^[a-z0-9_.]{3,24}$/.test(user)) return ($('#obError').textContent = 'Enter your username');
  const useKey = !$('#keyLoginField').classList.contains('hidden');
  let seeds;
  if (useKey) { try { seeds = C.parseRecoveryKey(f.key.value); } catch (err) { return ($('#obError').textContent = err.message); } }
  else {
    const pin = f.pin.value.trim();
    if (!PIN_RE.test(pin)) return ($('#obError').textContent = 'Enter your 6-digit PIN');
    setObBusy(true); $('#obError').textContent = 'Checking your PIN…';
    try { seeds = await core.pinRecover(user, pin, (t) => ($('#obError').textContent = t)); }
    catch (err) { setObBusy(false); f.pin.value = ''; $('#obError').textContent = err.message; if (err.info?.wiped) $('#toggleKeyLogin').click(); return; }
  }
  if (signedOut === user) { // same account as the data on this device → just unlock it
    setObBusy(true); $('#obError').textContent = 'Unlocking your chats…';
    if (await resumeSignedOut(user, seeds)) return setObBusy(false);
  }
  setObBusy(false);
  if (!(await releaseSignedOut(user))) return;
  setObBusy(true); $('#obError').textContent = useKey ? 'Verifying recovery key…' : 'PIN correct — linking this device…';
  const ok = await beginEnroll(core.newIdentity(user, seeds), { register: false, confirmReplace: () => confirmDialog('Too many devices', 'You already have 5 linked devices. Logging in here will remove your oldest device.', 'Continue', true) });
  if (!ok) return;
  const finish = async () => {
    const n = await restoreCloudBackup().catch(() => 0); // chats from the encrypted server backup
    core.sendPayload([], { type: 'sync_req', name: K.id.dev.name }); // + anything newer from my other devices
    if (!n) toast('Logged in. If another of your devices is online, approve the history copy there.', 6000);
  };
  if (useKey) { // account recovered with the recovery key (PIN forgotten) → choose a new PIN first
    setObBusy(false); $('#obError').textContent = '';
    $('#restoreForm').classList.add('hidden'); $('.tabs').classList.add('hidden');
    $('#obPin h3').textContent = 'Account recovered — set a new login PIN';
    $('#obPin p.muted').textContent = 'Your recovery key worked. Choose a new 6-digit PIN for logging in from now on; it replaces any PIN you forgot.';
    $('#obPin').classList.remove('hidden'); $('#pin1').focus();
    afterPinStep = finish; return;
  }
  await afterLogin(); finish();
};
let afterPinStep = null;
$('#obCopy').onclick = () => navigator.clipboard?.writeText(recoveryShown).then(() => toast('Copied'));
$('#obDownload').onclick = () => {
  const blob = new Blob([`QChat recovery key\nUsername: ${ME()}\n\n${recoveryShown}\n\nKeep this secret. Anyone with it can log in as you.\n`], { type: 'text/plain' });
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `qchat-recovery-${ME()}.txt`; a.click();
};
$('#obContinue').onclick = () => { recoveryShown = null; $('#obKey').classList.add('hidden'); $('#obPin').classList.remove('hidden'); $('#pin1').focus(); };
$('#obPin').onsubmit = async (e) => {
  e.preventDefault();
  const a = $('#pin1').value.trim(), b = $('#pin2').value.trim();
  const weak = weakPin(a); if (weak) return ($('#pinErr').textContent = weak);
  if (a !== b) return ($('#pinErr').textContent = "PINs don't match");
  $('#pinSave').disabled = true; $('#pinErr').textContent = 'Securing your PIN…';
  const r = await core.setPin(a).catch(() => null);
  $('#pinSave').disabled = false;
  if (!r?.enabled) return ($('#pinErr').textContent = 'Could not save your PIN — check your connection and try again.');
  $('#pinErr').textContent = ''; await afterLogin();
  if (afterPinStep) { const f = afterPinStep; afterPinStep = null; f(); }
};

async function loadAppState() {
  A.chats = (await db.get('chats')) || {};
  A.settings = { ...A.settings, ...((await db.get('settings')) || {}) };
  A.blocked = new Set((await db.get('blocked')) || []);
  const st = (await db.get('statuses')) || {}; A.statuses = st.others || {}; A.myStatus = st.mine || [];
  for (const cid of Object.keys(A.chats)) { A.msgs[cid] = (await db.get('msgs:' + cid)) || []; for (const m of A.msgs[cid]) msgIndex.set(m.id, cid); }
  A.hasPasscode = await db.hasPasscode();
  A.secAlerts = (await db.get('secAlerts')) || [];
}
async function afterLogin() {
  K.me ||= { username: ME(), displayName: ME() };
  show('#app'); renderMe(); renderChatList(); renderStatusBadge();
  if ('Notification' in window && Notification.permission === 'default') Notification.requestPermission().catch(() => {});
  hooks.onReady();
  consumeInvite();
}
async function startApp() {
  const id = await db.get('identity');
  if (!id) { await db.wipe(); await db.openDb(); return show('#onboard'); }
  core.loadIdentity(id); await core.loadCrypto(); await loadAppState();
  K.me = { username: id.user, displayName: id.user };
  show('#app'); renderMe(); renderChatList(); renderStatusBadge(); setBanner(true);
  core.connect();
  const target = decodeURIComponent((location.hash.match(/#chat=([^&]+)/) || [])[1] || '');
  if (target && A.chats['dm:' + target]) openChat('dm:' + target);
  setTimeout(consumeInvite, 800);
  // auto-lock
  if (A.hasPasscode && A.settings.autoLock) {
    let last = Date.now(); for (const ev of ['mousemove', 'keydown', 'touchstart', 'click']) addEventListener(ev, () => (last = Date.now()), { passive: true });
    setInterval(() => { if (Date.now() - last > A.settings.autoLock * 60e3 && !calls.inCall()) location.reload(); }, 15000);
  }
}
$('#lockForm').onsubmit = async (e) => {
  e.preventDefault(); $('#lockErr').textContent = 'Unlocking…'; $('#lockForm button').disabled = true;
  const ok = await db.unlock($('#lockInput').value);
  $('#lockForm button').disabled = false;
  if (!ok) { $('#lockErr').textContent = 'Wrong passcode'; $('#lockInput').select(); return; }
  $('#lockErr').textContent = ''; $('#lockInput').value = ''; await startApp();
};
$('#lockForget').onclick = async () => { if (await confirmDialog('Reset this device?', 'All data on this device will be erased. Your account is kept: log back in with your username + PIN (or recovery key) and your chats come back from your encrypted backup.', 'Erase & reset', true)) wipeAndReload(); };

// live service status on the home screen
async function loadServiceStatus() {
  if (window.__QCHAT_PREVIEW) { $$('.status-link').forEach((x) => x.classList.add('hidden')); return; }
  try {
    const st = await (await fetch('/api/status', { cache: 'no-store' })).json();
    const txt = { operational: 'All systems operational', degraded: 'Some services degraded', major_outage: 'Service outage' }[st.overall] || 'Service status';
    for (const [d, t] of [['#svcDot', '#svcText'], ['#svcDotOb', '#svcTextOb']]) { $(d).className = 'sdot ' + st.overall; $(t).textContent = txt; }
  } catch { for (const t of ['#svcText', '#svcTextOb']) $(t).textContent = 'Service status unavailable'; for (const d of ['#svcDot', '#svcDotOb']) $(d).className = 'sdot major_outage'; }
}
loadServiceStatus(); setInterval(loadServiceStatus, 60000);
try { navigator.serviceWorker?.addEventListener('message', (e) => { if (e.data?.op === 'open' && e.data.from && A.chats['dm:' + e.data.from]) openChat('dm:' + e.data.from); }); } catch {}
window.addEventListener('beforeunload', () => { flushPersist(); });

(async () => {
  if (!globalThis.crypto?.subtle) { document.body.innerHTML = '<p style="padding:30px">QChat needs a modern browser served over HTTPS (or localhost).</p>'; return; }
  if (!window.__QCHAT_PREVIEW) try { navigator.serviceWorker?.register('/sw.js').catch((e) => console.warn('sw', e)); } catch {}
  await db.openDb();
  const state = await db.keyState();
  if (state === 'locked') { show('#lockScreen'); setTimeout(() => $('#lockInput').focus(), 50); return; }
  if (state === 'new') return show('#onboard');
  if (state === 'signedout') return showSignedOut(await db.signedOutUser());
  await startApp();
})();
// Diagnostics (used by the automated tests; harmless in production)
window.__qchat = { liveStats: live.liveStats, frameStats: calls.frameStats, callInfo: calls.callInfo, sessions: () => Object.keys(K.sessions).length,
  groupKeys: () => ({ sending: Object.fromEntries(Object.entries(K.gsk).map(([g, st]) => [g, { kid: st.kid, n: st.n }])), receiving: Object.keys(K.gskr).length }) };
