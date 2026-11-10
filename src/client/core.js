// Client core: identity, server connection, prekeys, ratchet sessions, encrypted send/receive.
import * as C from '../shared/crypto.js';
import { newSession, needsBundle } from '../shared/ratchet.js';
import { seal, open } from '../shared/envelope.js';
import { newSenderKey, exportSenderKey, sealGroup, openGroup, storeReceivedKey } from '../shared/senderkey.js';
import * as db from './store.js';
import { mutex, deviceName } from './util.js';
import { pinKeys, sealSeeds, openSeeds } from '../shared/pin.js';

const OTPK_TARGET = 60, OTPK_LOW = 20, SPK_ROTATE = 7 * 864e5, SPK_KEEP = 30 * 864e5, CONTACT_STALE = 10 * 60e3;

export const S = {
  id: null,           // { user, aikSeed, backupSeed, dev: {device, sigPk, sigSk, name} }
  keys: null,         // { aikPk, aikSk, backupKey }
  pk: null,           // prekey secrets { spk:{cur, old:[]}, otpks:{id:sk}, nextOtpk }
  me: null, ice: null, vapid: null, pushOn: false,
  contacts: {},       // username -> { aik, listVersion, devices:{id:{sigPk,name,created}}, displayName, about, avatar, verified, fetched }
  sessions: {},       // "user:device" -> ratchet session
  outbox: {}, seen: new Set(),
  gsk: {},            // group id -> my sending chain {kid, ck, n, hist, floor, dist:{"u:d":1}}
  gskr: {},           // "g|user|device" -> receiving chains {kid: {ck, n, skipped}}
  gpend: {},          // "g|user|device" -> group envelopes waiting for that sender's key
};
export const BATCH = 1000; // recipients per multi-recipient envelope
export const hooks = { onPayload: async () => {}, onDecryptFail: () => {}, onReady: () => {}, onServer: () => {}, onOnboard: () => {}, onKeyChange: () => {} };
export const ME = () => S.id.user;
export const DEV = () => S.id.dev.device;
const lock = mutex();
const sk = (u, d) => `${u}:${d}`;

// ---------------------------------------------------------------- identity
export function loadIdentity(id) {
  S.id = id;
  S.keys = C.accountKeys({ aikSeed: C.unb64(id.aikSeed), backupSeed: C.unb64(id.backupSeed) });
}
export async function loadCrypto() {
  S.pk = await db.get('prekeys');
  for (const k of await db.keys('sess:')) S.sessions[k.slice(5)] = await db.get(k);
  S.contacts = (await db.get('contacts')) || {};
  S.outbox = (await db.get('outbox')) || {};
  S.seen = new Set((await db.get('seen')) || []);
  for (const k of await db.keys('gsk:')) S.gsk[k.slice(4)] = await db.get(k);
  for (const k of await db.keys('gskr:')) S.gskr[k.slice(5)] = await db.get(k);
  S.gpend = (await db.get('gpend')) || {};
}
export function newIdentity(user, seeds) {
  const dev = { ...C.newDevice(), name: deviceName() };
  return { user, aikSeed: C.b64(seeds.aikSeed), backupSeed: C.b64(seeds.backupSeed), dev };
}
export const recoveryKey = () => C.makeRecoveryKey({ aikSeed: C.unb64(S.id.aikSeed), backupSeed: C.unb64(S.id.backupSeed) });

function genOtpks(n) {
  const pubs = [];
  for (let i = 0; i < n; i++) { const id = S.pk.nextOtpk++; const k = C.makePrekey(ME(), DEV(), 'otpk', id, S.id.dev.sigSk); S.pk.otpks[id] = k.sk; pubs.push(k.pub); }
  return pubs;
}
function freshPrekeys() {
  const spk = C.makePrekey(ME(), DEV(), 'spk', 1, S.id.dev.sigSk);
  S.pk = { spk: { cur: { id: 1, sk: spk.sk, pub: spk.pub, created: Date.now() }, old: [] }, otpks: {}, nextOtpk: 1 };
  return { spk: spk.pub, otpks: genOtpks(OTPK_TARGET) };
}
const prekeyAccess = {
  getSpk: (id) => (S.pk.spk.cur.id === id ? S.pk.spk.cur.sk : S.pk.spk.old.find((o) => o.id === id)?.sk || null),
  getOtpk: (id) => S.pk.otpks[id] || null,
};
async function maintainPrekeys(serverCount) {
  const up = {};
  if (serverCount < OTPK_LOW) up.otpks = genOtpks(OTPK_TARGET - serverCount);
  if (Date.now() - S.pk.spk.cur.created > SPK_ROTATE) {
    const id = S.pk.spk.cur.id + 1; const k = C.makePrekey(ME(), DEV(), 'spk', id, S.id.dev.sigSk);
    S.pk.spk.old.push({ id: S.pk.spk.cur.id, sk: S.pk.spk.cur.sk, created: S.pk.spk.cur.created });
    S.pk.spk.cur = { id, sk: k.sk, pub: k.pub, created: Date.now() }; up.spk = k.pub;
  }
  S.pk.spk.old = S.pk.spk.old.filter((o) => Date.now() - o.created < SPK_ROTATE + SPK_KEEP); // forward secrecy for prekeys
  if (up.otpks || up.spk) { await db.set('prekeys', S.pk); wsSend({ t: 'prekeys', ...up }); }
}

// ---------------------------------------------------------------- connection
let ws, ready = false, backoff = 1000, stopped = false, enroll = null; // enroll: {register, profile, resolve, reject}
const rpcs = new Map(); let rid = 0;
export const isReady = () => ready;
export function wsSend(o) { if (ws?.readyState === 1 && (ready || ['hello', 'auth', 'enroll'].includes(o.t))) { ws.send(JSON.stringify(o)); return true; } return false; }
export function rpc(o, t, ms = 10000) {
  return new Promise((res) => {
    const id = ++rid; rpcs.set(id, res);
    if (!wsSend({ ...o, rid: id })) { rpcs.delete(id); return res(undefined); }
    setTimeout(() => { if (rpcs.has(id)) { rpcs.delete(id); res(undefined); } }, ms);
  });
}
export function connect() {
  stopped = false;
  ws = new WebSocket((location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host);
  ws.onopen = () => ws.send(JSON.stringify({ t: 'hello', user: ME(), device: DEV() }));
  ws.onmessage = (e) => { let m; try { m = JSON.parse(e.data); } catch { return; } onServer(m).catch((err) => console.error(err)); };
  ws.onclose = () => {
    ready = false; hooks.onServer({ t: 'disconnected' });
    if (!stopped) { setTimeout(connect, backoff); backoff = Math.min(backoff * 2, 15000); }
  };
}
export function disconnect() { stopped = true; try { ws?.close(); } catch {} }
/** Create an account or add this device to one (recovery key). Resolves when the server accepts. */
export function enrollDevice(opts) { return new Promise((resolve, reject) => { enroll = { ...opts, resolve, reject }; connect(); }); }

async function onServer(m) {
  if (m.rid && rpcs.has(m.rid)) { const r = rpcs.get(m.rid); rpcs.delete(m.rid); return r(m); }
  switch (m.t) {
    case 'challenge': {
      const auth = C.dsaSign(C.AUTH_DOMAIN, { user: ME(), device: DEV(), nonce: m.nonce }, C.unb64(S.id.dev.sigSk));
      if (m.deviceKnown) return ws.send(JSON.stringify({ t: 'auth', sig: auth }));
      if (!enroll) { stopped = true; ws.close(); return hooks.onServer({ t: 'kicked', reason: 'removed' }); }
      if (enroll.register && m.exists) return failEnroll('That username is taken — try another.');
      if (!enroll.register && !m.exists) return failEnroll('No account with that username.');
      const aik = C.b64(S.keys.aikPk);
      let devices = [], version = 1;
      if (m.exists) {
        if (m.aik !== aik) return failEnroll('That recovery key does not belong to @' + ME());
        if (!C.verifyDeviceList(m.deviceList, ME(), aik)) return failEnroll('Server sent an invalid device list');
        devices = m.deviceList.devices; version = m.deviceList.version + 1;
        if (devices.length >= 5) {
          if (!(await enroll.confirmReplace?.(devices))) return failEnroll('You already have 5 devices. Remove one in Settings → Devices.');
          devices = devices.slice(1);
        }
      }
      enroll.onProgress?.('Solving anti-spam puzzle…');
      const pow = await C.solvePow(m.nonce, ME(), DEV(), m.pow);
      const list = C.makeDeviceList(ME(), version, [...devices, DEV()], S.keys.aikSk);
      const cert = C.makeCert(ME(), S.id.dev, S.keys.aikSk, S.id.dev.name);
      const pre = freshPrekeys();
      ws.send(JSON.stringify({ t: 'enroll', pow, register: !!enroll.register, aik, cert, deviceList: list, spk: pre.spk, otpks: pre.otpks, profile: enroll.profile, sig: auth,
        aikSig: C.dsaSign(C.ENROLL_DOMAIN, { user: ME(), device: DEV(), nonce: m.nonce, list: list.version }, S.keys.aikSk) }));
      return;
    }
    case 'auth_error':
      if (enroll) return failEnroll(m.error);
      hooks.onServer({ t: 'auth_error', error: m.error });
      if (m.error === 'device_unknown') { stopped = true; ws.close(); hooks.onServer({ t: 'kicked', reason: 'removed' }); }
      return;
    case 'ready': {
      ready = true; backoff = 1000; S.me = m.me; S.ice = m.ice; S.vapid = m.vapid; S.pushOn = m.pushOn;
      if (enroll) { const e = enroll; enroll = null; await db.set('prekeys', S.pk); e.resolve(m); }
      await maintainPrekeys(m.prekeys.otpks);
      for (const [k, o] of Object.entries(S.outbox)) wsSend({ t: 'send', id: o.id || k, to: o.to, env: o.env, push: o.push });
      await refreshUser(ME());
      hooks.onReady(m);
      return;
    }
    case 'prekeys_low': return maintainPrekeys(0);
    case 'prekey_status': return;
    case 'env': return onEnv(m);
    case 'sent':
      if (m.ok) { const k = Object.keys(S.outbox).find((k) => (S.outbox[k].id || k) === m.id); if (k) { delete S.outbox[k]; db.set('outbox', S.outbox); } }
      return hooks.onServer(m);
    case 'devices_changed':
      if (S.contacts[m.username]) S.contacts[m.username].fetched = 0;
      if (m.username === ME()) await refreshUser(ME());
      return hooks.onServer(m);
    case 'profile_update': applyUser(m.user); return hooks.onServer(m);
    case 'profile_ok': S.me = { ...S.me, ...m.me }; return hooks.onServer(m);
    case 'kicked': stopped = true; return hooks.onServer(m);
    case 'pin_ok': pinAck(m); if (S.me) S.me.pinSet = m.enabled; return hooks.onServer(m);
    default: return hooks.onServer(m);
  }
}
function failEnroll(msg) { const e = enroll; enroll = null; stopped = true; try { ws.close(); } catch {} e?.reject(new Error(msg)); }

// ---------------------------------------------------------------- contacts (verified)
let saveContactsT;
function saveContacts() { clearTimeout(saveContactsT); saveContactsT = setTimeout(() => db.set('contacts', S.contacts), 200); }
export async function lookup(u) { const r = await rpc({ t: 'lookup', username: u }, 'lookup'); return r ? r.user : undefined; }
export async function refreshUser(u) {
  const p = await lookup(u);
  if (p) applyUser(p);
  return p === undefined ? S.contacts[u] : p ? S.contacts[u] : null;
}
export function applyUser(p) {
  if (!p) return;
  const u = p.username; const old = S.contacts[u];
  if (u === ME() && p.aik !== C.b64(S.keys.aikPk)) { console.error('Server returned a different identity key for our own account'); return; }
  let aikChanged = false;
  if (old?.aik && old.aik !== p.aik) aikChanged = true;
  if (!C.verifyDeviceList(p.deviceList, u, p.aik)) { console.warn('invalid device list for', u); return; }
  if (old && !aikChanged && p.deviceList.version < (old.listVersion || 0)) { console.warn('device list rollback refused for', u); return; }
  const devices = {};
  for (const d of p.devices || []) if (p.deviceList.devices.includes(d.device) && C.verifyCert(d.cert, u, p.aik)) devices[d.device] = { sigPk: d.cert.sigPk, name: d.cert.name || '', created: d.cert.created };
  S.contacts[u] = { ...(old || {}), username: u, aik: p.aik, listVersion: p.deviceList.version, devices, displayName: p.displayName, about: p.about, avatar: p.avatar, fetched: Date.now(), verified: aikChanged ? false : !!old?.verified, keyChanged: aikChanged ? true : !!old?.keyChanged };
  if (p.online !== undefined) hooks.onServer({ t: 'presence', username: u, online: p.online, lastSeen: p.lastSeen });
  if (aikChanged) hooks.onKeyChange(u);
  saveContacts();
}
const noSuchUser = new Map();
/** Bulk-load contacts we don't know yet (or that are stale) — 500 per request, used for big groups. */
export async function prefetch(users, { stale = false } = {}) {
  const now = Date.now();
  const need = [...new Set(users)].filter((u) => { const c = S.contacts[u]; return (!c?.devices && !(noSuchUser.get(u) > now)) || (stale && c && now - (c.fetched || 0) > CONTACT_STALE); });
  for (let i = 0; i < need.length; i += 500) {
    const part = need.slice(i, i + 500);
    const r = await rpc({ t: 'lookup', usernames: part }, 'lookup', 20000);
    if (!r?.users) break;
    for (const p of r.users) applyUser(p);
    const got = new Set(r.users.map((p) => p.username)); for (const u of part) if (!got.has(u)) noSuchUser.set(u, now + CONTACT_STALE);
  }
}
async function contactFor(u, fresh = false) {
  const c = S.contacts[u];
  if (!fresh && c?.devices && Date.now() - (c.fetched || 0) < CONTACT_STALE) return c;
  return (await refreshUser(u)) || c;
}

// ---------------------------------------------------------------- sending
/**
 * Encrypt `payload` for every device of `users` (+ this account's other devices) and send.
 * opts: { id, ephemeral, devices: [{u,d}] restrict, push: 'msg'|'call', self: include own devices (default true) }
 */
export function sendPayload(users, payload, opts = {}) {
  return lock(async () => {
    const id = opts.id || C.randId(12);
    const list = new Set(users); if (opts.self !== false) list.add(ME());
    if (list.size > 8) await prefetch([...list]);
    const only = opts.devices ? new Set(opts.devices.map((x) => sk(x.u, x.d))) : null;
    const targets = [];
    for (const u of list) {
      const c = list.size > 8 ? S.contacts[u] : await contactFor(u); if (!c?.devices) continue;
      for (const [d, info] of Object.entries(c.devices)) {
        if (u === ME() && d === DEV()) continue;
        if (only && !only.has(sk(u, d))) continue;
        targets.push({ user: u, device: d, sigPk: info.sigPk });
      }
    }
    if (!targets.length) return false;
    const need = targets.filter((t) => needsBundle(S.sessions[sk(t.user, t.device)]));
    const bundles = {};
    const needUsers = [...new Set(need.map((t) => t.user))];
    const devsOf = (u) => need.filter((t) => t.user === u).map((t) => t.device);
    if (needUsers.length === 1) {
      const r = await rpc({ t: 'bundle', username: needUsers[0], devices: devsOf(needUsers[0]) }, 'bundle');
      for (const b of r?.bundles || []) bundles[sk(needUsers[0], b.device)] = b;
    } else {
      for (let i = 0; i < needUsers.length; i += 200) { // bulk form for big groups
        const r = await rpc({ t: 'bundle', users: needUsers.slice(i, i + 200).map((u) => ({ username: u, devices: devsOf(u) })) }, 'bundle', 20000);
        for (const b of r?.bundles || []) bundles[sk(b.username, b.device)] = b;
        if (!r || r.error) break;
      }
    }
    const recips = [];
    for (const t of targets) {
      const k = sk(t.user, t.device);
      let bundle;
      if (needsBundle(S.sessions[k])) {
        const b = bundles[k];
        if (!b || !C.verifyPrekey(b.spk, t.user, t.device, 'spk', t.sigPk) || (b.otpk && !C.verifyPrekey(b.otpk, t.user, t.device, 'otpk', t.sigPk))) { if (needUsers.length < 30) console.warn('no valid prekey bundle for', k); continue; }
        bundle = { sigPk: t.sigPk, spk: b.spk, otpk: b.otpk || undefined };
      }
      S.sessions[k] ||= newSession(t.user, t.device);
      recips.push({ user: t.user, device: t.device, session: S.sessions[k], bundle });
    }
    if (!recips.length) return false;
    const me = { user: ME(), device: DEV(), sigSk: C.unb64(S.id.dev.sigSk) };
    const sent = [];
    for (let i = 0; i < recips.length; i += BATCH) { // ≤1,000 devices per envelope (a 3,500-member group is a few envelopes)
      const part = recips.slice(i, i + BATCH);
      const env = await seal(me, id, part, payload);
      for (const r of part) await db.set('sess:' + sk(r.user, r.device), r.session); // persist ratchet state before anything leaves
      const to = part.map((r) => ({ u: r.user, d: r.device }));
      const key = i ? id + '#' + i : id;
      if (!opts.ephemeral) { S.outbox[key] = { id, to, env, push: opts.push }; await db.set('outbox', S.outbox); }
      wsSend({ t: 'send', id, to, env, ephemeral: !!opts.ephemeral, push: opts.push });
      sent.push(...to);
    }
    return sent;
  });
}

// ---------------------------------------------------------------- big groups: sender keys
// Each device has one symmetric chain per group (see shared/senderkey.js). The chain key is handed to every member
// device over the post-quantum pairwise sessions; after that every message is encrypted ONCE (constant size) and the
// server fans it out to all members. Members missing a key ask the sender for it ("skey_req").
const saveGsk = (g) => (S.gsk[g] ? db.set('gsk:' + g, S.gsk[g]) : db.del('gsk:' + g));
/** Someone left / was removed (or a device was unlinked): start a new chain so they can't read what comes next. */
export function groupRotate(g) { return lock(async () => { if (S.gsk[g]) { delete S.gsk[g]; await saveGsk(g); } }); }
/** New members: they get the chain from now on — never older messages. */
export function groupMembersAdded(g) { return lock(async () => { const st = S.gsk[g]; if (st) { st.floor = st.n; await saveGsk(g); } }); }

async function distributeKey(g, members) {
  const users = [...new Set([...members, ME()])];
  const st = await lock(async () => {
    let st = S.gsk[g];
    // a member's device disappeared from their (signed) device list → that device must not keep reading
    if (st && Object.keys(st.dist || {}).some((k) => { const [u, d] = k.split(':'); return !users.includes(u) || (S.contacts[u]?.devices && !S.contacts[u].devices[d]); })) st = null;
    if (!st) { st = { ...newSenderKey(), dist: {}, floor: 0 }; S.gsk[g] = st; await saveGsk(g); }
    return st;
  });
  await prefetch(users);
  const devices = [];
  const now = Date.now(); st.miss ||= {};
  for (const u of users) for (const d of Object.keys(S.contacts[u]?.devices || {})) { const k = sk(u, d); if (!(u === ME() && d === DEV()) && !st.dist[k] && !(st.miss[k] > now)) devices.push({ u, d }); }
  if (!devices.length) return st;
  const k = exportSenderKey(st);
  const sent = await sendPayload([...new Set(devices.map((x) => x.u))], { type: 'skey', g, kid: k.kid, ck: k.ck, n: k.n }, { devices, self: true }) || [];
  await lock(async () => {
    if (S.gsk[g] !== st) return;
    for (const x of sent) st.dist[sk(x.u, x.d)] = 1;
    for (const x of devices) if (!st.dist[sk(x.u, x.d)]) st.miss[sk(x.u, x.d)] = now + 10 * 60e3; // unreachable for now: they'll ask (skey_req)
    await saveGsk(g);
  });
  return st; // devices we couldn't reach yet will ask for the key themselves
}
/** Send one payload to a group: one ciphertext, fanned out by the server to every member's devices. */
export async function groupSend(g, members, payload, opts = {}) {
  const id = opts.id || C.randId(12);
  for (let tries = 0; tries < 2; tries++) {
    const st = await distributeKey(g, members);
    const ok = await lock(async () => {
      if (S.gsk[g] !== st) return null; // rotated meanwhile → redistribute
      const env = await sealGroup({ user: ME(), device: DEV(), sigSk: C.unb64(S.id.dev.sigSk) }, id, g, st, payload);
      await saveGsk(g); // persist the advanced chain before the message leaves
      const to = [...new Set([...members, ME()])].map((u) => ({ u }));
      if (!opts.ephemeral) { S.outbox[id] = { id, to, env, push: opts.push }; await db.set('outbox', S.outbox); }
      wsSend({ t: 'send', id, to, env, ephemeral: !!opts.ephemeral, push: opts.push });
      return true;
    });
    if (ok) return true;
  }
  return false;
}

const skReq = {}; let skReqT; const skAsked = {};
function onSkeyReq(from, fd, p) {
  if (typeof p.g !== 'string' || !S.gsk[p.g] || !hooks.isGroupMember?.(p.g, from)) return;
  const k = p.g + '|' + sk(from, fd) + '|' + S.gsk[p.g].kid;
  if (Date.now() - (skAsked[k] || 0) < 30000) return; skAsked[k] = Date.now();
  const want = p.kid === S.gsk[p.g].kid && Number.isInteger(p.n) ? p.n : null;
  (skReq[p.g] ||= []).push({ u: from, d: fd, n: want });
  clearTimeout(skReqT); skReqT = setTimeout(flushSkeyReqs, 800); // answer requests in batches (≤1,000 devices per envelope)
}
async function flushSkeyReqs() {
  for (const [g, reqs] of Object.entries(skReq)) {
    delete skReq[g];
    const st = S.gsk[g]; if (!st) continue;
    const ns = reqs.map((r) => r.n).filter((n) => n != null);
    const from = Math.max(st.floor || 0, ns.length ? Math.min(...ns) : st.n); // never older than when they could have joined
    const k = exportSenderKey(st, from);
    const devices = reqs.map(({ u, d }) => ({ u, d }));
    const sent = await sendPayload([...new Set(devices.map((x) => x.u))], { type: 'skey', g, kid: k.kid, ck: k.ck, n: k.n }, { devices, self: false });
    if (sent) await lock(async () => { if (S.gsk[g] === st) { for (const x of sent) st.dist[sk(x.u, x.d)] = 1; await saveGsk(g); } });
  }
}
async function onSkey(from, fd, p) {
  if (typeof p.g !== 'string' || p.g.length > 64 || typeof p.kid !== 'string' || typeof p.ck !== 'string' || C.unb64(p.ck).length !== 32 || !Number.isInteger(p.n) || p.n < 0) return;
  const key = p.g + '|' + from + '|' + fd; // a chain is only ever accepted from the device that owns it
  await lock(async () => { S.gskr[key] = storeReceivedKey(S.gskr[key], { kid: p.kid, ck: p.ck, n: p.n }); await db.set('gskr:' + key, S.gskr[key]); });
  const waiting = S.gpend[key]; if (waiting) { delete S.gpend[key]; db.set('gpend', S.gpend); for (const it of waiting) onEnv(it); }
}
async function decryptGroup(item, retried = false) {
  const env = item.env;
  if (env.from !== item.from || env.fd !== item.fd || env.id !== item.id) return null;
  let c = S.contacts[item.from];
  if (!c?.devices?.[item.fd] || retried) c = await contactFor(item.from, true);
  const dev = c?.devices?.[item.fd]; if (!dev) return null;
  const key = env.g + '|' + item.from + '|' + item.fd;
  try {
    const r = await openGroup(env, dev.sigPk, S.gskr[key]);
    S.gskr[key] = r.rs; await db.set('gskr:' + key, r.rs);
    if (r.payload.g !== env.g) return null; // the payload must belong to the group the envelope claims
    return r.payload;
  } catch (e) {
    if (e.message === 'bad signature' && !retried) return decryptGroup(item, true);
    if (e.message === 'no sender key') {
      const q = (S.gpend[key] ||= []); if (q.length < 300) q.push(item); db.set('gpend', S.gpend);
      const ak = key + '|' + env.kid;
      if (Date.now() - (skAsked[ak] || 0) > 30000) {
        skAsked[ak] = Date.now();
        setTimeout(() => sendPayload([item.from], { type: 'skey_req', g: env.g, kid: env.kid, n: env.n }, { devices: [{ u: item.from, d: item.fd }], self: false }), 0);
      }
    } else if (!/duplicate|replayed/.test(e.message)) console.warn('group decrypt failed', e.message);
    return null;
  }
}
export function resetSendSession(u, d) {
  return lock(async () => { const s = S.sessions[sk(u, d)]; if (!s) return; s.send = null; s.theirR = null; await db.set('sess:' + sk(u, d), s); });
}

// ---------------------------------------------------------------- receiving
let chain = Promise.resolve(); const ackBuf = new Set(); let ackT, seenT;
function ack(id) { ackBuf.add(id); clearTimeout(ackT); ackT = setTimeout(() => { wsSend({ t: 'ack', ids: [...ackBuf] }); ackBuf.clear(); }, 150); }
function onEnv(item) { chain = chain.then(() => processEnv(item)).catch((e) => console.error(e)); }
async function processEnv(item) {
  if (S.seen.has(item.id)) return ack(item.id);
  if (hooks.isBlocked?.(item.from)) return ack(item.id);
  const payload = await lock(() => (item.env?.v === 3 ? decryptGroup(item) : decrypt(item)));
  if (payload?.type === 'skey') { S.seen.add(item.id); if (item.env?.v !== 3) await onSkey(item.from, item.fd, payload); return ack(item.id); }
  if (payload?.type === 'skey_req') { S.seen.add(item.id); if (item.env?.v !== 3) onSkeyReq(item.from, item.fd, payload); return ack(item.id); }
  if (payload) {
    S.seen.add(item.id); clearTimeout(seenT); seenT = setTimeout(() => db.set('seen', [...S.seen].slice(-5000)), 500);
    try { await hooks.onPayload(item.from, item.fd, item.ts, item.id, payload); } catch (e) { console.error('handler', e); }
  }
  ack(item.id);
}
async function decrypt(item, retried = false) {
  const env = item.env;
  if (!env || env.from !== item.from || env.fd !== item.fd || env.id !== item.id) return null;
  const c = await contactFor(item.from, retried);
  const dev = c?.devices?.[item.fd];
  if (!dev) { if (!retried) return decrypt(item, true); console.warn('unknown device', item.from, item.fd); return null; }
  const k = sk(item.from, item.fd);
  try {
    const r = await open({ user: ME(), device: DEV() }, env, dev.sigPk, S.sessions[k], prekeyAccess);
    S.sessions[k] = r.session; await db.set('sess:' + k, r.session);
    if (r.usedOtpk != null) { delete S.pk.otpks[r.usedOtpk]; await db.set('prekeys', S.pk); }
    return r.payload;
  } catch (e) {
    if (e.message === 'bad signature' && !retried) return decrypt(item, true);
    if (e.message !== 'not a recipient' && !/duplicate/.test(e.message)) setTimeout(() => hooks.onDecryptFail(item, e), 0);
    return null;
  }
}

// ---------------------------------------------------------------- devices
export function myDevices() { return Object.entries(S.contacts[ME()]?.devices || {}).map(([device, d]) => ({ device, ...d, current: device === DEV() })); }
export async function removeDevice(device) {
  const me = await refreshUser(ME());
  const list = C.makeDeviceList(ME(), me.listVersion + 1, Object.keys(me.devices).filter((d) => d !== device), S.keys.aikSk);
  wsSend({ t: 'devices_update', deviceList: list });
}

// ---------------------------------------------------------------- PIN login
/** Store the account seeds on the server, encrypted with the PIN + a server-held share. */
export async function setPin(pin) {
  const salt = C.rand(16); const { auth, enc } = await pinKeys(pin, salt); const share = C.rand(32);
  const seeds = C.concat(C.unb64(S.id.aikSeed), C.unb64(S.id.backupSeed));
  const blob = await sealSeeds(seeds, enc, share, ME());
  const res = new Promise((r) => (pinWaiter = r));
  wsSend({ t: 'pin_set', salt: C.b64(salt), auth: C.b64(auth), share: C.b64(share), blob });
  return Promise.race([res, new Promise((r) => setTimeout(() => r(null), 15000))]);
}
export function clearPin() { const res = new Promise((r) => (pinWaiter = r)); wsSend({ t: 'pin_clear' }); return res; }
let pinWaiter = null;
export function pinAck(m) { if (pinWaiter) { const w = pinWaiter; pinWaiter = null; w(m); } }

/**
 * Recover account seeds on a new device with username + PIN (no recovery key).
 * Uses a short-lived connection; on success returns {aikSeed, backupSeed}. Throws Error with
 * .info = {attemptsLeft, lockedFor, wiped} on failure.
 */
export async function pinRecover(user, pin, onStep = () => {}) {
  const ws = new WebSocket((location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host);
  const inbox = []; let waiter = null;
  ws.onmessage = (e) => { const m = JSON.parse(e.data); if (waiter && waiter.pred(m)) { const w = waiter; waiter = null; w.res(m); } else inbox.push(m); };
  const next = (pred, ms = 20000) => new Promise((res, rej) => {
    const i = inbox.findIndex(pred); if (i >= 0) return res(inbox.splice(i, 1)[0]);
    waiter = { pred, res }; setTimeout(() => rej(new Error('Server did not respond — check your connection')), ms);
  });
  const err = (msg, info = {}) => Object.assign(new Error(msg), { info });
  try {
    await new Promise((res, rej) => { ws.onopen = res; ws.onerror = () => rej(new Error('Cannot reach the server')); });
    ws.send(JSON.stringify({ t: 'pin_params', user, rid: 1 }));
    const params = await next((m) => m.t === 'pin_params');
    if (!params.enabled) throw err(params.error === 'rate_limited' ? 'Too many tries — wait a few minutes' : 'PIN login isn’t set up for this account (or was disabled after too many wrong PINs). Use your recovery key.');
    if (params.lockedFor > 0) throw err(`Too many wrong PINs. Try again in ${Math.ceil(params.lockedFor / 60000)} min.`, params);
    onStep('Checking your PIN…');
    const salt = C.unb64(params.salt); const { auth, enc } = await pinKeys(pin, salt);
    const tmpDev = C.randId(8);
    ws.send(JSON.stringify({ t: 'hello', user, device: tmpDev }));
    const ch = await next((m) => m.t === 'challenge' || m.t === 'auth_error');
    if (ch.t === 'auth_error') throw err(ch.error);
    onStep('Solving anti-abuse puzzle…');
    const pow = await C.solvePow(ch.nonce, user, tmpDev, ch.pow);
    ws.send(JSON.stringify({ t: 'pin_unlock', auth: C.b64(auth), pow }));
    const r = await next((m) => m.t === 'pin_result');
    if (!r.ok) {
      if (r.error === 'wiped') throw err('Too many wrong PINs — PIN login has been disabled for this account. Use your recovery key.', { wiped: true });
      if (r.error === 'wrong') throw err(`Wrong PIN. ${r.attemptsLeft} attempt${r.attemptsLeft === 1 ? '' : 's'} left before PIN login is disabled${r.lockedFor ? `; try again in ${Math.ceil(r.lockedFor / 60000)} min` : ''}.`, r);
      if (r.error === 'locked') throw err(`Too many wrong PINs. Try again in ${Math.ceil(r.lockedFor / 60000)} min.`, r);
      throw err(r.error, r);
    }
    const seeds = await openSeeds(r.blob, enc, C.unb64(r.share), user);
    return { aikSeed: seeds.slice(0, 32), backupSeed: seeds.slice(32, 96) };
  } finally { try { ws.close(); } catch {} }
}
