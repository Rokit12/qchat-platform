// Client core: identity, server connection, prekeys, ratchet sessions, encrypted send/receive.
import * as C from '../shared/crypto.js';
import { newSession, needsBundle } from '../shared/ratchet.js';
import { seal, open } from '../shared/envelope.js';
import * as db from './store.js';
import { mutex, deviceName } from './util.js';

const OTPK_TARGET = 60, OTPK_LOW = 20, SPK_ROTATE = 7 * 864e5, SPK_KEEP = 30 * 864e5, CONTACT_STALE = 10 * 60e3;

export const S = {
  id: null,           // { user, aikSeed, backupSeed, dev: {device, sigPk, sigSk, name} }
  keys: null,         // { aikPk, aikSk, backupKey }
  pk: null,           // prekey secrets { spk:{cur, old:[]}, otpks:{id:sk}, nextOtpk }
  me: null, ice: null, vapid: null, pushOn: false,
  contacts: {},       // username -> { aik, listVersion, devices:{id:{sigPk,name,created}}, displayName, about, avatar, verified, fetched }
  sessions: {},       // "user:device" -> ratchet session
  outbox: {}, seen: new Set(),
};
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
      for (const [id, o] of Object.entries(S.outbox)) wsSend({ t: 'send', id, to: o.to, env: o.env, push: o.push });
      await refreshUser(ME());
      hooks.onReady(m);
      return;
    }
    case 'prekeys_low': return maintainPrekeys(0);
    case 'prekey_status': return;
    case 'env': return onEnv(m);
    case 'sent':
      if (m.ok && S.outbox[m.id]) { delete S.outbox[m.id]; db.set('outbox', S.outbox); }
      return hooks.onServer(m);
    case 'devices_changed':
      if (S.contacts[m.username]) S.contacts[m.username].fetched = 0;
      if (m.username === ME()) await refreshUser(ME());
      return hooks.onServer(m);
    case 'profile_update': applyUser(m.user); return hooks.onServer(m);
    case 'profile_ok': S.me = { ...S.me, ...m.me }; return hooks.onServer(m);
    case 'kicked': stopped = true; return hooks.onServer(m);
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
    const targets = [];
    for (const u of list) {
      const c = await contactFor(u); if (!c?.devices) continue;
      for (const [d, info] of Object.entries(c.devices)) {
        if (u === ME() && d === DEV()) continue;
        if (opts.devices && !opts.devices.some((x) => x.u === u && x.d === d)) continue;
        targets.push({ user: u, device: d, sigPk: info.sigPk });
      }
    }
    if (!targets.length) return false;
    const need = targets.filter((t) => needsBundle(S.sessions[sk(t.user, t.device)]));
    const bundles = {};
    for (const u of new Set(need.map((t) => t.user))) {
      const r = await rpc({ t: 'bundle', username: u, devices: need.filter((t) => t.user === u).map((t) => t.device) }, 'bundle');
      for (const b of r?.bundles || []) bundles[sk(u, b.device)] = b;
    }
    const recips = [];
    for (const t of targets) {
      const k = sk(t.user, t.device);
      let bundle;
      if (needsBundle(S.sessions[k])) {
        const b = bundles[k];
        if (!b || !C.verifyPrekey(b.spk, t.user, t.device, 'spk', t.sigPk) || (b.otpk && !C.verifyPrekey(b.otpk, t.user, t.device, 'otpk', t.sigPk))) { console.warn('no valid prekey bundle for', k); continue; }
        bundle = { sigPk: t.sigPk, spk: b.spk, otpk: b.otpk || undefined };
      }
      S.sessions[k] ||= newSession(t.user, t.device);
      recips.push({ user: t.user, device: t.device, session: S.sessions[k], bundle });
    }
    if (!recips.length) return false;
    const env = await seal({ user: ME(), device: DEV(), sigSk: C.unb64(S.id.dev.sigSk) }, id, recips, payload);
    for (const r of recips) await db.set('sess:' + sk(r.user, r.device), r.session); // persist ratchet state before anything leaves
    const to = recips.map((r) => ({ u: r.user, d: r.device }));
    if (!opts.ephemeral) { S.outbox[id] = { to, env, push: opts.push }; await db.set('outbox', S.outbox); }
    wsSend({ t: 'send', id, to, env, ephemeral: !!opts.ephemeral, push: opts.push });
    return true;
  });
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
  const payload = await lock(() => decrypt(item));
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
