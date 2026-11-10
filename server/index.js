// QChat server v2 — a relay that never sees message contents.
// Multi-device accounts, signed device lists, PQ prekeys, offline queue, Web Push, horizontal scaling.
import './env.js';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { WebSocketServer } from 'ws';
import * as webpush from 'web-push';
import { openStore } from './store.js';
import { openBus } from './bus.js';
import { dsaVerify, verifyCert, verifyDeviceList, verifyPrekey, unb64, AUTH_DOMAIN, ENROLL_DOMAIN } from '../src/shared/crypto.js';
import { createSecurity, clientIp, timingSafeEqual, LIMITS } from './security.js';
import { openAdminStore, day } from './admin-store.js';
import { createAdmin } from './admin.js';
import { createMonitor } from './monitor.js';
import { isReservedUsername, cleanText, looksLikeImpersonation } from '../src/shared/policy.js';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const PUBLIC = path.join(ROOT, 'public');
const PORT = Number(process.env.PORT || 3000);
const MAX_PAYLOAD = 24 * 1024 * 1024;
const PREAUTH_MAX = 600 * 1024;        // max frame size before a socket has authenticated
const AUTH_TIMEOUT = Number(process.env.AUTH_TIMEOUT_MS || 20000); // unauthenticated sockets are closed after 20 s
const MAX_QUEUE_PER_DEVICE = 5000;
const INSTANCE_ID = crypto.randomBytes(6).toString('hex');
const QUEUE_TTL = 30 * 864e5;
const MAX_DEVICES = 5;
const USERNAME_RE = /^[a-z0-9_.]{3,24}$/;
const DEVICE_RE = /^[0-9a-f]{16}$/;
const DSA_PK = 1952, KEM_PK = 1184;

const store = await openStore({ databaseUrl: process.env.DATABASE_URL, dataDir: process.env.DATA_DIR || path.join(ROOT, 'data') });
// Independent admin/analytics database: separate file (SQLite) or separate server & credentials (ADMIN_DATABASE_URL)
const adminStore = await openAdminStore({ adminDatabaseUrl: process.env.ADMIN_DATABASE_URL, dataDir: process.env.DATA_DIR || path.join(ROOT, 'data') });
const bus = openBus(process.env.REDIS_URL);

// ---------- PIN login secrets ----------
// PIN_PEPPER never lives in the database: a stolen DB can't be used to brute-force PINs offline.
let pinPepper = process.env.PIN_PEPPER ? Buffer.from(process.env.PIN_PEPPER, 'utf8') : null;
if (!pinPepper) {
  pinPepper = Buffer.from(await store.initMeta('pin_pepper', crypto.randomBytes(32).toString('base64')), 'base64');
  console.warn('⚠️  PIN_PEPPER is not set — using a key stored in the database. Set PIN_PEPPER (openssl rand -base64 32) in production.');
}
const pinVerifier = (auth) => crypto.createHmac('sha256', pinPepper).update('qchat-pin-verifier|' + auth).digest('base64');
const shareKey = Buffer.from(crypto.hkdfSync('sha256', pinPepper, 'qchat', 'qchat-pin-share-v1', 32));
function encShare(shareB64, user) {
  const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', shareKey, iv); c.setAAD(Buffer.from(user));
  return Buffer.concat([iv, c.update(Buffer.from(shareB64, 'base64')), c.final(), c.getAuthTag()]).toString('base64');
}
function decShare(enc, user) {
  const b = Buffer.from(enc, 'base64'), d = crypto.createDecipheriv('aes-256-gcm', shareKey, b.subarray(0, 12)); d.setAAD(Buffer.from(user)); d.setAuthTag(b.subarray(b.length - 16));
  return Buffer.concat([d.update(b.subarray(12, b.length - 16)), d.final()]).toString('base64');
}

// ---------- Web Push (VAPID) ----------
let vapid = process.env.VAPID_PUBLIC_KEY ? { publicKey: process.env.VAPID_PUBLIC_KEY, privateKey: process.env.VAPID_PRIVATE_KEY } : await store.getMeta('vapid');
if (!vapid) vapid = await store.initMeta('vapid', webpush.generateVAPIDKeys());
// Push services want a contact for the sender: use the site URL (no email address is ever sent to them).
webpush.setVapidDetails(process.env.VAPID_SUBJECT || (process.env.DOMAIN ? `https://${process.env.DOMAIN}` : 'https://qchat.example'), vapid.publicKey, vapid.privateKey);

function iceServers(user) {
  const ice = [{ urls: (process.env.STUN_URLS || 'stun:stun.l.google.com:19302,stun:stun1.l.google.com:19302').split(',') }];
  if (process.env.TURN_URL) {
    if (process.env.TURN_SECRET) { // coturn "use-auth-secret": short-lived credentials, never shipped in the page
      const username = `${Math.floor(Date.now() / 1000) + 86400}:${user}`;
      const credential = crypto.createHmac('sha1', process.env.TURN_SECRET).update(username).digest('base64');
      ice.push({ urls: process.env.TURN_URL.split(','), username, credential });
    } else ice.push({ urls: process.env.TURN_URL.split(','), username: process.env.TURN_USER, credential: process.env.TURN_PASS });
  }
  return ice;
}

// ---------- static files & admin API ----------
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.json': 'application/json', '.webmanifest': 'application/manifest+json' };
const CSP = "default-src 'self'; img-src 'self' data: blob:; media-src 'self' data: blob:; connect-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; worker-src 'self' blob:; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; upgrade-insecure-requests";
const isHttps = (req) => req.socket.encrypted || (process.env.TRUST_PROXY === '1' && String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https');
function baseHeaders(req) {
  const h = { 'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer', 'x-frame-options': 'DENY', 'cross-origin-opener-policy': 'same-origin', 'cross-origin-resource-policy': 'same-origin', 'origin-agent-cluster': '?1', 'x-dns-prefetch-control': 'off', 'x-permitted-cross-domain-policies': 'none' };
  if (isHttps(req)) h['strict-transport-security'] = 'max-age=63072000; includeSubDomains; preload';
  return h;
}
function deny(res, req, code, msg) { res.writeHead(code, { ...baseHeaders(req), 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' }); res.end(msg || ''); }
async function readJson(req, max = 4096) { let b = ''; for await (const c of req) { b += c; if (b.length > max) throw new Error('too large'); } return b ? JSON.parse(b) : {}; }

const server = http.createServer(async (req, res) => {
  const ip = clientIp(req);
  try {
    if (await sec.isBanned(ip)) return deny(res, req, 403, 'Blocked for suspicious activity. Try again later.');
    if (!(await sec.allow('http:' + ip, LIMITS.httpRatePerIp, 60))) { await sec.strike(ip, 2, 'http_flood'); return deny(res, req, 429, 'Too many requests'); }
    if (process.env.TRUST_PROXY === '1' && process.env.FORCE_HTTPS !== '0' && req.headers['x-forwarded-proto'] === 'http') { res.writeHead(301, { location: 'https://' + req.headers.host + req.url }); return res.end(); }
    if (!['GET', 'HEAD', 'POST'].includes(req.method)) return deny(res, req, 405);
    const url = new URL(req.url, 'http://x');
    let raw; try { raw = decodeURIComponent(url.pathname); } catch { await sec.strike(ip, 5, 'bad_url'); return deny(res, req, 400); }
    if (raw.includes('\0') || raw.includes('..') || sec.isScannerPath(raw)) {
      await sec.event('scanner_probe', 'medium', { ip, detail: { path: raw.slice(0, 120), ua: String(req.headers['user-agent'] || '').slice(0, 120) } });
      await sec.strike(ip, 15, 'scanner'); return deny(res, req, 404, 'not found');
    }
    if (url.pathname === '/health') { res.writeHead(200, { ...baseHeaders(req), 'content-type': 'application/json' }); return res.end(JSON.stringify({ ok: true, store: store.kind, bus: bus.kind })); }
    if (url.pathname.startsWith('/admin')) return await adminApi.handle(req, res, url, ip);
    if (url.pathname === '/api/status') { // public service status (no internals)
      if (!(await sec.allow('status:' + ip, 60, 60))) return deny(res, req, 429);
      res.writeHead(200, { ...baseHeaders(req), 'content-type': 'application/json', 'cache-control': 'no-store' }); return res.end(JSON.stringify(await monitor.publicStatus()));
    }
    if (url.pathname === '/status') raw = '/status.html';
    if (req.method !== 'GET' && req.method !== 'HEAD') return deny(res, req, 405);
    let p = path.normalize(raw).replace(/^([/\\])+/, '') || 'index.html';
    if (/^@[a-z0-9_.]{3,24}$/i.test(p)) p = 'index.html'; // invite links: https://host/@username
    const file = path.join(PUBLIC, p);
    if (!file.startsWith(PUBLIC + path.sep) || path.basename(file).startsWith('.') || !MIME[path.extname(file)] || p.startsWith('admin')) return deny(res, req, 404, 'not found');
    fs.readFile(file, async (err, data) => {
      if (err) { if ((await sec.hit('404:' + ip, 60)) > 60) await sec.strike(ip, 5, 'path_scanning'); return deny(res, req, 404, 'not found'); }
      const h = { ...baseHeaders(req), 'content-type': MIME[path.extname(file)], 'content-security-policy': CSP, 'permissions-policy': 'camera=(self), microphone=(self), display-capture=(), geolocation=(), payment=(), usb=(), interest-cohort=()' };
      if (p === 'sw.js') { h['cache-control'] = 'no-cache'; h['service-worker-allowed'] = '/'; }
      res.writeHead(200, h); res.end(req.method === 'HEAD' ? undefined : data);
    });
  } catch (e) { console.error(e); deny(res, req, 500); }
});
// Slowloris / slow-body protection
server.headersTimeout = 15000; server.requestTimeout = 30000; server.keepAliveTimeout = 5000; server.maxHeadersCount = 60; server.maxRequestsPerSocket = 1000;

// ---------- connections ----------
const local = new Map(); // user -> Map(device -> ws)
const send = (ws, o) => { if (ws && ws.readyState === 1) ws.send(JSON.stringify(o)); };
const localWs = (u, d) => local.get(u)?.get(d);

function onBusMessage(u, m) {
  const devs = local.get(u); if (!devs) return;
  if (m.kind === 'dev') send(devs.get(m.d), m.msg);
  else if (m.kind === 'all') for (const ws of devs.values()) if (ws.device !== m.except) send(ws, m.msg);
  else if (m.kind === 'kickall') { for (const ws of devs.values()) { send(ws, { t: 'kicked', reason: m.reason }); ws.close(); } }
  else if (m.kind === 'kick') { const ws = devs.get(m.d); if (ws && ws.conn !== m.conn) { send(ws, { t: 'kicked', reason: m.reason }); ws.close(); } }
}
async function toDevice(u, d, msg) { const ws = localWs(u, d); if (ws) return send(ws, msg); await bus.publishUser(u, { kind: 'dev', d, msg }); }
async function toUser(u, msg, except) {
  for (const ws of local.get(u)?.values() || []) if (ws.device !== except) send(ws, msg);
  if (bus.kind !== 'local') await bus.publishUser(u, { kind: 'all', msg, except });
}

async function presenceOf(u, user) {
  user ||= await store.getUser(u); if (!user) return null;
  if (user.hideLastSeen) return { online: null, lastSeen: null };
  const online = (await bus.onlineDevices(u)).length > 0;
  return { online, lastSeen: online ? Date.now() : user.lastSeen };
}
async function onPresenceChange(u) {
  const watchers = [];
  for (const devs of local.values()) for (const ws of devs.values()) if (ws.watching.has(u)) watchers.push(ws);
  if (!watchers.length) return;
  const p = await presenceOf(u); if (!p) return;
  for (const ws of watchers) send(ws, { t: 'presence', username: u, ...p });
}
async function publicUser(u) {
  const user = await store.getUser(u); if (!user) return null;
  const devices = (await store.getDevices(u)).filter((d) => user.deviceList.devices.includes(d.device)).map((d) => ({ device: d.device, cert: d.cert }));
  return { username: u, aik: user.aik, deviceList: user.deviceList, devices, displayName: user.profile.displayName || u, about: user.profile.about || '', avatar: user.profile.avatar || null, ...(await presenceOf(u, user)) };
}
function localWatchers(u, msg) { for (const devs of local.values()) for (const ws of devs.values()) if (ws.watching.has(u)) send(ws, msg); }
const notifyWatchers = (u, msg) => bus.broadcast({ u, msg }); // reaches watchers on every instance

await bus.start((ev) => (ev.msg ? localWatchers(ev.u, ev.msg) : onPresenceChange(ev.u)));
const sec = createSecurity({ store: adminStore, bus });
const wss = new WebSocketServer({ noServer: true, maxPayload: MAX_PAYLOAD });
const connsPerIp = new Map();
function allowedOrigin(req) {
  const o = req.headers.origin; if (!o) return true; // non-browser clients send no Origin; browsers always do
  const allowed = (process.env.ALLOWED_ORIGINS || '').split(',').map((x) => x.trim()).filter(Boolean);
  if (allowed.length) return allowed.includes(o);
  try { return new URL(o).host === req.headers.host; } catch { return false; }
}
server.on('upgrade', async (req, socket, head) => {
  const ip = clientIp(req);
  const reject = (code, why) => { socket.write(`HTTP/1.1 ${code} ${why}\r\nConnection: close\r\n\r\n`); socket.destroy(); };
  try {
    if (await sec.isBanned(ip)) return reject(403, 'Forbidden');
    if (!allowedOrigin(req)) { // cross-site WebSocket hijacking attempt
      await sec.event('ws_bad_origin', 'high', { ip, detail: { origin: String(req.headers.origin).slice(0, 100) } }); await sec.strike(ip, 10, 'bad_origin');
      return reject(403, 'Forbidden');
    }
    if ((connsPerIp.get(ip) || 0) >= LIMITS.connPerIp) { await sec.strike(ip, 3, 'conn_flood'); return reject(429, 'Too Many Connections'); }
    if (!(await sec.allow('wsconn:' + ip, LIMITS.connRatePerIp, 60))) { await sec.strike(ip, 3, 'conn_rate'); return reject(429, 'Too Many Requests'); }
    wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req, ip));
  } catch (e) { console.error(e); socket.destroy(); }
});
wss.on('connection', (ws, req, ip) => {
  Object.assign(ws, { ip, user: null, device: null, conn: crypto.randomBytes(8).toString('hex'), watching: new Set(), bucket: { tokens: 80, at: Date.now() }, bundleBucket: { tokens: 30, at: Date.now() }, isAlive: true, inflight: new Set(), limited: 0 });
  connsPerIp.set(ip, (connsPerIp.get(ip) || 0) + 1);
  const authTimer = setTimeout(() => { if (!ws.user) ws.close(4001, 'auth timeout'); }, AUTH_TIMEOUT);
  ws.on('pong', () => (ws.isAlive = true));
  let chain = Promise.resolve();
  ws.on('message', async (raw) => {
    if (!ws.user && raw.length > PREAUTH_MAX) { await sec.strike(ip, 10, 'preauth_oversize'); return ws.close(1009, 'too large'); }
    if (!take(ws.bucket, 80, 40)) {
      if (++ws.limited % 50 === 1) await sec.event('rate_limited', 'low', { ip, user: ws.user, detail: { count: ws.limited } });
      if (await sec.strike(ip, 1, 'message_flood')) ws.close(1008, 'banned');
      return send(ws, { t: 'error', error: 'rate_limited' });
    }
    let m; try { m = JSON.parse(raw); } catch { await sec.strike(ip, 2, 'bad_json'); return; }
    if (!m || typeof m !== 'object' || typeof m.t !== 'string') { await sec.strike(ip, 2, 'bad_frame'); return; }
    chain = chain.then(() => handle(ws, m)).catch((e) => { console.error(e); send(ws, { t: 'error', error: 'server_error', rid: m.rid }); });
  });
  ws.on('close', async () => {
    clearTimeout(authTimer);
    const n = (connsPerIp.get(ip) || 1) - 1; if (n > 0) connsPerIp.set(ip, n); else connsPerIp.delete(ip);
    if (!ws.user) return;
    const devs = local.get(ws.user);
    if (devs?.get(ws.device) === ws) {
      devs.delete(ws.device);
      if (!devs.size) { local.delete(ws.user); await bus.unsubscribeUser(ws.user); }
      const others = (await bus.onlineDevices(ws.user)).filter((d) => d !== ws.device);
      if (!others.length) await store.updateUser(ws.user, { lastSeen: Date.now() }).catch(() => {});
      await bus.setOnline(ws.user, ws.device, false);
    }
  });
});
function take(b, cap, rate) { const now = Date.now(); b.tokens = Math.min(cap, b.tokens + ((now - b.at) / 1000) * rate); b.at = now; if (b.tokens < 1) return false; b.tokens--; return true; }
const clip = (s, n) => (typeof s === 'string' ? s.trim().slice(0, n) : '');
function cleanAvatar(a) { if (!a || typeof a !== 'object') return null; return { color: /^#[0-9a-f]{6}$/i.test(a.color) ? a.color : '#25a18e', emoji: typeof a.emoji === 'string' ? [...a.emoji].slice(0, 2).join('') : '' }; }
const validSpk = (u, d, sigPk, spk) => spk && Number.isInteger(spk.id) && unb64(spk.pk).length === KEM_PK && verifyPrekey(spk, u, d, 'spk', sigPk);

async function goOnline(ws, u, d) {
  ws.user = u; ws.device = d;
  let devs = local.get(u);
  if (!devs) { devs = new Map(); local.set(u, devs); await bus.subscribeUser(u, (m) => onBusMessage(u, m)); }
  const old = devs.get(d); if (old && old !== ws) { send(old, { t: 'kicked', reason: 'same_device' }); old.close(); }
  devs.set(d, ws);
  if (bus.kind !== 'local') await bus.publishUser(u, { kind: 'kick', d, conn: ws.conn, reason: 'same_device' });
  await bus.setOnline(u, d, true);
  const user = await store.getUser(u); const dev = await store.getDevice(u, d);
  trackLogin(u, d, dev, ws.ip);
  send(ws, { t: 'ready', me: { username: u, aik: user.aik, deviceList: user.deviceList, displayName: user.profile.displayName, about: user.profile.about, avatar: user.profile.avatar, hideLastSeen: user.hideLastSeen, pinSet: !!(await store.getPin(u)) },
    ice: iceServers(u), vapid: vapid.publicKey, prekeys: { otpks: await store.countOtpks(u, d), spkId: dev.spk.id }, pushOn: !!dev.push });
  const alerts = await adminStore.listSecurityEvents({ username: u, since: Date.now() - 7 * 864e5, minSeverity: 'high', limit: 20 });
  if (alerts.length) send(ws, { t: 'security_alerts', alerts: alerts.filter((a) => ALERT_TYPES.has(a.type)).map(alertView) });
  await flushQueue(ws);
}
async function flushQueue(ws) {
  const items = await store.listQueue(ws.user, ws.device, 300);
  const fresh = items.filter((e) => !ws.inflight.has(e.id));
  for (const e of fresh) { ws.inflight.add(e.id); send(ws, { t: 'env', ...e }); }
  ws.queueMore = items.length === 300;
}

async function handle(ws, m) {
  // ---------- authentication ----------
  if (m.t === 'hello') {
    const u = String(m.user || '').toLowerCase(), d = String(m.device || '');
    if (!USERNAME_RE.test(u) || !DEVICE_RE.test(d)) return send(ws, { t: 'auth_error', error: 'Username must be 3–24 chars: a-z, 0-9, _ or .' });
    const user = await store.getUser(u); const dev = user ? await store.getDevice(u, d) : null;
    const deviceKnown = !!dev && user.deviceList.devices.includes(d);
    ws.pending = { u, d, nonce: crypto.randomBytes(32).toString('base64'), pow: deviceKnown ? 0 : await sec.powBits() };
    return send(ws, { t: 'challenge', nonce: ws.pending.nonce, exists: !!user, deviceKnown, aik: user?.aik, deviceList: user?.deviceList, pow: ws.pending.pow || undefined });
  }
  // ---------- PIN login (pre-auth): returns the encrypted seeds only for the right PIN ----------
  if (m.t === 'pin_params') {
    const u = String(m.user || '').toLowerCase();
    if (!USERNAME_RE.test(u) || !(await sec.allow('pinparams:' + ws.ip, 60, 600))) return send(ws, { t: 'pin_params', rid: m.rid, enabled: false, error: 'rate_limited' });
    const rec = await store.getPin(u);
    return send(ws, { t: 'pin_params', rid: m.rid, enabled: !!rec, salt: rec?.salt, attemptsLeft: rec ? LIMITS.pinMaxAttempts - rec.attempts : 0, lockedFor: rec ? Math.max(0, rec.lockedUntil - Date.now()) : 0 });
  }
  if (m.t === 'pin_unlock') {
    const p = ws.pending; ws.pending = null; // one guess per fresh challenge
    const fail = (o) => send(ws, { t: 'pin_result', ok: false, ...o });
    if (!p) return fail({ error: 'No challenge' });
    if (!sec.verifyPow(p.nonce, p.u, p.d, m.pow, p.pow)) { await sec.strike(ws.ip, 4, 'bad_pow'); return fail({ error: 'Proof-of-work check failed — please retry' }); }
    if (!(await sec.allow('pintry:' + ws.ip, LIMITS.pinTriesPerIp, 3600))) {
      if ((await sec.hit('pinbf:' + ws.ip, 3600)) === 1) await sec.event('pin_bruteforce', 'high', { ip: ws.ip, user: p.u });
      await sec.strike(ws.ip, 10, 'pin_bruteforce'); return fail({ error: 'Too many PIN attempts from your network. Try again later.' });
    }
    const rec = await store.getPin(p.u);
    if (!rec) return fail({ error: 'PIN login isn\'t set up for this account. Use your recovery key.' });
    if (rec.lockedUntil > Date.now()) { await sec.event('pin_while_locked', 'medium', { ip: ws.ip, user: p.u }); return fail({ error: 'locked', lockedFor: rec.lockedUntil - Date.now(), attemptsLeft: LIMITS.pinMaxAttempts - rec.attempts }); }
    if (timingSafeEqual(pinVerifier(String(m.auth || '')), rec.verifier)) {
      await store.pinSucceeded(p.u);
      await sec.event('pin_unlock', 'medium', { ip: ws.ip, user: p.u });
      return send(ws, { t: 'pin_result', ok: true, share: decShare(rec.share, p.u), blob: rec.blob });
    }
    const n = await store.pinFailed(p.u, pinBackoff);
    const left = LIMITS.pinMaxAttempts - n;
    await sec.strike(ws.ip, 6, 'pin_failed');
    if (left <= 0) {
      await store.deletePin(p.u);
      const e = await sec.event('pin_wiped', 'critical', { ip: ws.ip, user: p.u, detail: { attempts: n } });
      await toUser(p.u, { t: 'security_alert', alert: alertView(e) });
      return fail({ error: 'wiped' });
    }
    const e = await sec.event('pin_failed', 'high', { ip: ws.ip, user: p.u, detail: { attempt: n, left } });
    await toUser(p.u, { t: 'security_alert', alert: alertView(e) });
    return fail({ error: 'wrong', attemptsLeft: left, lockedFor: pinBackoff(n) });
  }
  if (m.t === 'auth') { // existing device: sign the challenge with the device key
    const p = ws.pending; ws.pending = null; if (!p) return send(ws, { t: 'auth_error', error: 'No challenge' });
    const user = await store.getUser(p.u); const dev = user && await store.getDevice(p.u, p.d);
    if (!dev || !user.deviceList.devices.includes(p.d)) { await authFailed(ws, p.u, 'unknown_device', 'low'); return send(ws, { t: 'auth_error', error: 'device_unknown' }); }
    if (!dsaVerify(AUTH_DOMAIN, { user: p.u, device: p.d, nonce: p.nonce }, m.sig, dev.cert.sigPk)) { await authFailed(ws, p.u, 'bad_device_signature', 'high'); return send(ws, { t: 'auth_error', error: 'Bad signature' }); }
    if (user.suspendedUntil > Date.now()) return send(ws, { t: 'auth_error', error: 'suspended', until: user.suspendedUntil, reason: user.suspendReason });
    return goOnline(ws, p.u, p.d);
  }
  if (m.t === 'enroll') { // new account or new device: prove possession of the account identity key (AIK)
    const p = ws.pending; ws.pending = null; if (!p) return send(ws, { t: 'auth_error', error: 'No challenge' });
    await sec.hit('enroll:global', 60);
    if ((await sec.peek('enrollfail:' + p.u)) >= LIMITS.enrollFailPerUser) {
      await sec.event('enroll_while_locked', 'medium', { ip: ws.ip, user: p.u }); await sec.strike(ws.ip, 5, 'locked_account_attempt');
      return send(ws, { t: 'auth_error', error: 'Too many failed attempts on this account. Try again in 15 minutes.' });
    }
    if (!sec.verifyPow(p.nonce, p.u, p.d, m.pow, p.pow)) { await sec.strike(ws.ip, 4, 'bad_pow'); return send(ws, { t: 'auth_error', error: 'Proof-of-work check failed — please retry' }); }
    const user = await store.getUser(p.u);
    if (user && user.suspendedUntil > Date.now()) return send(ws, { t: 'auth_error', error: 'This account has been suspended by the QChat team.' });
    if (user && m.register) return send(ws, { t: 'auth_error', error: 'That username is taken' });
    if (!user && !m.register) return send(ws, { t: 'auth_error', error: 'No account with that username' });
    if (!user) {
      if (isReservedUsername(p.u)) { await sec.event('reserved_username_attempt', 'medium', { ip: ws.ip, detail: { username: p.u } }); return send(ws, { t: 'auth_error', error: 'That username is reserved — please choose another.' }); }
      if (!(await sec.allow('reg:' + ws.ip, LIMITS.regPerIpHour, 3600))) { await sec.event('mass_registration', 'high', { ip: ws.ip }); await sec.strike(ws.ip, 10, 'mass_registration'); return send(ws, { t: 'auth_error', error: 'Too many new accounts from your network. Try again later.' }); }
      if (looksLikeImpersonation(m.profile?.displayName)) return send(ws, { t: 'auth_error', error: 'That display name looks like an official account — please choose another.' });
    }
    const aik = user ? user.aik : String(m.aik || '');
    if (unb64(aik).length !== DSA_PK) return send(ws, { t: 'auth_error', error: 'Bad identity key' });
    const { cert, deviceList: list, spk, otpks } = m;
    const enrollObj = { user: p.u, device: p.d, nonce: p.nonce, list: list?.version };
    if (!dsaVerify(ENROLL_DOMAIN, enrollObj, m.aikSig, aik)) {
      if (user) await takeoverAttempt(ws, p.u);
      return send(ws, { t: 'auth_error', error: user ? 'Recovery key does not match this username' : 'Bad signature' });
    }
    if (!verifyCert(cert, p.u, aik) || cert.device !== p.d || unb64(cert.sigPk).length !== DSA_PK) return send(ws, { t: 'auth_error', error: 'Bad device certificate' });
    if (!dsaVerify(AUTH_DOMAIN, { user: p.u, device: p.d, nonce: p.nonce }, m.sig, cert.sigPk)) return send(ws, { t: 'auth_error', error: 'Bad device signature' });
    if (!verifyDeviceList(list, p.u, aik) || !list.devices.includes(p.d) || list.devices.length > MAX_DEVICES) return send(ws, { t: 'auth_error', error: list?.devices?.length > MAX_DEVICES ? `Maximum ${MAX_DEVICES} devices — remove one first` : 'Bad device list' });
    if (user && list.version <= user.deviceList.version) return send(ws, { t: 'auth_error', error: 'stale_device_list', version: user.deviceList.version, devices: user.deviceList.devices });
    if (!validSpk(p.u, p.d, cert.sigPk, spk)) return send(ws, { t: 'auth_error', error: 'Bad signed prekey' });
    const goodOtpks = (Array.isArray(otpks) ? otpks : []).slice(0, 100).filter((k) => Number.isInteger(k?.id) && verifyPrekey(k, p.u, p.d, 'otpk', cert.sigPk));
    if (!user) {
      const prof = m.profile || {};
      await store.createUser(p.u, aik, list, { displayName: cleanText(prof.displayName, 40) || p.u, about: 'Hey there! I am using QChat.', avatar: null });
      await sec.event('account_created', 'info', { ip: ws.ip, user: p.u });
      activity(p.u, 'account_created', { device: cleanText(cert.name, 60) }, ws.ip); metric('new_users');
    } else {
      await store.updateUser(p.u, { deviceList: list });
      for (const d of await store.getDevices(p.u)) if (!list.devices.includes(d.device)) { await store.removeDevice(p.u, d.device); await toDevice(p.u, d.device, { t: 'kicked', reason: 'removed' }); }
    }
    await store.putDevice(p.u, p.d, cert, spk);
    if (user) activity(p.u, 'device_linked', { device: p.d, name: cleanText(cert.name, 60) }, ws.ip);
    if (user) { const e = await sec.event('device_linked', 'high', { ip: ws.ip, user: p.u, detail: { device: p.d, name: cleanText(cert.name, 60) } }); await toUser(p.u, { t: 'security_alert', alert: alertView(e) }, p.d); }
    await store.addOtpks(p.u, p.d, goodOtpks);
    await goOnline(ws, p.u, p.d);
    await toUser(p.u, { t: 'devices_changed', username: p.u }, p.d);
    return notifyWatchers(p.u, { t: 'devices_changed', username: p.u });
  }

  if (!ws.user) return send(ws, { t: 'error', error: 'not_authenticated' });
  const me = ws.user, myDev = ws.device;

  switch (m.t) {
    case 'lookup': {
      if (!(await sec.allow('lookup:' + me, LIMITS.lookupPerMin, 60))) {
        if ((await sec.hit('enumflag:' + me, 300)) === 1) await sec.event('enumeration_suspected', 'medium', { ip: ws.ip, user: me });
        await sec.strike(ws.ip, 2, 'enumeration'); return send(ws, { t: 'lookup', rid: m.rid, user: undefined, error: 'rate_limited' });
      }
      const u = String(m.username || '').toLowerCase().replace(/^@/, '');
      return send(ws, { t: 'lookup', rid: m.rid, user: USERNAME_RE.test(u) ? await publicUser(u) : null });
    }
    case 'bundle': { // prekey bundles for starting sessions; hands out each one-time prekey once
      if (!take(ws.bundleBucket, 30, 0.5)) return send(ws, { t: 'bundle', rid: m.rid, error: 'rate_limited' });
      const u = String(m.username || ''); const user = await store.getUser(u);
      if (!user) return send(ws, { t: 'bundle', rid: m.rid, bundles: [] });
      if (u !== me && !(await sec.allow('contacts:' + me, await contactQuota(me), 86400))) {
        if ((await sec.hit('spamflag:' + me, 3600)) === 1) await sec.event('spam_suspected', 'high', { ip: ws.ip, user: me, detail: { reason: 'too many new conversations' } });
        return send(ws, { t: 'bundle', rid: m.rid, bundles: [], error: 'quota' });
      }
      const want = new Set(Array.isArray(m.devices) ? m.devices : user.deviceList.devices);
      const out = [];
      for (const d of await store.getDevices(u)) {
        if (!want.has(d.device) || !user.deviceList.devices.includes(d.device)) continue;
        out.push({ device: d.device, cert: d.cert, spk: d.spk, otpk: await store.takeOtpk(u, d.device) });
        if (await store.countOtpks(u, d.device) < 10) toDevice(u, d.device, { t: 'prekeys_low' });
      }
      return send(ws, { t: 'bundle', rid: m.rid, bundles: out });
    }
    case 'prekeys': {
      const dev = await store.getDevice(me, myDev);
      if (m.spk) { if (!validSpk(me, myDev, dev.cert.sigPk, m.spk)) return send(ws, { t: 'error', error: 'bad_spk' }); await store.setSpk(me, myDev, m.spk); }
      if (Array.isArray(m.otpks)) await store.addOtpks(me, myDev, m.otpks.slice(0, 100).filter((k) => Number.isInteger(k?.id) && unb64(k.pk).length === KEM_PK && verifyPrekey(k, me, myDev, 'otpk', dev.cert.sigPk)));
      return send(ws, { t: 'prekey_status', otpks: await store.countOtpks(me, myDev) });
    }
    case 'devices_update': { // remove devices: new list signed by the account identity key
      const user = await store.getUser(me); const list = m.deviceList;
      if (!verifyDeviceList(list, me, user.aik) || list.version <= user.deviceList.version) return send(ws, { t: 'error', error: 'bad_device_list' });
      await store.updateUser(me, { deviceList: list });
      for (const d of user.deviceList.devices) if (!list.devices.includes(d)) { await store.removeDevice(me, d); await toDevice(me, d, { t: 'kicked', reason: 'removed' }); activity(me, 'device_removed', { device: d }, ws.ip); }
      await toUser(me, { t: 'devices_changed', username: me });
      return notifyWatchers(me, { t: 'devices_changed', username: me });
    }
    case 'profile': {
      const user = await store.getUser(me); const prof = { ...user.profile };
      if (m.displayName !== undefined) {
        const dn = cleanText(m.displayName, 40) || me;
        if (looksLikeImpersonation(dn)) { await sec.event('impersonation_attempt', 'medium', { ip: ws.ip, user: me, detail: { displayName: dn } }); return send(ws, { t: 'error', error: 'display_name_not_allowed' }); }
        prof.displayName = dn;
      }
      if (m.about !== undefined) prof.about = cleanText(m.about, 140);
      if (m.avatar !== undefined) prof.avatar = cleanAvatar(m.avatar);
      await store.updateUser(me, { profile: prof, hideLastSeen: m.hideLastSeen });
      activity(me, 'profile_updated', { fields: ['displayName', 'about', 'avatar', 'hideLastSeen'].filter((k) => m[k] !== undefined) }, ws.ip);
      const pu = await publicUser(me);
      send(ws, { t: 'profile_ok', me: { ...pu, hideLastSeen: m.hideLastSeen ?? user.hideLastSeen } });
      await toUser(me, { t: 'profile_update', user: pu }, myDev);
      return notifyWatchers(me, { t: 'profile_update', user: pu });
    }
    case 'watch': {
      for (const u of (Array.isArray(m.users) ? m.users : []).slice(0, 3000)) {
        if (typeof u !== 'string' || !USERNAME_RE.test(u)) continue;
        ws.watching.add(u);
        const p = await presenceOf(u); if (p) send(ws, { t: 'presence', username: u, ...p });
      }
      return;
    }
    case 'send': {
      // m: { id, to: [{u, d}], env, ephemeral, push }
      const id = String(m.id || '').slice(0, 64);
      if (!id || !validEnvelope(m.env) || !Array.isArray(m.to)) { await sec.strike(ws.ip, 2, 'bad_envelope'); return send(ws, { t: 'sent', id, ok: false }); }
      if (!(await sec.allow('send:' + me, LIMITS.sendPerMin, 60))) { await sec.event('send_flood', 'medium', { ip: ws.ip, user: me }); return send(ws, { t: 'sent', id, ok: false, error: 'rate_limited' }); }
      const item = { id, from: me, fd: myDev, ts: Date.now(), env: m.env };
      const seen = new Set(); const targets = [];
      for (const r of m.to.slice(0, 1500)) {
        const key = r?.u + ':' + r?.d; if (seen.has(key) || (r.u === me && r.d === myDev)) continue; seen.add(key);
        if (USERNAME_RE.test(r.u) && DEVICE_RE.test(r.d)) targets.push(r);
      }
      const devCache = new Map();
      for (const r of targets) {
        if (!devCache.has(r.u)) devCache.set(r.u, new Map((await store.getDevices(r.u)).map((d) => [d.device, d])));
        const dev = devCache.get(r.u).get(r.d); if (!dev) continue;
        if (!m.ephemeral) {
          if (await store.queueCount(r.u, r.d) >= MAX_QUEUE_PER_DEVICE) { if ((await sec.hit('qfull:' + r.u, 3600)) === 1) await sec.event('queue_full', 'medium', { user: r.u, detail: { from: me } }); continue; }
          await store.enqueue(r.u, r.d, item);
        }
        await toDevice(r.u, r.d, { t: 'env', ...item });
        if (m.push && dev.push && r.u !== me && !(await bus.onlineDevices(r.u)).includes(r.d)) sendPush(r.u, r.d, dev.push, { from: me, kind: ['call', 'live'].includes(m.push) ? m.push : 'msg' });
      }
      metric('messages'); metric('deliveries', targets.length); metric('bytes', JSON.stringify(m.env).length); userSent(me);
      return send(ws, { t: 'sent', id, ts: item.ts, ok: true });
    }
    case 'ack': {
      const ids = (Array.isArray(m.ids) ? m.ids : []).map(String).slice(0, 1000);
      for (const id of ids) ws.inflight.delete(id);
      for (let i = 0; i < ids.length; i += 200) await store.ackQueue(me, myDev, ids.slice(i, i + 200));
      if (ws.queueMore && ws.inflight.size === 0) await flushQueue(ws);
      return;
    }
    case 'typing': {
      const msg = { t: 'typing', from: me, chat: clip(m.chat, 80), on: !!m.on, kind: m.kind === 'audio' ? 'audio' : 'text' };
      for (const u of (Array.isArray(m.to) ? m.to : []).slice(0, 256)) if (u !== me && USERNAME_RE.test(u)) await toUser(u, msg);
      return;
    }
    case 'pin_set': {
      const ok = (x, n) => typeof x === 'string' && x.length < 100 && unb64(x).length === n;
      const b = m.blob;
      if (!ok(m.salt, 16) || !ok(m.auth, 32) || !ok(m.share, 32) || !b || typeof b.iv !== 'string' || typeof b.ct !== 'string' || b.ct.length > 400 || unb64(b.iv).length !== 12) return send(ws, { t: 'error', error: 'bad_pin_setup' });
      const existed = !!(await store.getPin(me));
      activity(me, existed ? 'pin_changed' : 'pin_set', { device: myDev }, ws.ip);
      await store.setPin(me, { salt: m.salt, verifier: pinVerifier(m.auth), share: encShare(m.share, me), blob: { iv: b.iv, ct: b.ct } });
      const e = await sec.event(existed ? 'pin_changed' : 'pin_set', existed ? 'high' : 'info', { ip: ws.ip, user: me, detail: { device: myDev } });
      if (existed) await toUser(me, { t: 'security_alert', alert: alertView(e) }, myDev);
      return send(ws, { t: 'pin_ok', enabled: true });
    }
    case 'pin_clear': {
      await store.deletePin(me);
      const e = await sec.event('pin_removed', 'high', { ip: ws.ip, user: me, detail: { device: myDev } });
      await toUser(me, { t: 'security_alert', alert: alertView(e) }, myDev);
      return send(ws, { t: 'pin_ok', enabled: false });
    }
    case 'report': {
      const target = String(m.username || '').toLowerCase();
      if (!USERNAME_RE.test(target) || target === me || !(await store.getUser(target))) return;
      await store.addReport(me, target, cleanText(m.reason, 60));
      activity(me, 'reported_user', { target, reason: cleanText(m.reason, 60) }, ws.ip);
      await sec.event('user_reported', 'medium', { ip: ws.ip, user: target, detail: { by: me, reason: cleanText(m.reason, 60) } });
      if (await store.countReports(target, Date.now() - 864e5) === 5) await sec.event('account_restricted', 'high', { user: target, detail: { reason: '5+ reports in 24h' } });
      return send(ws, { t: 'report_ok', username: target });
    }
    case 'push_sub': {
      const s = m.sub; const ok = s && typeof s.endpoint === 'string' && /^https:\/\//.test(s.endpoint) && s.keys?.p256dh && s.keys?.auth;
      await store.setPush(me, myDev, ok ? { endpoint: s.endpoint, keys: { p256dh: String(s.keys.p256dh), auth: String(s.keys.auth) } } : null);
      activity(me, ok ? 'push_enabled' : 'push_disabled', { device: myDev }, ws.ip);
      return send(ws, { t: 'push_ok', on: !!ok });
    }
    case 'delete_account': {
      await toUser(me, { t: 'kicked', reason: 'deleted' }, myDev);
      await store.deleteUser(me); await adminStore.forgetUser(me); await sec.event('account_deleted', 'info', { ip: ws.ip, user: me }); send(ws, { t: 'deleted' }); ws.close();
      return;
    }
  }
}

// ---------- activity log & analytics (metadata only; buffered, flushed every 15 s) ----------
function activity(username, type, detail, ip) { adminStore.addActivity({ username, type, detail, ipHash: ip ? sec.ipHash(ip) : null }).catch((e) => console.error('activity', e.message)); }
const metricBuf = new Map(), userBuf = new Map(), activeBuf = new Set(), loginSeen = new Map();
function metric(name, n = 1) { const k = day() + '|' + name; metricBuf.set(k, (metricBuf.get(k) || 0) + n); }
function userSent(u) { const k = day() + '|' + u; userBuf.set(k, (userBuf.get(k) || 0) + 1); }
function trackLogin(u, d, dev, ip) {
  activeBuf.add(day() + '|' + u);
  const k = u + ':' + d; if (Date.now() - (loginSeen.get(k) || 0) < 3600e3) return;
  loginSeen.set(k, Date.now()); metric('logins'); activity(u, 'login', { device: d, name: cleanText(dev?.cert?.name, 60) }, ip);
}
async function flushMetrics() {
  const m = [...metricBuf].map(([k, n]) => [...k.split('|'), n]); metricBuf.clear();
  const u = [...userBuf].map(([k, n]) => [...k.split('|'), n]); userBuf.clear();
  const a = [...activeBuf]; activeBuf.clear();
  try {
    if (m.length) await adminStore.incrStats(m);
    if (u.length) await adminStore.incrUserDaily(u);
    const byDay = {}; for (const k of a) { const [d, user] = k.split('|'); (byDay[d] ||= []).push(user); }
    for (const [d, users] of Object.entries(byDay)) await adminStore.markActive(d, users);
  } catch (e) { console.error('metrics flush', e.message); }
}
setInterval(flushMetrics, Number(process.env.METRICS_FLUSH_MS || 15000)).unref();
async function kickUser(u, reason) {
  for (const ws of local.get(u)?.values() || []) { send(ws, { t: 'kicked', reason }); ws.close(); }
  if (bus.kind !== 'local') await bus.publishUser(u, { kind: 'kickall', reason });
}
async function kickDevice(u, d, reason) {
  const ws = localWs(u, d); if (ws) { send(ws, { t: 'kicked', reason }); ws.close(); }
  if (bus.kind !== 'local') await bus.publishUser(u, { kind: 'kick', d, conn: null, reason });
}
function localStats() { let connections = 0; for (const d of local.values()) connections += d.size; return { connections, users: local.size }; }
const monitor = createMonitor({ store, adminStore, bus, sec, port: PORT, instanceId: INSTANCE_ID, localStats, vapidReady: () => !!vapid?.publicKey });
const adminApi = await createAdmin({ store, adminStore, sec, LIMITS, monitor, PUBLIC, CSP, baseHeaders, deny, readJson, isHttps, clientIp, kickUser, kickDevice, onlineDevices: (u) => bus.onlineDevices(u), publicUser });
// First-run bootstrap: create the owner admin from env (kept in .env, never in the repo). 2FA is enrolled at first sign-in.
if (process.env.ADMIN_BOOTSTRAP_USER && process.env.ADMIN_BOOTSTRAP_PASSWORD && (await adminStore.countAdmins()) === 0) {
  try { const r = await adminApi.addAdmin(process.env.ADMIN_BOOTSTRAP_USER, process.env.ADMIN_BOOTSTRAP_PASSWORD, 'owner', { enrolled: false }); console.log(`Created owner admin ${r.username} — sign in at /admin to set up two-factor authentication.`); await adminStore.audit('bootstrap', 'create_admin', r.username, { role: 'owner' }); }
  catch (e) { console.error('Admin bootstrap failed:', e.message); }
}

// ---------- detection helpers ----------
const ALERT_TYPES = new Set(['account_takeover_attempt', 'account_locked', 'device_linked', 'bad_device_signature', 'pin_failed', 'pin_wiped', 'pin_changed', 'pin_removed']);
// growing lockouts after wrong PINs: 3rd → 1 min, 4th → 5 min, 5th → 15 min, 6th → 1 h, then 4 h, 12 h, 24 h
const PIN_BACKOFF_S = [0, 0, 0, 60, 300, 900, 3600, 14400, 43200, 86400];
const pinBackoff = (n) => (LIMITS.pinBackoff ? (PIN_BACKOFF_S[Math.min(n, PIN_BACKOFF_S.length - 1)] || 0) * 1000 : 0);
const alertView = (e) => ({ id: e.id, ts: e.ts, type: e.type, ipHash: e.ipHash, detail: e.detail });
async function authFailed(ws, user, reason, severity) {
  const e = await sec.event(reason === 'bad_device_signature' ? 'bad_device_signature' : 'auth_failed', severity, { ip: ws.ip, user, detail: { reason } });
  if (reason === 'bad_device_signature') await toUser(user, { t: 'security_alert', alert: alertView(e) });
  if (!(await sec.allow('authfail:' + ws.ip, LIMITS.authFailPerIp, 600))) await sec.ban(ws.ip, LIMITS.banSeconds, 'auth_bruteforce');
  else await sec.strike(ws.ip, 4, 'auth_failed');
}
async function takeoverAttempt(ws, user) {
  const n = await sec.hit('enrollfail:' + user, 900);
  const e = await sec.event('account_takeover_attempt', 'high', { ip: ws.ip, user, detail: { attempt: n } });
  await toUser(user, { t: 'security_alert', alert: alertView(e) });
  if (n === LIMITS.enrollFailPerUser) {
    const l = await sec.event('account_locked', 'critical', { ip: ws.ip, user, detail: { minutes: 15 } });
    await toUser(user, { t: 'security_alert', alert: alertView(l) });
  }
  if (!(await sec.allow('authfail:' + ws.ip, LIMITS.authFailPerIp, 600))) await sec.ban(ws.ip, LIMITS.banSeconds, 'recovery_key_bruteforce');
  else await sec.strike(ws.ip, 8, 'takeover_attempt');
}
async function contactQuota(u) {
  const user = await store.getUser(u);
  if (await store.countReports(u, Date.now() - 864e5) >= 5) return LIMITS.newContactsPerDayReported;
  return Date.now() - user.createdAt < 7 * 864e5 ? LIMITS.newContactsPerDayNew : LIMITS.newContactsPerDay;
}
const B64_RE = /^[A-Za-z0-9+/=]*$/;
function validEnvelope(env) { // shape check only — contents stay opaque
  if (!env || typeof env !== 'object' || env.v !== 2) return false;
  if (typeof env.iv !== 'string' || env.iv.length > 32 || typeof env.ct !== 'string' || typeof env.sig !== 'string' || env.sig.length > 6000) return false;
  if (!B64_RE.test(env.iv) || !B64_RE.test(env.sig)) return false;
  if (!Array.isArray(env.keys) || !env.keys.length || env.keys.length > 1500) return false;
  for (const k of env.keys) if (!k || typeof k.u !== 'string' || typeof k.d !== 'string' || typeof k.w !== 'string' || k.w.length > 64 || typeof k.h !== 'object') return false;
  return true;
}

async function sendPush(u, d, sub, data) {
  try { await webpush.sendNotification(sub, JSON.stringify(data), { TTL: 86400, urgency: 'high', topic: 'qchat-' + data.from.replace(/[^a-z0-9]/g, '').slice(0, 20) }); }
  catch (e) { if (e.statusCode === 404 || e.statusCode === 410) await store.setPush(u, d, null); else console.warn('push failed', e.statusCode || e.message); }
}

// heartbeat, presence refresh, queue expiry
setInterval(async () => {
  const list = [];
  for (const ws of wss.clients) {
    if (!ws.isAlive) { ws.terminate(); continue; }
    ws.isAlive = false; ws.ping();
    if (ws.user) list.push([ws.user, ws.device]);
  }
  await bus.refresh(list).catch(() => {});
}, 30000);
setInterval(() => { store.purgeQueue(Date.now() - QUEUE_TTL).catch(() => {}); adminStore.purge().catch(() => {}); }, 3600e3);
process.on('unhandledRejection', (e) => console.error('unhandled', e));

server.listen(PORT, () => { console.log(`QChat running on http://localhost:${PORT} (store: ${store.kind}, admin store: ${adminStore.kind}, bus: ${bus.kind})`); monitor.start(); });
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, async () => { monitor.stop(); server.close(); await flushMetrics(); await bus.close().catch(() => {}); await store.close().catch(() => {}); await adminStore.close().catch(() => {}); process.exit(0); });
