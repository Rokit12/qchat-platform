// Attack simulations against a real server process. node --test tests/security.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import WebSocket from 'ws';
import * as C from '../src/shared/crypto.js';
import { startServer, Client } from './helpers.mjs';
import { adminLogin, BOOT } from './admin-helpers.mjs';

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'qsec-'));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const get = (port, p, headers = {}) => fetch(`http://localhost:${port}${p}`, { headers, redirect: 'manual' });
function wsTry(port, headers) {
  return new Promise((res) => {
    const ws = new WebSocket(`ws://localhost:${port}`, { headers });
    ws.on('open', () => res({ ok: true, ws })); ws.on('unexpected-response', (_, r) => res({ ok: false, status: r.statusCode })); ws.on('error', () => res({ ok: false }));
  });
}
const uniq = (p) => p + Math.random().toString(36).slice(2, 7);

test('HTTP hardening: security headers, HSTS, HTTPS redirect, traversal, scanner auto-ban', async () => {
  const s = await startServer(3301, { DATA_DIR: tmp(), TRUST_PROXY: '1', STRIKE_BAN: '40' });
  try {
    const r = await get(3301, '/', { 'x-forwarded-proto': 'https', 'x-forwarded-for': '10.0.0.1' });
    assert.equal(r.status, 200);
    const h = Object.fromEntries(r.headers);
    assert.match(h['content-security-policy'], /default-src 'self'/);
    assert.match(h['content-security-policy'], /frame-ancestors 'none'/);
    assert.equal(h['x-frame-options'], 'DENY'); assert.equal(h['x-content-type-options'], 'nosniff');
    assert.match(h['strict-transport-security'], /max-age=63072000; includeSubDomains; preload/);
    assert.equal(h['cross-origin-opener-policy'], 'same-origin');
    const redir = await get(3301, '/', { 'x-forwarded-proto': 'http', 'x-forwarded-for': '10.0.0.2' });
    assert.equal(redir.status, 301); assert.match(redir.headers.get('location'), /^https:/);
    assert.equal((await get(3301, '/..%2f..%2fetc%2fpasswd', { 'x-forwarded-for': '10.0.0.3' })).status, 404);
    assert.equal((await get(3301, '/server/index.js', { 'x-forwarded-for': '10.0.0.3' })).status, 404, 'source files are never served');
    assert.equal((await fetch('http://localhost:3301/', { method: 'PUT', headers: { 'x-forwarded-for': '10.0.0.3' } })).status, 405);
    // a vulnerability scanner probing common paths gets banned
    for (const p of ['/.env', '/wp-login.php', '/.git/config']) await get(3301, p, { 'x-forwarded-for': '10.6.6.6' });
    assert.equal((await get(3301, '/', { 'x-forwarded-for': '10.6.6.6' })).status, 403, 'scanner IP is banned');
    assert.equal((await get(3301, '/', { 'x-forwarded-for': '10.0.0.4' })).status, 200, 'other users unaffected');
  } finally { s.kill(); }
});

test('WebSocket hardening: origin check, per-IP caps, auth timeout, oversized frames, bad envelopes, floods', async () => {
  const s = await startServer(3302, { DATA_DIR: tmp(), MAX_CONN_PER_IP: '3', AUTH_TIMEOUT_MS: '800', STRIKE_BAN: '60' });
  try {
    const evil = await wsTry(3302, { origin: 'https://evil.example' });
    assert.equal(evil.ok, false, 'cross-site WebSocket hijacking blocked'); assert.equal(evil.status, 403);
    const same = await wsTry(3302, { origin: 'http://localhost:3302' }); assert.ok(same.ok);
    const socks = [same.ws, (await wsTry(3302)).ws, (await wsTry(3302)).ws];
    const fourth = await wsTry(3302); assert.equal(fourth.ok, false); assert.equal(fourth.status, 429, 'per-IP connection cap');
    const closed = await new Promise((r) => socks[0].on('close', (code) => r(code)));
    assert.equal(closed, 4001, 'unauthenticated socket closed after timeout');
    for (const w of socks) w.close(); await sleep(200);
    const big = (await wsTry(3302)).ws;
    const code = await new Promise((r) => { big.on('close', (c) => r(c)); big.send('x'.repeat(700 * 1024)); });
    assert.equal(code, 1009, 'oversized pre-auth frame rejected');
    await sleep(200);
    const a = new Client(3302, uniq('flood'), C.accountKeys(C.newAccountSeeds())); assert.equal((await a.login({ register: true })).t, 'ready');
    a.sendRaw({ t: 'send', id: 'x1', to: [{ u: a.user, d: a.dev.device }], env: { v: 2, keys: 'nope' } });
    assert.equal((await a.next((m) => m.t === 'sent')).ok, false, 'malformed envelope refused');
    for (let i = 0; i < 400; i++) a.sendRaw({ t: 'watch', users: [] });
    await a.next((m) => m.t === 'error' && m.error === 'rate_limited');
    const closedByBan = await new Promise((r) => { a.ws.on('close', () => r(true)); setTimeout(() => r(false), 4000); });
    assert.ok(closedByBan, 'sustained flood → IP banned and socket closed');
    assert.equal((await wsTry(3302)).status, 403, 'banned IP cannot reconnect');
  } finally { s.kill(); }
});

test('Account protection: PoW, reserved names, impersonation, mass sign-up, takeover detection + lockout + owner alerts', async () => {
  const s = await startServer(3303, { DATA_DIR: tmp(), REG_PER_IP_HOUR: '4', ...BOOT });
  try {
    const noPow = new Client(3303, uniq('pow'), C.accountKeys(C.newAccountSeeds()));
    assert.match((await noPow.login({ register: true, tamper: 'pow' })).error, /Proof-of-work/); noPow.close();
    const fake = new Client(3303, 'support', C.accountKeys(C.newAccountSeeds()));
    assert.match((await fake.login({ register: true })).error, /reserved/); fake.close();
    const imp = Object.assign(new Client(3303, uniq('imp'), C.accountKeys(C.newAccountSeeds())), { displayName: 'QChat Support ✔' });
    assert.match((await imp.login({ register: true })).error, /official/); imp.close();

    const acct = C.accountKeys(C.newAccountSeeds());
    const owner = new Client(3303, uniq('owner'), acct); assert.equal((await owner.login({ register: true })).t, 'ready');
    owner.sendRaw({ t: 'profile', displayName: 'Official Admin' });
    assert.equal((await owner.next((m) => m.t === 'error')).error, 'display_name_not_allowed');
    owner.sendRaw({ t: 'profile', displayName: 'Ali‮ecila' }); // RTL-override spoofing characters are stripped
    assert.equal((await owner.next((m) => m.t === 'profile_ok')).me.displayName, 'Aliecila');

    // attacker guesses recovery keys for the owner's username
    for (let i = 1; i <= 5; i++) {
      const thief = new Client(3303, owner.user, C.accountKeys(C.newAccountSeeds()));
      assert.match((await thief.login()).error, /does not match/); thief.close();
      const al = await owner.next((m) => m.t === 'security_alert' && m.alert.type === 'account_takeover_attempt');
      assert.equal(al.alert.detail.attempt, i);
    }
    assert.equal((await owner.next((m) => m.t === 'security_alert')).alert.type, 'account_locked');
    const real = new Client(3303, owner.user, acct); // even the right key is refused while locked
    assert.match((await real.login()).error, /Too many failed attempts/); real.close();

    // mass registration from one IP
    let blocked = false;
    for (let i = 0; i < 4; i++) { const c = new Client(3303, uniq('bulk'), C.accountKeys(C.newAccountSeeds())); const r = await c.login({ register: true }); c.close(); if (r.error && /Too many new accounts/.test(r.error)) blocked = true; }
    assert.ok(blocked, 'per-IP registration limit');

    // admin dashboard (password + 2FA; failed sign-ins are logged)
    assert.equal((await get(3303, '/admin/api/overview', { 'x-qchat-admin': '1' })).status, 401);
    await fetch('http://localhost:3303/admin/api/login', { method: 'POST', headers: { 'x-qchat-admin': '1', 'content-type': 'application/json' }, body: JSON.stringify({ username: BOOT.ADMIN_BOOTSTRAP_USER, password: 'guessing-123456' }) });
    const adm = await adminLogin(3303);
    const types = new Set((await adm.api('overview')).body.security7d.map((e) => e.type));
    for (const t of ['account_takeover_attempt', 'account_locked', 'reserved_username_attempt', 'mass_registration', 'admin_auth_failed']) assert.ok(types.has(t), 'event logged: ' + t);
    const ev = (await adm.api(`events?user=${owner.user}&minSeverity=high`)).body;
    assert.ok(ev.length >= 6 && ev.every((e) => !String(e.ipHash).includes('127.0.0.1')), 'events stored with hashed IPs');
    assert.equal((await get(3303, '/admin')).status, 200);
    owner.close();
  } finally { s.kill(); }
});

test('Anti-spam & anti-enumeration: lookup limits, new-contact quota, reports', async () => {
  const s = await startServer(3304, { DATA_DIR: tmp(), LOOKUP_PER_MIN: '5', NEW_CONTACTS_PER_DAY_NEW_ACCOUNT: '2', ...BOOT });
  try {
    const users = [];
    for (let i = 0; i < 4; i++) { const c = new Client(3304, uniq('u'), C.accountKeys(C.newAccountSeeds())); await c.login({ register: true }); users.push(c); }
    const [spammer, ...victims] = users;
    for (let i = 0; i < 5; i++) assert.ok((await spammer.rpc({ t: 'lookup', username: victims[0].user }, 'lookup')).user);
    assert.equal((await spammer.rpc({ t: 'lookup', username: victims[1].user }, 'lookup')).error, 'rate_limited', 'username enumeration throttled');
    assert.equal((await spammer.rpc({ t: 'bundle', username: victims[0].user }, 'bundle')).bundles.length, 1);
    assert.equal((await spammer.rpc({ t: 'bundle', username: victims[1].user }, 'bundle')).bundles.length, 1);
    assert.equal((await spammer.rpc({ t: 'bundle', username: victims[2].user }, 'bundle')).error, 'quota', 'new accounts can only start a few conversations per day');
    for (const v of victims) { v.sendRaw({ t: 'report', username: spammer.user, reason: 'phishing' }); await v.next((m) => m.t === 'report_ok'); }
    const ev = (await (await adminLogin(3304)).api(`events?user=${spammer.user}`)).body;
    assert.ok(ev.filter((e) => e.type === 'user_reported').length === 3);
    assert.ok(ev.some((e) => e.type === 'spam_suspected') && ev.some((e) => e.type === 'enumeration_suspected'));
    users.forEach((u) => u.close());
  } finally { s.kill(); }
});

// ---------------------------------------------------------------- PIN login
import { pinKeys, sealSeeds, openSeeds, weakPin } from '../src/shared/pin.js';
async function setupPin(client, seeds, pin) {
  const salt = C.rand(16); const { auth, enc } = await pinKeys(pin, salt); const share = C.rand(32);
  const blob = await sealSeeds(C.concat(seeds.aikSeed, seeds.backupSeed), enc, share, client.user);
  client.sendRaw({ t: 'pin_set', salt: C.b64(salt), auth: C.b64(auth), share: C.b64(share), blob });
  return client.next((m) => m.t === 'pin_ok');
}
async function tryPin(port, user, pin) { // what a brand-new device does
  const c = new Client(port, user, null); await c.connect();
  const params = await c.rpc({ t: 'pin_params', user }, 'pin_params');
  if (!params.enabled) { c.close(); return { disabled: true }; }
  const { auth, enc } = await pinKeys(pin, C.unb64(params.salt));
  c.sendRaw({ t: 'hello', user, device: C.randId(8) });
  const ch = await c.next((m) => m.t === 'challenge');
  c.sendRaw({ t: 'pin_unlock', auth: C.b64(auth), pow: await C.solvePow(ch.nonce, user, c.lastDevice, ch.pow) });
  const r = await c.next((m) => m.t === 'pin_result'); c.close();
  if (r.ok) { const raw = await openSeeds(r.blob, enc, C.unb64(r.share), user); return { ok: true, seeds: { aikSeed: raw.slice(0, 32), backupSeed: raw.slice(32, 96) } }; }
  return r;
}

test('PIN login: right PIN recovers the account, wrong PINs alert the owner, lock out, then wipe', async () => {
  const dir = tmp();
  const s = await startServer(3305, { DATA_DIR: dir, PIN_MAX_ATTEMPTS: '5', PIN_PEPPER: 'test-pepper-0123456789abcdef', STRIKE_BAN: '100000' });
  try {
    assert.ok(weakPin('123456') && weakPin('111111') && weakPin('121212') && weakPin('19900') && !weakPin('482916'));
    const seeds = C.newAccountSeeds();
    const owner = new Client(3305, uniq('pin'), C.accountKeys(seeds)); assert.equal((await owner.login({ register: true })).t, 'ready');
    assert.equal((await setupPin(owner, seeds, '482916')).enabled, true);

    const ok = await tryPin(3305, owner.user, '482916');
    assert.ok(ok.ok && C.b64(ok.seeds.aikSeed) === C.b64(seeds.aikSeed), 'correct PIN returns the account seeds');
    // the recovered seeds can enrol a new device exactly like a recovery key
    const newDev = new Client(3305, owner.user, C.accountKeys({ aikSeed: ok.seeds.aikSeed, backupSeed: ok.seeds.backupSeed }));
    assert.equal((await newDev.login()).t, 'ready'); newDev.close();

    // the server database alone can't verify PIN guesses (needs PIN_PEPPER, kept outside the DB)
    const { DatabaseSync } = await import('node:sqlite');
    const row = new DatabaseSync(path.join(dir, 'qchat.db')).prepare('SELECT * FROM pin_recovery').get();
    const { auth } = await pinKeys('482916', C.unb64(row.salt));
    assert.notEqual(row.verifier, C.b64(auth), 'stored verifier is peppered, not the raw PIN hash');

    for (let i = 1; i <= 2; i++) {
      const r = await tryPin(3305, owner.user, '000137');
      assert.equal(r.error, 'wrong'); assert.equal(r.attemptsLeft, 5 - i);
      const al = await owner.next((m) => m.t === 'security_alert' && m.alert.type === 'pin_failed');
      assert.equal(al.alert.detail.left, 5 - i);
    }
    const third = await tryPin(3305, owner.user, '000138');
    assert.equal(third.lockedFor, 60000, 'third wrong PIN → 1 minute lockout');
    const locked = await tryPin(3305, owner.user, '482916');
    assert.equal(locked.error, 'locked', 'even the right PIN is refused during the lockout');
    owner.close();
  } finally { s.kill(); }
});

test('PIN login: guess limit wipes PIN recovery; per-IP PIN brute force is blocked', async () => {
  const s = await startServer(3306, { DATA_DIR: tmp(), PIN_MAX_ATTEMPTS: '3', PIN_BACKOFF: '0', PIN_TRIES_PER_IP: '4', STRIKE_BAN: '100000' });
  try {
    const seeds = C.newAccountSeeds();
    const owner = new Client(3306, uniq('wipe'), C.accountKeys(seeds)); await owner.login({ register: true });
    await setupPin(owner, seeds, '582047');
    for (const g of ['111112', '222224']) assert.equal((await tryPin(3306, owner.user, g)).error, 'wrong');
    assert.equal((await tryPin(3306, owner.user, '333336')).error, 'wiped');
    assert.equal((await owner.next((m) => m.t === 'security_alert' && m.alert.type === 'pin_wiped')).alert.type, 'pin_wiped');
    assert.ok((await tryPin(3306, owner.user, '582047')).disabled, 'after the wipe even the right PIN cannot recover the account');
    // an attacker spraying guesses across accounts from one IP hits the per-IP cap
    const other = new Client(3306, uniq('spray'), C.accountKeys(seeds)); await other.login({ register: true }); await setupPin(other, seeds, '582047');
    let blocked = false;
    for (let i = 0; i < 4 && !blocked; i++) { const r = await tryPin(3306, other.user, '90000' + i); if (/Too many PIN attempts/.test(r.error || '')) blocked = true; }
    assert.ok(blocked, 'per-IP PIN attempt cap');
    owner.close(); other.close();
  } finally { s.kill(); }
});
