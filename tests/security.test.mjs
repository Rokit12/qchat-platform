// Attack simulations against a real server process. node --test tests/security.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import WebSocket from 'ws';
import * as C from '../src/shared/crypto.js';
import { startServer, Client } from './helpers.mjs';

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
  const s = await startServer(3303, { DATA_DIR: tmp(), REG_PER_IP_HOUR: '4', ADMIN_TOKEN: 'test-admin-token-123' });
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

    // admin dashboard
    assert.equal((await get(3303, '/admin/api/summary')).status, 401);
    assert.equal((await get(3303, '/admin/api/summary', { authorization: 'Bearer wrong' })).status, 401);
    const sum = await (await get(3303, '/admin/api/summary', { authorization: 'Bearer test-admin-token-123' })).json();
    for (const t of ['account_takeover_attempt', 'account_locked', 'reserved_username_attempt', 'mass_registration', 'admin_auth_failed']) assert.ok(sum.last24h.byType[t] >= 1, 'event logged: ' + t);
    const ev = await (await get(3303, `/admin/api/events?user=${owner.user}&minSeverity=high`, { authorization: 'Bearer test-admin-token-123' })).json();
    assert.ok(ev.length >= 6 && ev.every((e) => !String(e.ipHash).includes('127.0.0.1')), 'events stored with hashed IPs');
    assert.equal((await get(3303, '/admin')).status, 200);
    owner.close();
  } finally { s.kill(); }
});

test('Anti-spam & anti-enumeration: lookup limits, new-contact quota, reports', async () => {
  const s = await startServer(3304, { DATA_DIR: tmp(), LOOKUP_PER_MIN: '5', NEW_CONTACTS_PER_DAY_NEW_ACCOUNT: '2', ADMIN_TOKEN: 'tok-abcdef' });
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
    const ev = await (await get(3304, `/admin/api/events?user=${spammer.user}`, { authorization: 'Bearer tok-abcdef' })).json();
    assert.ok(ev.filter((e) => e.type === 'user_reported').length === 3);
    assert.ok(ev.some((e) => e.type === 'spam_suspected') && ev.some((e) => e.type === 'enumeration_suspected'));
    users.forEach((u) => u.close());
  } finally { s.kill(); }
});
