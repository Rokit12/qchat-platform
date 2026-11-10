// Admin dashboard API, admin-auth attacks, user management, analytics, independent DB, service status.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import * as C from '../src/shared/crypto.js';
import { startServer, Client } from './helpers.mjs';
import { adminLogin, BOOT } from './admin-helpers.mjs';
import { totpAt } from '../server/admin-auth.js';

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'qadm-'));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const uniq = (p) => p + Math.random().toString(36).slice(2, 7);
const H = { 'x-qchat-admin': '1', 'content-type': 'application/json' };
const login = (port, body) => fetch(`http://localhost:${port}/admin/api/login`, { method: 'POST', headers: H, body: JSON.stringify(body) });

test('admin auth: bootstrap owner, 2FA enrolment, lockout, TOTP replay, CSRF, roles', async () => {
  const s = await startServer(3501, { DATA_DIR: tmp(), ...BOOT });
  try {
    assert.equal((await login(3501, { username: BOOT.ADMIN_BOOTSTRAP_USER, password: 'wrong-password-123' })).status, 401);
    const owner = await adminLogin(3501);
    assert.match(owner.rawSetCookie, /HttpOnly/); assert.match(owner.rawSetCookie, /SameSite=Strict/);
    assert.equal((await owner.api('me')).body.role, 'owner');
    // the same TOTP code can't be replayed
    const code = totpAt(owner.secret, Math.floor(Date.now() / 30000));
    const replay = await login(3501, { username: BOOT.ADMIN_BOOTSTRAP_USER, password: BOOT.ADMIN_BOOTSTRAP_PASSWORD, code });
    assert.equal(replay.status, 401, 'TOTP code replay rejected');
    // CSRF: no custom header / foreign Origin
    assert.equal((await fetch('http://localhost:3501/admin/api/me', { headers: { cookie: owner.cookie } })).status, 403);
    assert.equal((await fetch('http://localhost:3501/admin/api/me', { headers: { ...H, cookie: owner.cookie, origin: 'https://evil.example' } })).status, 403);
    // owner creates a read-only viewer
    const v = await owner.api('admins', { method: 'POST', body: { username: 'viewer.one', password: 'Viewer-pass-12345', role: 'viewer' } });
    assert.ok(v.body.totpSecret);
    const vl = await login(3501, { username: 'viewer.one', password: 'Viewer-pass-12345', code: totpAt(v.body.totpSecret, Math.floor(Date.now() / 30000)) });
    const vCookie = vl.headers.get('set-cookie').split(';')[0];
    const vApi = (p, o = {}) => fetch('http://localhost:3501/admin/api/' + p, { method: o.method || 'GET', headers: { ...H, cookie: vCookie }, body: o.body ? JSON.stringify(o.body) : undefined });
    assert.equal((await vApi('overview')).status, 200, 'viewer can read');
    assert.equal((await vApi('audit')).status, 403, 'viewer cannot read the audit log');
    // brute force on an admin account → lockout
    for (let i = 0; i < 5; i++) await login(3501, { username: 'viewer.one', password: 'nope-nope-nope-1', code: '000000' });
    const locked = await login(3501, { username: 'viewer.one', password: 'Viewer-pass-12345', code: totpAt(v.body.totpSecret, Math.floor(Date.now() / 30000) + 1) });
    assert.ok([423, 429].includes(locked.status), 'admin account locked after repeated failures (got ' + locked.status + ')');
    const audit = await owner.api('audit');
    assert.ok(audit.body.some((a) => a.action === 'create_admin') && audit.body.some((a) => a.action === 'enrolled_2fa'));
  } finally { s.kill(); }
});

test('users, activity, analytics, management actions, SQL-injection safety, independent DB', async () => {
  const dir = tmp();
  const s = await startServer(3502, { DATA_DIR: dir, ...BOOT, METRICS_FLUSH_MS: '400' });
  try {
    const a = new Client(3502, uniq('ana'), C.accountKeys(C.newAccountSeeds())); await a.login({ register: true });
    const b = new Client(3502, uniq('ben'), C.accountKeys(C.newAccountSeeds())); await b.login({ register: true });
    for (let i = 0; i < 3; i++) await a.sendTo(b.user, { text: 'hi ' + i });
    await sleep(900);
    const adm = await adminLogin(3502);
    const list = await adm.api('users?q=' + encodeURIComponent(a.user));
    assert.equal(list.body.total, 1); assert.equal(list.body.users[0].online, true);
    // injection attempts are treated as plain text / ignored
    for (const q of ["' OR 1=1 --", '%', '_', "x'); DROP TABLE users; --"]) assert.equal((await adm.api('users?q=' + encodeURIComponent(q))).body.total, 0, q);
    assert.equal((await adm.api('users?sort=' + encodeURIComponent('created_at; DROP TABLE users'))).body.total, 2, 'unknown sort falls back to a whitelisted one');
    assert.equal((await adm.api('users')).body.total, 2, 'users table intact');
    const det = (await adm.api('users/' + a.user)).body;
    assert.ok(det.timeline.some((t) => t.type === 'account_created') && det.timeline.some((t) => t.type === 'login'));
    assert.equal(det.messagesPerDay.reduce((x, y) => x + y.sent, 0), 3, 'per-user message counts (metadata only)');
    const ov = (await adm.api('overview')).body;
    assert.equal(ov.totals.users, 2); assert.ok(ov.charts.messages.at(-1) >= 3); assert.ok(ov.charts.dau.at(-1) >= 2);
    // suspend → live session kicked, logins refused; unsuspend → works again
    assert.equal((await adm.api(`users/${b.user}/suspend`, { method: 'POST', body: { hours: 1, reason: 'test' } })).status, 200);
    assert.equal((await b.next((m) => m.t === 'kicked')).reason, 'suspended');
    const b2 = Object.assign(new Client(3502, b.user, b.acct), { dev: b.dev });
    assert.equal((await b2.login()).error, 'suspended'); b2.close();
    await adm.api(`users/${b.user}/unsuspend`, { method: 'POST' });
    const b3 = Object.assign(new Client(3502, b.user, b.acct), { dev: b.dev }); assert.equal((await b3.login()).t, 'ready');
    // force sign-out & device removal
    await adm.api(`users/${a.user}/logout`, { method: 'POST' }); assert.equal((await a.next((m) => m.t === 'kicked')).reason, 'admin_logout');
    await adm.api(`users/${b.user}/remove_device/${b.dev.device}`, { method: 'POST' });
    assert.equal((await b3.next((m) => m.t === 'kicked')).reason, 'removed');
    // delete requires typing the username
    assert.equal((await adm.api(`users/${a.user}/delete`, { method: 'POST', body: { confirm: 'nope' } })).status, 400);
    assert.equal((await adm.api(`users/${a.user}/delete`, { method: 'POST', body: { confirm: a.user } })).status, 200);
    assert.equal((await adm.api('users')).body.total, 1);
    const audit = (await adm.api('audit')).body.map((x) => x.action);
    for (const act of ['suspend', 'unsuspend', 'force_logout', 'remove_device', 'delete_account']) assert.ok(audit.includes(act), 'audited: ' + act);
    // independent databases: no admin tables in the chat DB and no chat tables in the admin DB
    const { DatabaseSync } = await import('node:sqlite');
    const tables = (f) => new DatabaseSync(path.join(dir, f)).prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map((r) => r.name);
    const chat = tables('qchat.db'), admin = tables('admin.db');
    assert.ok(!chat.some((t) => /admin|activity|security_events|health/.test(t)), 'chat DB holds no admin data: ' + chat);
    assert.ok(!admin.some((t) => ['users', 'devices', 'queue', 'otpks', 'pin_recovery'].includes(t)), 'admin DB holds no chat data: ' + admin);
    b3.close();
  } finally { s.kill(); }
});

test('service monitor: detects an outage, opens an incident, public status shows it', async () => {
  const s = await startServer(3503, { DATA_DIR: tmp(), ...BOOT, MONITOR_INTERVAL_MS: '700', TURN_URL: 'turn:127.0.0.1:1' });
  try {
    await sleep(3200);
    const pub = await (await fetch('http://localhost:3503/api/status')).json();
    assert.equal(pub.overall, 'degraded');
    const calls = pub.services.find((x) => x.name === 'Voice & video calls'); assert.equal(calls.state, 'down');
    assert.equal(pub.services.find((x) => x.name === 'Messaging').state, 'up');
    assert.ok(!JSON.stringify(pub).includes('127.0.0.1'), 'public status reveals no internals');
    const adm = await adminLogin(3503);
    const st = (await adm.api('status')).body;
    assert.ok(st.incidents.some((i) => i.service === 'turn' && !i.ended), 'incident opened');
    assert.ok(st.services.find((x) => x.id === 'database').uptime24h === 100);
    assert.equal(st.instances.length, 1);
    const ev = (await adm.api('events?minSeverity=critical')).body; assert.ok(ev.some((e) => e.type === 'service_down'));
  } finally { s.kill(); }
});
