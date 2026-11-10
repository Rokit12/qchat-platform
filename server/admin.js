// Admin dashboard API. Individual admin accounts (password + TOTP 2FA), roles, HttpOnly session cookies,
// CSRF protection, idle/absolute session timeouts, login lockouts and a full audit trail.
// Message content is end-to-end encrypted, so it is never available here — only account metadata.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { hashPassword, verifyPassword, verifyTotp, newTotpSecret, otpauthUrl, secretBox, passwordProblem, ROLES } from './admin-auth.js';
import { day } from './admin-store.js';

const SESSION_ABS = 8 * 3600e3, SESSION_IDLE = 30 * 60e3, LOGIN_FAILS = 5, LOGIN_LOCK = 15 * 60e3;
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');

export async function createAdmin(ctx) {
  const { store, adminStore, sec, monitor, PUBLIC, baseHeaders, deny, readJson, isHttps, kickUser, kickDevice, onlineDevices } = ctx;
  let keyMaterial = process.env.ADMIN_SECRET_KEY;
  if (!keyMaterial) { keyMaterial = await adminStore.initMeta('secret_key', crypto.randomBytes(32).toString('base64')); if (sec) console.warn('⚠️  ADMIN_SECRET_KEY is not set — using a key stored in the admin database. Set it in production.'); }
  const box = secretBox(keyMaterial);
  const html = (f) => fs.promises.readFile(path.join(PUBLIC, f));

  function cookie(req, token, maxAge) {
    return `qadmin=${token}; Path=/admin; HttpOnly; SameSite=Strict; Max-Age=${Math.floor(maxAge / 1000)}${isHttps(req) ? '; Secure' : ''}`;
  }
  const readCookie = (req) => (String(req.headers.cookie || '').match(/(?:^|;\s*)qadmin=([A-Za-z0-9_-]{20,})/) || [])[1];
  async function session(req) {
    const tok = readCookie(req); if (!tok) return null;
    const s = await adminStore.getSession(sha(tok)); const now = Date.now();
    if (!s || Number(s.expires) < now || now - Number(s.last_seen) > SESSION_IDLE) { if (s) await adminStore.deleteSession(sha(tok)); return null; }
    const admin = await adminStore.getAdminById(s.admin_id);
    if (!admin || Number(admin.disabled)) return null;
    await adminStore.touchSession(sha(tok));
    return { admin, tokenHash: sha(tok) };
  }

  /** Create an admin (CLI bootstrap or by an owner). Returns the TOTP secret + otpauth URL to scan once. */
  async function addAdmin(username, password, role = 'admin', { enrolled = true } = {}) {
    username = String(username || '').trim().toLowerCase();
    if (!/^[a-z0-9_.-]{3,32}$/.test(username) && !/^[a-z0-9._%+-]{1,64}@[a-z0-9.-]+\.[a-z]{2,24}$/.test(username)) throw new Error('Admin login must be an email address or 3–32 chars a-z 0-9 . _ -');
    if (!ROLES[role]) throw new Error('Role must be viewer, admin or owner');
    const prob = passwordProblem(password); if (prob) throw new Error(prob);
    if (await adminStore.getAdmin(username)) throw new Error('Admin already exists');
    const secret = newTotpSecret();
    await adminStore.createAdmin({ username, pwHash: await hashPassword(password), totpEnc: box.seal(secret, 'totp|' + username), role, enrolled });
    return { username, role, totpSecret: secret, otpauth: otpauthUrl('QChat Admin', username, secret) };
  }

  async function handle(req, res, url, ip) {
    if (process.env.ADMIN_IPS && !process.env.ADMIN_IPS.split(',').map((x) => x.trim()).includes(ip)) return deny(res, req, 404, 'not found');
    const ipHash = sec.ipHash(ip);
    // ---- static pages ----
    if (url.pathname === '/admin' || url.pathname === '/admin/') { res.writeHead(200, { ...baseHeaders(req), 'content-type': 'text/html; charset=utf-8', 'content-security-policy': ctx.CSP, 'cache-control': 'no-store' }); return res.end(await html('admin.html')); }
    if (url.pathname === '/admin/admin.js') { res.writeHead(200, { ...baseHeaders(req), 'content-type': 'text/javascript; charset=utf-8', 'cache-control': 'no-store' }); return res.end(await html('admin.js')); }
    if (!url.pathname.startsWith('/admin/api/')) return deny(res, req, 404, 'not found');

    // ---- CSRF: API calls must carry a custom header (impossible cross-site without CORS) and a same-origin Origin ----
    if (req.headers['x-qchat-admin'] !== '1') { await sec.event('admin_csrf_blocked', 'high', { ip, detail: { path: url.pathname } }); return deny(res, req, 403, 'forbidden'); }
    if (req.headers.origin) { try { if (new URL(req.headers.origin).host !== req.headers.host) { await sec.event('admin_csrf_blocked', 'high', { ip, detail: { origin: String(req.headers.origin).slice(0, 80) } }); return deny(res, req, 403, 'forbidden'); } } catch { return deny(res, req, 403, 'forbidden'); } }
    const json = (o, code = 200, extra = {}) => { res.writeHead(code, { ...baseHeaders(req), 'content-type': 'application/json', 'cache-control': 'no-store', ...extra }); res.end(JSON.stringify(o)); };
    const route = url.pathname.slice('/admin/api/'.length);

    // ---- login (rate-limited, lockout, 2FA, generic errors) ----
    if (route === 'login' && req.method === 'POST') {
      if (!(await sec.allow('adminlogin:' + ip, 10, 900))) { await sec.strike(ip, 10, 'admin_bruteforce'); return json({ error: 'Too many attempts. Try again later.' }, 429); }
      const b = await readJson(req).catch(() => ({}));
      const admin = await adminStore.getAdmin(String(b.username || '').toLowerCase());
      const fail = async (why) => {
        await sec.event('admin_auth_failed', 'high', { ip, detail: { username: String(b.username || '').slice(0, 40), why } }); await sec.strike(ip, 5, 'admin_auth_failed');
        if (admin) { const f = Number(admin.failed) + 1; await adminStore.updateAdmin(admin.id, { failed: f, locked_until: f >= LOGIN_FAILS ? Date.now() + LOGIN_LOCK : 0 }); }
        return json({ error: 'Wrong username, password or code' }, 401);
      };
      if (!admin) { await hashPassword('timing-equaliser'); return fail('unknown_admin'); }
      if (Number(admin.disabled)) return fail('disabled');
      if (Number(admin.locked_until) > Date.now()) { await sec.event('admin_login_locked', 'high', { ip, detail: { username: admin.username } }); return json({ error: 'Account temporarily locked after failed attempts. Try again in 15 minutes.' }, 423); }
      if (!(await verifyPassword(String(b.password || ''), admin.pw_hash))) return fail('bad_password');
      const secret = box.open(admin.totp_enc, 'totp|' + admin.username);
      if (!Number(admin.totp_enrolled) && !b.code) { // first sign-in: show the authenticator QR, require one valid code before any session exists
        await sec.event('admin_2fa_setup_started', 'medium', { ip, detail: { username: admin.username } });
        return json({ setup2fa: true, otpauth: otpauthUrl('QChat Admin', admin.username, secret), secret });
      }
      if (!b.code) return json({ needCode: true, error: 'Enter the 6-digit code from your authenticator app' }, 401);
      const step = verifyTotp(secret, b.code, Number(admin.totp_last));
      if (step < 0) return fail('bad_totp');
      if (!Number(admin.totp_enrolled)) { await adminStore.updateAdmin(admin.id, { totp_enrolled: 1 }); await adminStore.audit(admin.username, 'enrolled_2fa', null, {}, ipHash); }
      await adminStore.updateAdmin(admin.id, { failed: 0, locked_until: 0, last_login: Date.now(), totp_last: step });
      const tok = crypto.randomBytes(32).toString('base64url');
      await adminStore.createSession({ tokenHash: sha(tok), adminId: admin.id, expires: Date.now() + SESSION_ABS, ipHash, ua: String(req.headers['user-agent'] || '').slice(0, 160) });
      await adminStore.audit(admin.username, 'login', null, {}, ipHash);
      return json({ ok: true, username: admin.username, role: admin.role }, 200, { 'set-cookie': cookie(req, tok, SESSION_ABS) });
    }

    const s = await session(req);
    if (!s) return json({ error: 'Not signed in' }, 401);
    const me = s.admin, role = ROLES[me.role] || 0;
    const need = (r) => { if (role < ROLES[r]) { json({ error: 'Your role does not allow this' }, 403); return false; } return true; };
    const audit = (action, target, detail) => adminStore.audit(me.username, action, target, detail, ipHash);
    const body = req.method === 'POST' ? await readJson(req, 8192).catch(() => ({})) : {};

    if (route === 'logout' && req.method === 'POST') { await adminStore.deleteSession(s.tokenHash); await audit('logout'); return json({ ok: true }, 200, { 'set-cookie': cookie(req, 'x'.repeat(20), 0) }); }
    if (route === 'me') return json({ username: me.username, role: me.role });
    if (route === 'password' && req.method === 'POST') { // change own password: needs current password + a fresh 2FA code
      if (!(await sec.allow('adminpw:' + me.id, 5, 900))) return json({ error: 'Too many attempts. Try again later.' }, 429);
      if (!(await verifyPassword(String(body.current || ''), me.pw_hash))) { await sec.event('admin_auth_failed', 'high', { ip, detail: { username: me.username, why: 'password_change_wrong_current' } }); return json({ error: 'Current password is wrong' }, 400); }
      const step = verifyTotp(box.open(me.totp_enc, 'totp|' + me.username), body.code, Number(me.totp_last));
      if (step < 0) return json({ error: 'Authenticator code is wrong' }, 400);
      if (String(body.password) === String(body.current)) return json({ error: 'Choose a different password' }, 400);
      const prob = passwordProblem(body.password); if (prob) return json({ error: prob }, 400);
      await adminStore.updateAdmin(me.id, { pw_hash: await hashPassword(body.password), totp_last: step });
      await adminStore.deleteSessionsFor(me.id); // sign out everywhere, including this browser
      await audit('change_password', me.username);
      await sec.event('admin_password_changed', 'medium', { ip, detail: { username: me.username } });
      return json({ ok: true }, 200, { 'set-cookie': cookie(req, 'x'.repeat(20), 0) });
    }

    // ---- overview & analytics ----
    if (route === 'overview') {
      const from = day(Date.now() - 29 * 864e5);
      const [totals, series, status, secCounts, names, top, sessions] = await Promise.all([store.totals(), adminStore.statsSeries(from), monitor.status(), adminStore.securityCounts(Date.now() - 7 * 864e5), store.deviceNames(), adminStore.topSenders(from, 10), Promise.resolve(null)]);
      const days = Array.from({ length: 30 }, (_, i) => day(Date.now() - (29 - i) * 864e5));
      const metric = (m) => days.map((d) => series.stats.find((x) => x.day === d && x.metric === m)?.value || 0);
      const created = await store.userCreatedSince(Date.now() - 30 * 864e5);
      const platforms = {}; for (const n of names) { const os = (/ on (\w+)/.exec(n) || [])[1] || 'Other'; const br = (/^(\w+)/.exec(n) || [])[1] || 'Other'; platforms[os] = platforms[os] || {}; platforms[os][br] = (platforms[os][br] || 0) + 1; }
      const online = status.instances.reduce((a, i) => a + i.users, 0), connections = status.instances.reduce((a, i) => a + i.connections, 0);
      return json({
        totals: { ...totals, onlineUsers: online, connections, pinAdoption: totals.users ? Math.round((totals.pinUsers / totals.users) * 100) : 0 },
        days, charts: {
          newUsers: days.map((d) => created.filter((t) => day(t) === d).length), dau: days.map((d) => series.dau.find((x) => x.day === d)?.n || 0),
          messages: metric('messages'), deliveries: metric('deliveries'), mb: metric('bytes').map((b) => Math.round(b / 1048576 * 10) / 10), logins: metric('logins'),
        },
        platforms, topSenders: top, security7d: secCounts, status,
      });
    }
    if (route === 'status') return json(await monitor.status());

    // ---- users ----
    if (route === 'users' && req.method === 'GET') {
      const page = Math.max(0, Number(url.searchParams.get('page')) || 0), limit = 50;
      const { total, users } = await store.listUsers({ q: url.searchParams.get('q') || '', status: url.searchParams.get('status') || '', sort: url.searchParams.get('sort') || 'created', limit, offset: page * limit });
      const counts = await store.countsFor(users.map((u) => u.username));
      const rows = await Promise.all(users.map(async (u) => ({
        username: u.username, displayName: u.profile.displayName, createdAt: u.createdAt, lastSeen: u.lastSeen, online: (await onlineDevices(u.username)).length > 0,
        devices: counts[u.username]?.devices || 0, pin: !!counts[u.username]?.pin, reports: counts[u.username]?.reports || 0, suspendedUntil: u.suspendedUntil > Date.now() ? u.suspendedUntil : 0,
      })));
      await audit('list_users', null, { q: url.searchParams.get('q') || '', page });
      return json({ total, page, pageSize: limit, users: rows });
    }
    const um = route.match(/^users\/([a-z0-9_.]{3,24})(?:\/([a-z_]+))?(?:\/([0-9a-f]{16}))?$/);
    if (um) {
      const [, uname, action, devId] = um;
      const user = await store.getUser(uname);
      if (!user) return json({ error: 'No such user' }, 404);
      if (!action && req.method === 'GET') {
        const devices = await store.getDevices(uname); const online = await onlineDevices(uname);
        const [activity, security, reports, series, activeDays, pin] = await Promise.all([adminStore.listActivity({ username: uname, limit: 300 }), adminStore.listSecurityEvents({ username: uname, limit: 200 }), store.listReports(uname), adminStore.userSeries(uname, day(Date.now() - 29 * 864e5)), adminStore.activeDays(uname), store.getPin(uname)]);
        await audit('view_user', uname);
        return json({
          username: uname, profile: user.profile, createdAt: user.createdAt, lastSeen: user.lastSeen, hideLastSeen: user.hideLastSeen, suspendedUntil: user.suspendedUntil > Date.now() ? user.suspendedUntil : 0, suspendReason: user.suspendReason,
          devices: devices.filter((d) => user.deviceList.devices.includes(d.device)).map((d) => ({ device: d.device, name: d.cert.name || '', created: d.cert.created, online: online.includes(d.device), push: !!d.push })),
          pin: pin ? { enabled: true, failedAttempts: pin.attempts, lockedUntil: pin.lockedUntil } : { enabled: false },
          reports, activeDays, messagesPerDay: series,
          timeline: [...activity.map((a) => ({ ...a, kind: 'activity' })), ...security.map((e) => ({ ts: e.ts, type: e.type, severity: e.severity, detail: e.detail, ipHash: e.ipHash, kind: 'security' }))].sort((a, b) => b.ts - a.ts).slice(0, 400),
        });
      }
      if (req.method !== 'POST') return json({ error: 'Method not allowed' }, 405);
      if (!need('admin')) return;
      const reason = String(body.reason || '').slice(0, 200);
      switch (action) {
        case 'suspend': {
          const hours = Math.min(Math.max(Number(body.hours) || 0, 0), 24 * 3650); const until = hours ? Date.now() + hours * 3600e3 : Date.now() + 100 * 365 * 864e5;
          await store.setSuspension(uname, until, reason); await kickUser(uname, 'suspended');
          await adminStore.addActivity({ username: uname, type: 'suspended_by_admin', detail: { by: me.username, until, reason } }); await audit('suspend', uname, { hours, reason });
          return json({ ok: true, suspendedUntil: until });
        }
        case 'unsuspend': await store.setSuspension(uname, 0, null); await adminStore.addActivity({ username: uname, type: 'unsuspended_by_admin', detail: { by: me.username } }); await audit('unsuspend', uname); return json({ ok: true });
        case 'logout': await kickUser(uname, 'admin_logout'); await adminStore.addActivity({ username: uname, type: 'signed_out_by_admin', detail: { by: me.username } }); await audit('force_logout', uname); return json({ ok: true });
        case 'remove_device': {
          if (!devId) return json({ error: 'device required' }, 400);
          await store.removeDevice(uname, devId); await kickDevice(uname, devId, 'removed');
          await adminStore.addActivity({ username: uname, type: 'device_removed_by_admin', detail: { by: me.username, device: devId } }); await audit('remove_device', uname, { device: devId });
          return json({ ok: true });
        }
        case 'reset_pin': await store.deletePin(uname); await adminStore.addActivity({ username: uname, type: 'pin_reset_by_admin', detail: { by: me.username } }); await audit('reset_pin', uname); return json({ ok: true });
        case 'clear_reports': await store.clearReports(uname); await audit('clear_reports', uname); return json({ ok: true });
        case 'delete': {
          if (!need('owner')) return;
          if (body.confirm !== uname) return json({ error: 'Type the username to confirm' }, 400);
          await kickUser(uname, 'deleted'); await store.deleteUser(uname); await adminStore.forgetUser(uname); await audit('delete_account', uname, { reason });
          return json({ ok: true });
        }
      }
      return json({ error: 'Unknown action' }, 400);
    }

    // ---- security ----
    if (route === 'events') return json(await adminStore.listSecurityEvents({ since: Number(url.searchParams.get('since') || 0), limit: url.searchParams.get('limit') || 200, minSeverity: url.searchParams.get('minSeverity') || undefined, username: url.searchParams.get('user') || undefined }));
    if (route === 'activity') return json(await adminStore.listActivity({ limit: url.searchParams.get('limit') || 200 }));
    if (route === 'bans' && req.method === 'GET') return json(await sec.listBans());
    if (route === 'unban' && req.method === 'POST') { if (!need('admin')) return; await sec.unban(String(body.ip)); await audit('unban', String(body.ip)); return json({ ok: true }); }
    if (route === 'ban' && req.method === 'POST') { if (!need('admin')) return; await sec.ban(String(body.ip), Number(body.seconds) || 3600, 'admin'); await audit('ban', String(body.ip), { seconds: body.seconds }); return json({ ok: true }); }

    // ---- owner only: audit trail & admin accounts ----
    if (route === 'audit') { if (!need('owner')) return; return json(await adminStore.listAudit(300)); }
    if (route === 'admins' && req.method === 'GET') { if (!need('owner')) return; return json(await adminStore.listAdmins()); }
    if (route === 'admins' && req.method === 'POST') {
      if (!need('owner')) return;
      try { const r = await addAdmin(body.username, body.password, body.role); await audit('create_admin', r.username, { role: r.role }); return json(r); } catch (e) { return json({ error: e.message }, 400); }
    }
    const am = route.match(/^admins\/(\d+)\/(disable|enable)$/);
    if (am && req.method === 'POST') {
      if (!need('owner')) return;
      if (Number(am[1]) === Number(me.id)) return json({ error: "You can't disable yourself" }, 400);
      await adminStore.updateAdmin(Number(am[1]), { disabled: am[2] === 'disable' ? 1 : 0 }); if (am[2] === 'disable') await adminStore.deleteSessionsFor(Number(am[1]));
      await audit(am[2] + '_admin', am[1]); return json({ ok: true });
    }
    return json({ error: 'Not found' }, 404);
  }
  return { handle, addAdmin };
}
