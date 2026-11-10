// Sign in to the admin API like the dashboard does (password + TOTP, CSRF header, session cookie).
import { totpAt } from '../server/admin-auth.js';
export const BOOT = { ADMIN_BOOTSTRAP_USER: 'admin@qchat.test', ADMIN_BOOTSTRAP_PASSWORD: 'Test-admin-pass-2026!' };
const H = { 'x-qchat-admin': '1', 'content-type': 'application/json' };
export async function adminLogin(port, user = BOOT.ADMIN_BOOTSTRAP_USER, password = BOOT.ADMIN_BOOTSTRAP_PASSWORD) {
  const post = (body) => fetch(`http://localhost:${port}/admin/api/login`, { method: 'POST', headers: H, body: JSON.stringify(body) });
  const first = await (await post({ username: user, password })).json();
  if (!first.setup2fa) throw new Error('expected 2FA setup: ' + JSON.stringify(first));
  const code = totpAt(first.secret, Math.floor(Date.now() / 30000));
  const r = await post({ username: user, password, code });
  const cookie = (r.headers.get('set-cookie') || '').split(';')[0];
  const body = await r.json(); if (!body.ok) throw new Error('login failed: ' + JSON.stringify(body));
  const api = async (p, opts = {}) => { const res = await fetch(`http://localhost:${port}/admin/api/${p}`, { method: opts.method || 'GET', headers: { ...H, cookie }, body: opts.body ? JSON.stringify(opts.body) : undefined }); return { status: res.status, body: await res.json().catch(() => ({})), headers: res.headers }; };
  return { cookie, secret: first.secret, api, rawSetCookie: r.headers.get('set-cookie') };
}
