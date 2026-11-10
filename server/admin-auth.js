// Admin authentication primitives: scrypt passwords, RFC 6238 TOTP (authenticator apps), encrypted TOTP secrets.
import crypto from 'node:crypto';

const SCRYPT = { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
export async function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const h = await new Promise((res, rej) => crypto.scrypt(pw, salt, 64, SCRYPT, (e, k) => (e ? rej(e) : res(k))));
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString('base64')}$${h.toString('base64')}`;
}
export async function verifyPassword(pw, stored) {
  const [alg, N, r, p, salt, hash] = String(stored).split('$');
  if (alg !== 'scrypt') return false;
  const want = Buffer.from(hash, 'base64');
  const got = await new Promise((res, rej) => crypto.scrypt(String(pw), Buffer.from(salt, 'base64'), want.length, { N: +N, r: +r, p: +p, maxmem: 64 * 1024 * 1024 }, (e, k) => (e ? rej(e) : res(k))));
  return crypto.timingSafeEqual(got, want);
}
export function passwordProblem(pw) {
  if (typeof pw !== 'string' || pw.length < 12) return 'Use at least 12 characters';
  if (pw.length > 200) return 'Too long';
  if (!/[a-z]/i.test(pw) || !/\d|[^a-z0-9]/i.test(pw)) return 'Mix letters with numbers or symbols';
  return null;
}

// ---- TOTP (Google Authenticator, Authy, 1Password, …) ----
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export function base32(buf) { let bits = 0, val = 0, out = ''; for (const b of buf) { val = (val << 8) | b; bits += 8; while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; } } if (bits) out += B32[(val << (5 - bits)) & 31]; return out; }
export function unbase32(s) { let bits = 0, val = 0; const out = []; for (const c of s.replace(/=+$/, '').toUpperCase()) { const i = B32.indexOf(c); if (i < 0) continue; val = (val << 5) | i; bits += 5; if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; } } return Buffer.from(out); }
export const newTotpSecret = () => base32(crypto.randomBytes(20));
export function totpAt(secretB32, step) {
  const msg = Buffer.alloc(8); msg.writeBigUInt64BE(BigInt(step));
  const h = crypto.createHmac('sha1', unbase32(secretB32)).update(msg).digest();
  const o = h[h.length - 1] & 15;
  return String(((h.readUInt32BE(o) & 0x7fffffff) % 1e6)).padStart(6, '0');
}
/** Returns the matching time-step (to block replays) or -1. Accepts ±1 step of clock drift. */
export function verifyTotp(secretB32, code, lastStep = 0) {
  if (!/^\d{6}$/.test(String(code || ''))) return -1;
  const now = Math.floor(Date.now() / 30000);
  for (const s of [now, now - 1, now + 1]) if (s > lastStep && crypto.timingSafeEqual(Buffer.from(totpAt(secretB32, s)), Buffer.from(String(code)))) return s;
  return -1;
}
export const otpauthUrl = (issuer, account, secret) => `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(account)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;

// ---- secret-at-rest encryption for TOTP seeds (key from ADMIN_SECRET_KEY, never stored with the data) ----
export function secretBox(keyMaterial) {
  const key = Buffer.from(crypto.hkdfSync('sha256', Buffer.from(keyMaterial), 'qchat-admin', 'qchat-admin-secrets-v1', 32));
  return {
    seal(text, aad) { const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', key, iv); c.setAAD(Buffer.from(aad)); return Buffer.concat([iv, c.update(text, 'utf8'), c.final(), c.getAuthTag()]).toString('base64'); },
    open(b64, aad) { const b = Buffer.from(b64, 'base64'), d = crypto.createDecipheriv('aes-256-gcm', key, b.subarray(0, 12)); d.setAAD(Buffer.from(aad)); d.setAuthTag(b.subarray(b.length - 16)); return Buffer.concat([d.update(b.subarray(12, b.length - 16)), d.final()]).toString('utf8'); },
  };
}
export const ROLES = { viewer: 1, admin: 2, owner: 3 };
