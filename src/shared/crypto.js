// Shared post-quantum crypto primitives (browser + Node). See PROTOCOL.md.
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { argon2idAsync } from '@noble/hashes/argon2.js';

export { ml_kem768, ml_dsa65, sha256, hmac };
export const te = new TextEncoder(), td = new TextDecoder();
export const subtle = globalThis.crypto.subtle;
export const rand = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));
export const randId = (n = 8) => hex(rand(n));

export function b64(u8) { let s = ''; for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000)); return btoa(s); }
export function unb64(s) { const bin = atob(String(s ?? '')); const u = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return u; }
export const b64url = (u8) => b64(u8).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
export const unb64url = (s) => unb64(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4));
export const hex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('');
export function concat(...a) { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of a) { o.set(x, i); i += x.length; } return o; }
export const xor = (a, b) => { if (a.length !== b.length) throw new Error('xor length'); return a.map((x, i) => x ^ b[i]); };
export function ctEqual(a, b) { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i]; return d === 0; }
export const kdf = (ikm, salt, info, len = 32) => hkdf(sha256, ikm, typeof salt === 'string' ? te.encode(salt) : salt, te.encode(info), len);

// Deterministic JSON (sorted keys) so signatures survive any storage/transport that reorders keys.
export function stable(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(stable).join(',') + ']';
  return '{' + Object.keys(v).filter((k) => v[k] !== undefined).sort().map((k) => JSON.stringify(k) + ':' + stable(v[k])).join(',') + '}';
}
const signBytes = (domain, obj) => te.encode(domain + '\n' + stable(obj));
export const dsaSign = (domain, obj, sk) => b64(ml_dsa65.sign(signBytes(domain, obj), sk));
export function dsaVerify(domain, obj, sigB64, pkB64) {
  try { return ml_dsa65.verify(unb64(sigB64), signBytes(domain, obj), unb64(pkB64)); } catch { return false; }
}

// ---------- AES-256-GCM ----------
export async function aesEncrypt(key32, plaintext, aad) {
  const iv = rand(12);
  const k = await subtle.importKey('raw', key32, 'AES-GCM', false, ['encrypt']);
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad || new Uint8Array() }, k, plaintext));
  return { iv, ct };
}
export async function aesDecrypt(key32, iv, ct, aad) {
  const k = await subtle.importKey('raw', key32, 'AES-GCM', false, ['decrypt']);
  return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad || new Uint8Array() }, k, ct));
}

// ---------- account identity & recovery key ----------
// Recovery key = 32-byte ML-DSA seed (account identity key, AIK) + 64-byte backup seed, plus checksum.
export function newAccountSeeds() { return { aikSeed: rand(32), backupSeed: rand(64) }; }
export function accountKeys({ aikSeed, backupSeed }) {
  const k = ml_dsa65.keygen(aikSeed);
  return { aikPk: k.publicKey, aikSk: k.secretKey, backupKey: kdf(concat(aikSeed, backupSeed), 'qchat-salt', 'qchat-backup-v1') };
}
export function makeRecoveryKey({ aikSeed, backupSeed }) {
  const body = concat(aikSeed, backupSeed);
  return 'QC1-' + b64url(concat(body, sha256(body).subarray(0, 4)));
}
export function parseRecoveryKey(s) {
  s = String(s).replace(/\s+/g, '');
  if (!s.startsWith('QC1-')) throw new Error('Not a QChat recovery key');
  const raw = unb64url(s.slice(4));
  if (raw.length !== 100) throw new Error('Recovery key is the wrong length');
  const body = raw.subarray(0, 96);
  if (!ctEqual(sha256(body).subarray(0, 4), raw.subarray(96))) throw new Error('Recovery key checksum failed — check for typos');
  return { aikSeed: body.slice(0, 32), backupSeed: body.slice(32, 96) };
}

// ---------- devices ----------
// Every device has its own ML-DSA-65 signing key, certified by the account identity key.
export function newDevice() {
  const k = ml_dsa65.keygen(rand(32));
  return { device: randId(8), sigPk: b64(k.publicKey), sigSk: b64(k.secretKey) };
}
export function makeCert(user, dev, aikSk, name = '') {
  const c = { user, device: dev.device, sigPk: dev.sigPk, created: Date.now(), name: String(name).slice(0, 60) };
  return { ...c, sig: dsaSign('qchat-device-cert-v2', c, aikSk) };
}
export function verifyCert(cert, user, aikPkB64) {
  if (!cert || cert.user !== user) return false;
  const { sig, ...c } = cert;
  return dsaVerify('qchat-device-cert-v2', { user: c.user, device: c.device, sigPk: c.sigPk, created: c.created, name: c.name }, sig, aikPkB64);
}
// Signed, versioned device list — the server can't add devices, or roll back to an older list unnoticed.
export function makeDeviceList(user, version, devices, aikSk) {
  const l = { user, version, devices: [...new Set(devices)].sort(), ts: Date.now() };
  return { ...l, sig: dsaSign('qchat-device-list-v2', l, aikSk) };
}
export function verifyDeviceList(list, user, aikPkB64) {
  if (!list || list.user !== user || !Array.isArray(list.devices)) return false;
  const { sig, ...l } = list;
  return dsaVerify('qchat-device-list-v2', { user: l.user, version: l.version, devices: l.devices, ts: l.ts }, sig, aikPkB64);
}

// ---------- prekeys (ML-KEM-768, signed by the device key) ----------
export function makePrekey(user, device, kind, id, sigSkB64) {
  const k = ml_kem768.keygen();
  const pub = { user, device, kind, id, pk: b64(k.publicKey) };
  return { pub: { id, pk: pub.pk, sig: dsaSign('qchat-prekey-v2', pub, unb64(sigSkB64)) }, sk: b64(k.secretKey), created: Date.now() };
}
export function verifyPrekey(pk, user, device, kind, devSigPkB64) {
  return !!pk && dsaVerify('qchat-prekey-v2', { user, device, kind, id: pk.id, pk: pk.pk }, pk.sig, devSigPkB64);
}

// ---------- login ----------
export const authPayload = (user, device, nonce) => ({ user, device, nonce });
export const AUTH_DOMAIN = 'qchat-auth-v2';
export const ENROLL_DOMAIN = 'qchat-enroll-v2';

// ---------- safety number (from account identity keys; stable across devices) ----------
export function safetyNumber(userA, aikA, userB, aikB) {
  const part = (u, k) => sha256(concat(te.encode(u + '|'), unb64(k)));
  const [x, y] = [[userA, aikA], [userB, aikB]].sort((p, q) => (p[0] < q[0] ? -1 : 1));
  const h1 = sha256(concat(part(...x), part(...y))), h2 = sha256(h1), all = concat(h1, h2);
  const dv = new DataView(all.buffer);
  return Array.from({ length: 12 }, (_, i) => String(dv.getUint32(i * 4) % 100000).padStart(5, '0'));
}

// ---------- passcode KDF ----------
export async function passcodeKey(passcode, salt) {
  // Argon2id, OWASP-recommended minimum (19 MiB, t=2). Run off the critical path.
  return argon2idAsync(te.encode(passcode), salt, { t: 2, m: 19456, p: 1, dkLen: 32, asyncTick: 20 });
}

// ---------- proof of work (enrolment anti-abuse) ----------
export function leadingZeroBits(h) { let z = 0; for (const b of h) { if (b === 0) { z += 8; continue; } z += Math.clz32(b) - 24; break; } return z; }
export async function solvePow(nonce, user, device, bits) {
  if (!bits) return 0;
  for (let c = 0; ; c++) {
    if (leadingZeroBits(sha256(te.encode(`qchat-pow|${nonce}|${user}|${device}|${c}`))) >= bits) return c;
    if (c % 8192 === 8191) await new Promise((r) => setTimeout(r, 0)); // keep the UI responsive
  }
}
