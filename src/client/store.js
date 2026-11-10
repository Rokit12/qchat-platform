// Encrypted local storage. Every value in IndexedDB is AES-256-GCM encrypted with a data key (DEK).
// The DEK is wrapped either by a non-extractable device key (no passcode) or by an Argon2id-derived
// key from the user's passcode. With a passcode set, nothing readable is left on disk when locked.
import { rand, te, td, passcodeKey, aesEncrypt, aesDecrypt, subtle } from '../shared/crypto.js';

const DB = 'qchat2';
let db, dek = null, dekRaw = null, closing = false;

function req(r) { return new Promise((res, rej) => { r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); }); }
function txn(store, mode, fn) {
  if (closing) return Promise.resolve(undefined); // device is being wiped: drop late writes
  return new Promise((res, rej) => {
    const t = db.transaction(store, mode); const r = fn(t.objectStore(store));
    t.oncomplete = () => res(r && 'result' in r ? r.result : undefined); t.onerror = () => rej(t.error); t.onabort = () => rej(t.error);
  });
}
export async function openDb() {
  closing = false;
  const r = indexedDB.open(DB, 1);
  r.onupgradeneeded = () => { r.result.createObjectStore('kv'); r.result.createObjectStore('meta'); };
  db = await req(r);
}
const metaGet = (k) => txn('meta', 'readonly', (s) => s.get(k));
const metaSet = (k, v) => txn('meta', 'readwrite', (s) => s.put(v, k));
export const getPlain = metaGet, setPlain = metaSet; // non-secret local prefs (e.g. auto-lock minutes)

async function useDek(raw) { dekRaw = raw; dek = await subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']); }

/** Returns 'new' | 'unlocked' | 'locked' */
export async function keyState() {
  const k = await metaGet('keys');
  if (!k) return 'new';
  if (k.device) { const raw = await aesDecryptWith(k.device, k.iv, k.wrapped); await useDek(raw); return 'unlocked'; }
  return 'locked';
}
async function aesDecryptWith(cryptoKey, iv, ct) { return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv }, cryptoKey, ct)); }
async function aesEncryptWith(cryptoKey, pt) { const iv = rand(12); return { iv, ct: new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, pt)) }; }

async function wrapWithDeviceKey(raw) {
  const device = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  const { iv, ct } = await aesEncryptWith(device, raw);
  await metaSet('keys', { device, iv, wrapped: ct });
}
export async function createKeys() { const raw = rand(32); await wrapWithDeviceKey(raw); await useDek(raw); }
export async function hasPasscode() { return !!(await metaGet('keys'))?.salt; }
export async function setPasscode(code) {
  if (!dekRaw) throw new Error('locked');
  if (!code) return wrapWithDeviceKey(dekRaw);
  const salt = rand(16); const kek = await passcodeKey(code, salt);
  const { iv, ct } = await aesEncrypt(kek, dekRaw, te.encode('qchat-dek'));
  await metaSet('keys', { salt, iv, wrapped: ct });
}
export async function unlock(code) {
  const k = await metaGet('keys');
  const kek = await passcodeKey(code, k.salt);
  try { await useDek(await aesDecrypt(kek, k.iv, k.wrapped, te.encode('qchat-dek'))); return true; } catch { return false; }
}

// ----- encrypted key/value -----
async function enc(key, bytes) { const iv = rand(12); const ct = await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: te.encode(key) }, dek, bytes); return { iv, ct }; }
async function dec(key, rec) { return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: rec.iv, additionalData: te.encode(key) }, dek, rec.ct)); }
export async function get(key) { const r = await txn('kv', 'readonly', (s) => s.get(key)); return r ? JSON.parse(td.decode(await dec(key, r))) : undefined; }
export async function set(key, val) { const r = await enc(key, te.encode(JSON.stringify(val))); await txn('kv', 'readwrite', (s) => s.put(r, key)); }
export async function del(key) { await txn('kv', 'readwrite', (s) => s.delete(key)); }
export async function keys(prefix) { const all = await txn('kv', 'readonly', (s) => s.getAllKeys()); return all.filter((k) => k.startsWith(prefix)); }
export async function putBytes(key, bytes, mime) { const r = await enc(key, bytes); r.mime = mime; await txn('kv', 'readwrite', (s) => s.put(r, key)); }
export async function getBytes(key) { const r = await txn('kv', 'readonly', (s) => s.get(key)); return r ? { bytes: await dec(key, r), mime: r.mime } : null; }
export async function wipe() { closing = true; db?.close(); await req(indexedDB.deleteDatabase(DB)).catch(() => {}); }
