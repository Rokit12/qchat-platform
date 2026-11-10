// PIN login: recover the account seeds with a 6-digit PIN instead of the recovery key.
//
// A 6-digit PIN has only 10^6 possibilities, so it is never enough on its own:
//   pinKey  = Argon2id(PIN, salt, 64 MiB, t=3)            (slow on purpose)
//   auth    = HKDF(pinKey, "auth")   → server keeps only HMAC(PEPPER, auth) as a verifier
//   enc     = HKDF(pinKey, "enc")
//   share   = 32 random bytes, kept by the server (encrypted with its PEPPER), released only after a correct PIN
//   blob    = AES-256-GCM( HKDF(enc ‖ share), recovery seeds )
// The server enforces the guess limit (lockouts, then permanent wipe after 10 wrong PINs), and the
// stored database alone is useless without the server's PEPPER. See SECURITY.md §PIN login.
import { argon2idAsync } from '@noble/hashes/argon2.js';
import { te, kdf, concat, aesEncrypt, aesDecrypt, b64, unb64 } from './crypto.js';

export const PIN_KDF = { t: 3, m: 65536, p: 1 };
export const PIN_RE = /^\d{6}$/;

export async function pinKeys(pin, salt) {
  const k = await argon2idAsync(te.encode(String(pin)), salt, { ...PIN_KDF, dkLen: 32, asyncTick: 25 });
  return { auth: kdf(k, salt, 'qchat-pin-auth-v1'), enc: kdf(k, salt, 'qchat-pin-enc-v1') };
}
const blobKey = (enc, share, user) => kdf(concat(enc, share), 'qchat-pin-blob', 'qchat-pin-blob-v1|' + user);
export async function sealSeeds(seeds, enc, share, user) {
  const { iv, ct } = await aesEncrypt(blobKey(enc, share, user), seeds, te.encode('qchat-pin|' + user));
  return { iv: b64(iv), ct: b64(ct) };
}
export async function openSeeds(blob, enc, share, user) {
  return aesDecrypt(blobKey(enc, share, user), unb64(blob.iv), unb64(blob.ct), te.encode('qchat-pin|' + user));
}

// Reject PINs that attackers try first.
const COMMON = new Set(['123456', '654321', '123123', '121212', '112233', '123321', '111222', '696969', '102030', '520520', '147258', '159753', '789456', '456789', '987654', '000111', '101010', '202020', '131313', '777888', '222333']);
export function weakPin(pin) {
  if (!PIN_RE.test(pin)) return 'Use exactly 6 digits';
  if (/^(\d)\1{5}$/.test(pin)) return 'Avoid repeating the same digit';
  const d = [...pin].map(Number); const steps = d.slice(1).map((x, i) => x - d[i]);
  if (steps.every((s) => s === 1) || steps.every((s) => s === -1)) return 'Avoid number sequences like 123456';
  if (COMMON.has(pin)) return 'That PIN is too common — pick something less predictable';
  if (/^(\d\d)\1\1$/.test(pin) || /^(\d{3})\1$/.test(pin)) return 'Avoid repeating patterns';
  if (/^(19|20)\d\d(0[1-9]|1[0-2])$/.test(pin)) return 'Avoid dates like birth years';
  return null;
}
