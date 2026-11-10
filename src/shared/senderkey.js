// Sender keys for large groups (up to 3,500 members).
//
// Pairwise encryption costs one key-wrap per member device per message, which is fine for small groups
// but makes a message to 3,500 people huge. With sender keys each member device has one symmetric chain
// per group:
//   - the chain key (CK) is delivered to every other member device inside the post-quantum double ratchet;
//   - each message uses mk = HMAC(CK, 1), then CK = HMAC(CK, 2) (forward secrecy within the chain);
//   - the message is AES-256-GCM encrypted ONCE and signed with the sender's ML-DSA-65 device key, so other
//     members (who also hold CK) still can't forge messages in someone else's name.
// The chain is replaced ("rotated") whenever someone leaves or is removed, so they can't read new messages.
import { hmac, sha256, kdf, b64, unb64, rand, randId, te, td, stable, aesEncrypt, aesDecrypt, ml_dsa65 } from './crypto.js';

export const SK_MAX_SKIP = 2000;
const stepMk = (ck) => hmac(sha256, ck, new Uint8Array([1]));
const stepCk = (ck) => hmac(sha256, ck, new Uint8Array([2]));
const msgKey = (mk, g) => kdf(mk, 'qchat-gmsg', 'qchat-gmsg-v1|' + g, 32);
const aadFor = (e) => te.encode(`qchat-env-v3|${e.id}|${e.from}|${e.fd}|${e.g}|${e.kid}|${e.n}`);
export const groupDigest = (e) => sha256(te.encode('qchat-env-v3\n' + stable({ v: e.v, from: e.from, fd: e.fd, id: e.id, g: e.g, kid: e.kid, n: e.n, iv: e.iv, ct: e.ct })));

/** A fresh sending chain. `hist` keeps recent chain keys so late joiners/requesters can catch up on recent messages. */
export function newSenderKey() { return { kid: randId(8), ck: b64(rand(32)), n: 0, created: Date.now(), hist: {} }; }

/** Distribution payload for a member device: the chain from message `n` onwards. */
export function exportSenderKey(st, fromN) {
  if (fromN != null && fromN < st.n && st.hist[fromN]) return { kid: st.kid, ck: st.hist[fromN], n: fromN };
  return { kid: st.kid, ck: st.ck, n: st.n };
}

/** Encrypt + sign one group payload. Mutates `st` (advance the chain). */
export async function sealGroup(me, id, g, st, payload) {
  const ck = unb64(st.ck);
  st.hist[st.n] = st.ck; // keep a short history (max 500) for catch-up requests
  const keys = Object.keys(st.hist); if (keys.length > 500) for (const k of keys.slice(0, keys.length - 500)) delete st.hist[k];
  const env = { v: 3, from: me.user, fd: me.device, id, g, kid: st.kid, n: st.n };
  const { iv, ct } = await aesEncrypt(msgKey(stepMk(ck), g), te.encode(JSON.stringify(payload)), aadFor(env));
  st.ck = b64(stepCk(ck)); st.n++;
  env.iv = b64(iv); env.ct = b64(ct);
  env.sig = b64(ml_dsa65.sign(groupDigest(env), me.sigSk));
  return env;
}

/** Receiver chains for one sender device: { [kid]: { ck, n, skipped: {n: mk}, t } } */
export function storeReceivedKey(rs, k) {
  rs = rs || {};
  const cur = rs[k.kid];
  if (!cur || k.n < cur.n) rs[k.kid] = { ck: k.ck, n: k.n, skipped: cur?.skipped || {}, t: Date.now() }; // keep the earliest position we know
  const kids = Object.entries(rs).sort((a, b) => b[1].t - a[1].t);
  for (const [kid] of kids.slice(4)) delete rs[kid]; // keep the 4 most recent chains per sender device
  return rs;
}

/** Verify + decrypt. Returns {payload, rs (updated clone)} or throws ('no sender key' → ask the sender). */
export async function openGroup(env, senderSigPk, rs) {
  if (!env || env.v !== 3 || typeof env.g !== 'string' || !Number.isInteger(env.n) || env.n < 0) throw new Error('bad group envelope');
  if (!ml_dsa65.verify(unb64(env.sig), groupDigest(env), unb64(senderSigPk))) throw new Error('bad signature');
  const s = JSON.parse(JSON.stringify(rs || {}));
  const ch = s[env.kid];
  if (!ch) throw new Error('no sender key');
  let mk;
  if (env.n < ch.n) {
    const sk = ch.skipped[env.n];
    if (!sk) throw new Error(env.n < ch.n - SK_MAX_SKIP ? 'no sender key' : 'duplicate or replayed message');
    mk = unb64(sk); delete ch.skipped[env.n];
  } else {
    if (env.n - ch.n > SK_MAX_SKIP) throw new Error('too many skipped messages');
    let ck = unb64(ch.ck);
    while (ch.n < env.n) { ch.skipped[ch.n] = b64(stepMk(ck)); ck = stepCk(ck); ch.n++; }
    mk = stepMk(ck); ch.ck = b64(stepCk(ck)); ch.n++;
    const sk = Object.keys(ch.skipped); if (sk.length > SK_MAX_SKIP) for (const k of sk.slice(0, sk.length - SK_MAX_SKIP)) delete ch.skipped[k];
  }
  ch.t = Date.now();
  const pt = await aesDecrypt(msgKey(mk, env.g), unb64(env.iv), unb64(env.ct), aadFor(env));
  return { payload: JSON.parse(td.decode(pt)), rs: s };
}
