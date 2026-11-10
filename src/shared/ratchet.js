// Post-quantum double ratchet (KEM ratchet + symmetric hash ratchet). See PROTOCOL.md §4.
//
// Each (local device, remote device) pair has a Session. Each direction runs independent "epochs":
//  - An epoch starts with a fresh ML-KEM-768 encapsulation: either to the remote's signed prekey
//    (+ a one-time prekey) for the first epoch ("pre"), or to the latest ratchet public key the
//    remote advertised ("rk"). The shared secret seeds a chain key.
//  - Each message advances the chain key with HMAC-SHA256 (forward secrecy within an epoch).
//  - Every side advertises a fresh ratchet key; once the remote uses it, a new one is generated
//    and the old secret is deleted shortly after (forward secrecy + post-compromise security).
import { ml_kem768, hmac, sha256, kdf, b64, unb64, rand, randId, concat, verifyPrekey } from './crypto.js';

export const MAX_SKIP = 2000;          // max messages skipped within one epoch
const KEEP_RECV_EPOCHS = 4;            // receive chains kept per session (out-of-order tolerance)
const KEEP_OLD_RATCHET = 3;            // old ratchet secrets kept per session
const SKIPPED_TTL = 7 * 864e5;         // skipped message keys expire after 7 days
const OLD_RATCHET_TTL = 7 * 864e5;

const chainInfo = (fu, fd, tu, td) => `qchat-chain-v2|${fu}|${fd}|${tu}|${td}`;
const stepMk = (ck) => hmac(sha256, ck, new Uint8Array([1]));
const stepCk = (ck) => hmac(sha256, ck, new Uint8Array([2]));

function newRatchetKey(id) { const k = ml_kem768.keygen(); return { id, pk: b64(k.publicKey), sk: b64(k.secretKey) }; }

export function newSession(ru, rd) {
  return { v: 2, ru, rd, send: null, recv: {}, theirR: null, myR: { cur: newRatchetKey(0), old: {} }, seenMine: -1, lastRecvE: null, created: Date.now() };
}
export const cloneSession = (s) => JSON.parse(JSON.stringify(s));
// True if we can't send without first fetching the remote device's prekey bundle.
export const needsBundle = (s) => !s || (!s.send && !s.theirR);

/**
 * Advance the sending side. `me` = {user, device}; `bundle` (only needed when needsBundle) =
 * {sigPk, spk:{id,pk,sig}, otpk?:{id,pk,sig}} for the remote device, sigPk from a verified certificate.
 * Mutates `s`. Returns {h, mk}.
 */
export function ratchetSend(s, me, bundle) {
  const now = Date.now();
  if (!s.send || (s.theirR && s.send.target !== s.theirR.id)) {
    const e = randId(8);
    let ss, k, target = null;
    if (s.theirR) {
      const { cipherText, sharedSecret } = ml_kem768.encapsulate(unb64(s.theirR.pk));
      ss = sharedSecret; k = { t: 'rk', id: s.theirR.id, c: b64(cipherText) }; target = s.theirR.id;
    } else {
      if (!bundle) throw new Error('bundle required');
      if (!verifyPrekey(bundle.spk, s.ru, s.rd, 'spk', bundle.sigPk)) throw new Error('bad signed prekey');
      const a = ml_kem768.encapsulate(unb64(bundle.spk.pk));
      k = { t: 'pre', s: bundle.spk.id, c1: b64(a.cipherText) };
      ss = a.sharedSecret;
      if (bundle.otpk) {
        if (!verifyPrekey(bundle.otpk, s.ru, s.rd, 'otpk', bundle.sigPk)) throw new Error('bad one-time prekey');
        const b = ml_kem768.encapsulate(unb64(bundle.otpk.pk));
        k.o = bundle.otpk.id; k.c2 = b64(b.cipherText); ss = concat(ss, b.sharedSecret);
      }
    }
    s.send = { e, ck: b64(kdf(ss, e, chainInfo(me.user, me.device, s.ru, s.rd))), n: 0, k, target, acked: false, t: now };
  }
  const ck = unb64(s.send.ck);
  const mk = stepMk(ck);
  const h = { e: s.send.e, n: s.send.n, a: s.theirR ? s.theirR.id : -1 };
  s.send.ck = b64(stepCk(ck)); s.send.n++;
  if (!s.send.acked) h.k = s.send.k;                                  // epoch init until the remote confirms it
  if (s.seenMine < s.myR.cur.id) h.r = { id: s.myR.cur.id, pk: s.myR.cur.pk }; // advertise my ratchet key
  if (s.lastRecvE) h.ae = s.lastRecvE;
  return { h, mk };
}

/**
 * Process a received header. `keys` = {getSpk(id)->skB64|null, getOtpk(id)->skB64|null}.
 * Mutates `s` (call on a clone; commit only after the payload decrypts). Returns {mk, usedOtpk}.
 */
export function ratchetRecv(s, h, me, keys) {
  const now = Date.now();
  if (!h || typeof h.e !== 'string' || !Number.isInteger(h.n) || h.n < 0) throw new Error('bad header');
  let ch = s.recv[h.e], usedOtpk = null;
  if (!ch) {
    const k = h.k;
    if (!k) throw new Error('unknown epoch');
    let ss;
    if (k.t === 'pre') {
      const spkSk = keys.getSpk(k.s);
      if (!spkSk) throw new Error('signed prekey unavailable');
      ss = ml_kem768.decapsulate(unb64(k.c1), unb64(spkSk));
      if (k.o !== undefined) {
        const o = keys.getOtpk(k.o);
        if (!o) throw new Error('one-time prekey already used');
        ss = concat(ss, ml_kem768.decapsulate(unb64(k.c2), unb64(o)));
        usedOtpk = k.o;
      }
    } else if (k.t === 'rk') {
      const r = k.id === s.myR.cur.id ? s.myR.cur : s.myR.old[k.id];
      if (!r) throw new Error('ratchet key unavailable');
      ss = ml_kem768.decapsulate(unb64(k.c), unb64(r.sk));
      if (k.id === s.myR.cur.id) {                // remote consumed my key: rotate
        s.myR.old[s.myR.cur.id] = { sk: s.myR.cur.sk, t: now };
        s.myR.cur = newRatchetKey(s.myR.cur.id + 1);
      }
    } else throw new Error('bad epoch init');
    ch = s.recv[h.e] = { ck: b64(kdf(ss, h.e, chainInfo(s.ru, s.rd, me.user, me.device))), n: 0, skipped: {}, t: now };
  }
  let mk;
  if (h.n < ch.n) {
    const sk = ch.skipped[h.n];
    if (!sk) throw new Error('duplicate or replayed message');
    mk = unb64(sk.mk); delete ch.skipped[h.n];
  } else {
    if (h.n - ch.n > MAX_SKIP) throw new Error('too many skipped messages');
    let ck = unb64(ch.ck);
    while (ch.n < h.n) { ch.skipped[ch.n] = { mk: b64(stepMk(ck)), t: now }; ck = stepCk(ck); ch.n++; }
    mk = stepMk(ck); ch.ck = b64(stepCk(ck)); ch.n++;
  }
  ch.t = now;
  // bookkeeping from the authenticated header
  if (h.r && Number.isInteger(h.r.id) && typeof h.r.pk === 'string' && (!s.theirR || h.r.id > s.theirR.id)) s.theirR = { id: h.r.id, pk: h.r.pk };
  if (Number.isInteger(h.a) && h.a > s.seenMine) s.seenMine = Math.min(h.a, s.myR.cur.id);
  if (s.send && h.ae === s.send.e) s.send.acked = true;
  s.lastRecvE = h.e;
  prune(s, now);
  return { mk, usedOtpk };
}

function prune(s, now) {
  const epochs = Object.entries(s.recv).sort((a, b) => b[1].t - a[1].t);
  for (const [e] of epochs.slice(KEEP_RECV_EPOCHS)) delete s.recv[e];
  for (const [, ch] of epochs) for (const [n, v] of Object.entries(ch.skipped)) if (now - v.t > SKIPPED_TTL) delete ch.skipped[n];
  const olds = Object.entries(s.myR.old).sort((a, b) => b[1].t - a[1].t);
  for (const [id, v] of olds.slice(KEEP_OLD_RATCHET)) delete s.myR.old[id];
  for (const [id, v] of olds) if (now - v.t > OLD_RATCHET_TTL) delete s.myR.old[id];
  // once the remote has moved past a key, older secrets are no longer needed
  for (const id of Object.keys(s.myR.old)) if (Number(id) < s.seenMine - 1) delete s.myR.old[id];
}

export const wrapKey = (mk) => kdf(mk, 'qchat-wrap', 'qchat-wrap-v2', 32);
