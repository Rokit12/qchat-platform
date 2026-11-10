// Multi-recipient envelope: one AES-256-GCM ciphertext, the content key wrapped per recipient
// device with that device's ratchet message key, the whole thing signed with ML-DSA-65.
import { te, td, rand, b64, unb64, xor, sha256, stable, aesEncrypt, aesDecrypt, ml_dsa65 } from './crypto.js';
import { ratchetSend, ratchetRecv, cloneSession, wrapKey, newSession } from './ratchet.js';

const aadFor = (env) => te.encode(`qchat-env-v2|${env.id}|${env.from}|${env.fd}`);
export const envDigest = (env) => sha256(te.encode('qchat-env-v2\n' + stable({ v: env.v, from: env.from, fd: env.fd, id: env.id, iv: env.iv, ct: env.ct, keys: env.keys })));

/**
 * me: {user, device, sigSk: Uint8Array}
 * recipients: [{user, device, session, bundle?}] — sessions are mutated in place.
 */
export async function seal(me, id, recipients, payload) {
  const K = rand(32);
  const env = { v: 2, from: me.user, fd: me.device, id };
  const { iv, ct } = await aesEncrypt(K, te.encode(JSON.stringify(payload)), aadFor(env));
  env.iv = b64(iv); env.ct = b64(ct);
  env.keys = recipients.map((r) => {
    const { h, mk } = ratchetSend(r.session, me, r.bundle);
    return { u: r.user, d: r.device, h, w: b64(xor(K, wrapKey(mk))) };
  });
  env.sig = b64(ml_dsa65.sign(envDigest(env), me.sigSk));
  return env;
}

/**
 * Verify + decrypt. senderSigPk: verified device key of env.fd. session: existing session or null.
 * keys: prekey accessors. Returns {payload, session (new state to commit), usedOtpk}.
 */
export async function open(me, env, senderSigPk, session, keys) {
  if (!env || env.v !== 2 || typeof env.id !== 'string') throw new Error('bad envelope');
  if (!ml_dsa65.verify(unb64(env.sig), envDigest(env), unb64(senderSigPk))) throw new Error('bad signature');
  const mine = (env.keys || []).find((k) => k.u === me.user && k.d === me.device);
  if (!mine) throw new Error('not a recipient');
  const s = session ? cloneSession(session) : newSession(env.from, env.fd);
  const { mk, usedOtpk } = ratchetRecv(s, mine.h, me, keys);
  const K = xor(unb64(mine.w), wrapKey(mk));
  const pt = await aesDecrypt(K, unb64(env.iv), unb64(env.ct), aadFor(env));
  return { payload: JSON.parse(td.decode(pt)), session: s, usedOtpk };
}
