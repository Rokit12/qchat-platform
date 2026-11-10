// Protocol tests: node --test tests/
import test from 'node:test';
import assert from 'node:assert/strict';
import * as C from '../src/shared/crypto.js';
import { newSession, needsBundle, cloneSession } from '../src/shared/ratchet.js';
import { seal, open } from '../src/shared/envelope.js';

function mkDevice(user) {
  const acct = C.accountKeys(C.newAccountSeeds());
  const dev = C.newDevice();
  const cert = C.makeCert(user, dev, acct.aikSk);
  const spk = C.makePrekey(user, dev.device, 'spk', 1, dev.sigSk);
  const otpks = {}; for (let i = 1; i <= 3; i++) otpks[i] = C.makePrekey(user, dev.device, 'otpk', i, dev.sigSk);
  const d = {
    user, device: dev.device, sigPk: dev.sigPk, sigSk: C.unb64(dev.sigSk), cert, acct, spk, otpks, sessions: {},
    keys: { getSpk: (id) => (id === 1 ? spk.sk : null), getOtpk: (id) => otpks[id]?.sk || null },
    bundle(withOtpk = true) { const o = Object.keys(otpks)[0]; return { sigPk: dev.sigPk, spk: spk.pub, otpk: withOtpk && o ? otpks[o].pub : undefined }; },
  };
  return d;
}
const me = (d) => ({ user: d.user, device: d.device, sigSk: d.sigSk });
const sk = (d, peer) => `${peer.user}:${peer.device}`;
async function send(from, tos, payload, id = C.randId()) {
  const recips = tos.map((to) => {
    let s = from.sessions[sk(from, to)];
    if (!s) s = from.sessions[sk(from, to)] = newSession(to.user, to.device);
    return { user: to.user, device: to.device, session: s, bundle: needsBundle(s) ? to.bundle() : undefined };
  });
  return seal(me(from), id, recips, payload);
}
async function recv(to, from, env, commit = true) {
  const r = await open(me(to), env, from.sigPk, to.sessions[sk(to, from)], to.keys);
  if (commit) { to.sessions[sk(to, from)] = r.session; if (r.usedOtpk != null) delete to.otpks[r.usedOtpk]; }
  return r.payload;
}

test('recovery key round-trip and checksum', () => {
  const seeds = C.newAccountSeeds(); const rk = C.makeRecoveryKey(seeds);
  const back = C.parseRecoveryKey(rk);
  assert.deepEqual(back.aikSeed, seeds.aikSeed);
  const bad = rk.slice(0, 10) + (rk[10] === 'A' ? 'B' : 'A') + rk.slice(11);
  assert.throws(() => C.parseRecoveryKey(bad), /checksum/);
});

test('device certificates and signed device lists', () => {
  const a = mkDevice('alice'); const aik = C.b64(a.acct.aikPk);
  assert.ok(C.verifyCert(a.cert, 'alice', aik));
  assert.ok(!C.verifyCert({ ...a.cert, sigPk: C.newDevice().sigPk }, 'alice', aik), 'server cannot swap a device key');
  assert.ok(!C.verifyCert(a.cert, 'mallory', aik));
  const other = C.accountKeys(C.newAccountSeeds());
  const forged = C.makeCert('alice', C.newDevice(), other.aikSk);
  assert.ok(!C.verifyCert(forged, 'alice', aik), 'cert signed by another account is rejected');
  const l = C.makeDeviceList('alice', 3, ['b', 'a'], a.acct.aikSk);
  assert.ok(C.verifyDeviceList(l, 'alice', aik));
  assert.ok(!C.verifyDeviceList({ ...l, devices: [...l.devices, 'evil'] }, 'alice', aik));
  assert.ok(!C.verifyDeviceList({ ...l, version: 4 }, 'alice', aik));
  // key order changes (e.g. a JSONB column) must not break verification
  const reordered = Object.fromEntries(Object.entries(l).reverse());
  assert.ok(C.verifyDeviceList(reordered, 'alice', aik));
});

test('first contact, replies, and KEM ratchet progression', async () => {
  const A = mkDevice('alice'), B = mkDevice('bob');
  const e1 = await send(A, [B], { t: 'hi' });
  assert.equal(e1.keys[0].h.k.t, 'pre');
  assert.equal((await recv(B, A, e1)).t, 'hi');
  assert.equal(Object.keys(B.otpks).length, 2, 'one-time prekey deleted after use');
  const e2 = await send(B, [A], { t: 'hey' }); // B has no session -> pre epoch with A's bundle
  await recv(A, B, e2);
  const e3 = await send(A, [B], { t: 'ratchet!' });
  assert.equal(e3.keys[0].h.k.t, 'rk', 'A switched to a KEM ratchet epoch using B\'s advertised key');
  assert.notEqual(e3.keys[0].h.e, e1.keys[0].h.e);
  assert.equal((await recv(B, A, e3)).t, 'ratchet!');
  for (let i = 0; i < 6; i++) { // ping-pong a few rounds
    await recv(B, A, await send(A, [B], { i }));
    await recv(A, B, await send(B, [A], { i }));
  }
  const sA = A.sessions[sk(A, B)];
  assert.ok(sA.myR.cur.id >= 5, 'ratchet keys rotate');
  assert.ok(Object.keys(sA.myR.old).length <= 3, 'old ratchet secrets are pruned');
  assert.ok(Object.keys(sA.recv).length <= 4, 'old receive chains are pruned');
});

test('out-of-order delivery within and across epochs', async () => {
  const A = mkDevice('alice'), B = mkDevice('bob');
  const m = [];
  for (let i = 0; i < 5; i++) m.push(await send(A, [B], { i }));
  assert.equal((await recv(B, A, m[3])).i, 3);
  assert.equal((await recv(B, A, m[0])).i, 0);
  assert.equal((await recv(B, A, m[4])).i, 4);
  await recv(A, B, await send(B, [A], { r: 1 }));
  const n1 = await send(A, [B], { x: 'new epoch' });
  assert.equal((await recv(B, A, n1)).x, 'new epoch');
  assert.equal((await recv(B, A, m[1])).i, 1, 'late message from the previous epoch still opens');
  assert.equal((await recv(B, A, m[2])).i, 2);
});

test('replays and duplicates are rejected', async () => {
  const A = mkDevice('alice'), B = mkDevice('bob');
  const e = await send(A, [B], { x: 1 });
  await recv(B, A, e);
  await assert.rejects(recv(B, A, e), /duplicate|replay/);
});

test('tampering is detected by the ML-DSA signature', async () => {
  const A = mkDevice('alice'), B = mkDevice('bob'), M = mkDevice('mallory');
  const e = await send(A, [B], { amount: 10 });
  const flip = (s) => { const u = C.unb64(s); u[5] ^= 1; return C.b64(u); };
  await assert.rejects(recv(B, A, { ...e, ct: flip(e.ct) }, false), /signature/);
  await assert.rejects(recv(B, A, { ...e, keys: [{ ...e.keys[0], w: flip(e.keys[0].w) }] }, false), /signature/);
  await assert.rejects(recv(B, A, { ...e, keys: [{ ...e.keys[0], h: { ...e.keys[0].h, n: 1 } }] }, false), /signature/);
  await assert.rejects(recv(B, A, { ...e, from: 'mallory' }, false), /signature/);
  // an attacker who re-signs with their own key is rejected because B checks A's certified key
  const forged = await send(M, [B], { amount: 1e6 });
  await assert.rejects(recv(B, A, { ...forged, from: 'alice', fd: A.device }, false), /signature/);
});

test('server-forged prekeys are refused by the sender', async () => {
  const A = mkDevice('alice'), B = mkDevice('bob'), M = mkDevice('mallory');
  const s = newSession(B.user, B.device);
  const evil = { sigPk: B.sigPk, spk: M.spk.pub }; // attacker substitutes their own prekey
  await assert.rejects(seal(me(A), 'x', [{ user: B.user, device: B.device, session: s, bundle: evil }], {}), /prekey/);
});

test('one-time prekeys cannot be reused', async () => {
  const A = mkDevice('alice'), A2 = mkDevice('alice'), B = mkDevice('bob');
  const bundle = B.bundle();
  const mk = (from) => { const s = newSession(B.user, B.device); return seal(me(from), C.randId(), [{ user: B.user, device: B.device, session: s, bundle }], { from: from.device }); };
  const e1 = await mk(A); await recv(B, A, e1);
  const e2 = await mk(A2);
  await assert.rejects(recv(B, A2, e2), /one-time prekey/);
});

test('forward secrecy: stealing current state does not reveal old messages', async () => {
  const A = mkDevice('alice'), B = mkDevice('bob');
  const old = await send(A, [B], { secret: 'old' });
  await recv(B, A, old);
  for (let i = 0; i < 4; i++) { await recv(A, B, await send(B, [A], { i })); await recv(B, A, await send(A, [B], { i })); }
  // attacker now steals B's full state (session + prekeys) and replays the captured envelope
  const stolen = cloneSession(B.sessions[sk(B, A)]);
  // even if the signed prekey were still around, the one-time prekey secret is gone
  await assert.rejects(open(me(B), old, A.sigPk, stolen, B.keys), /one-time prekey|duplicate/);
  await assert.rejects(open(me(B), old, A.sigPk, stolen, { getSpk: () => null, getOtpk: () => null }), /unknown epoch|unavailable|duplicate/);
});

test('post-compromise security: a stolen session stops working after a round trip', async () => {
  const A = mkDevice('alice'), B = mkDevice('bob');
  await recv(B, A, await send(A, [B], { a: 1 }));
  await recv(A, B, await send(B, [A], { b: 1 }));
  const stolenA = cloneSession(A.sessions[sk(A, B)]); // attacker copies Alice's state once
  for (let i = 0; i < 2; i++) { await recv(B, A, await send(A, [B], { i })); await recv(A, B, await send(B, [A], { i })); }
  const fresh = await send(B, [A], { secret: 'after healing' });
  await assert.rejects(open(me(A), fresh, B.sigPk, stolenA, A.keys), /unavailable|unknown epoch/);
  assert.equal((await recv(A, B, fresh)).secret, 'after healing');
});

test('group fan-out: every device decrypts, non-recipients cannot', async () => {
  const A = mkDevice('alice'), B = mkDevice('bob'), C2 = mkDevice('carol'), A2 = mkDevice('alice'), E = mkDevice('eve');
  const e = await send(A, [B, C2, A2], { g: 'hello group' });
  assert.equal((await recv(B, A, e)).g, 'hello group');
  assert.equal((await recv(C2, A, e)).g, 'hello group');
  assert.equal((await recv(A2, A, e)).g, 'hello group');
  await assert.rejects(recv(E, A, e), /not a recipient/);
});

test('safety numbers are symmetric and key-dependent', () => {
  const a = C.b64(C.accountKeys(C.newAccountSeeds()).aikPk), b = C.b64(C.accountKeys(C.newAccountSeeds()).aikPk);
  assert.deepEqual(C.safetyNumber('alice', a, 'bob', b), C.safetyNumber('bob', b, 'alice', a));
  const c = C.b64(C.accountKeys(C.newAccountSeeds()).aikPk);
  assert.notDeepEqual(C.safetyNumber('alice', a, 'bob', b), C.safetyNumber('alice', a, 'bob', c));
});

test('passcode KDF is Argon2id and deterministic per salt', async () => {
  const salt = C.rand(16);
  const k1 = await C.passcodeKey('1234', salt), k2 = await C.passcodeKey('1234', salt), k3 = await C.passcodeKey('1235', salt);
  assert.deepEqual(k1, k2); assert.notDeepEqual(k1, k3); assert.equal(k1.length, 32);
});
