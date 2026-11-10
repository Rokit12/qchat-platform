// Sender-key group encryption: correctness, authenticity, rotation and size at 3,500 members.
import test from 'node:test';
import assert from 'node:assert/strict';
import * as C from '../src/shared/crypto.js';
import { newSenderKey, exportSenderKey, sealGroup, openGroup, storeReceivedKey } from '../src/shared/senderkey.js';
import { newSession, needsBundle } from '../src/shared/ratchet.js';
import { seal, open } from '../src/shared/envelope.js';

const dev = (user) => { const d = C.newDevice(); return { user, device: d.device, sigPk: d.sigPk, sigSk: C.unb64(d.sigSk) }; };
const me = (d) => ({ user: d.user, device: d.device, sigSk: d.sigSk });

test('members decrypt, order/skips handled, replays rejected', async () => {
  const A = dev('alice'), st = newSenderKey();
  const rsB = storeReceivedKey(null, exportSenderKey(st));
  const m = []; for (let i = 0; i < 5; i++) m.push(await sealGroup(me(A), 'id' + i, 'g1', st, { i }));
  let rs = rsB;
  for (const k of [3, 0, 4, 1, 2]) { const r = await openGroup(m[k], A.sigPk, rs); assert.equal(r.payload.i, k); rs = r.rs; }
  await assert.rejects(openGroup(m[2], A.sigPk, rs), /duplicate|replayed/);
});

test('a member holding the chain key cannot forge messages as the sender', async () => {
  const A = dev('alice'), M = dev('mallory'), st = newSenderKey();
  const exported = exportSenderKey(st);
  const stolen = { ...newSenderKey(), kid: exported.kid, ck: exported.ck, n: exported.n }; // mallory knows alice's chain
  const forged = await sealGroup(me(M), 'x', 'g1', stolen, { text: 'send money' });
  await assert.rejects(openGroup({ ...forged, from: 'alice', fd: A.device }, A.sigPk, storeReceivedKey(null, exported)), /signature/);
  const real = await sealGroup(me(A), 'y', 'g1', st, { text: 'hi' });
  await assert.rejects(openGroup({ ...real, ct: real.ct.slice(0, -4) + 'AAAA' }, A.sigPk, storeReceivedKey(null, exported)), /signature/);
});

test('rotation: a removed member cannot read messages sent after the rotation', async () => {
  const A = dev('alice'); let st = newSenderKey();
  const removedMemberState = storeReceivedKey(null, exportSenderKey(st));
  st = newSenderKey(); // alice rotates after a removal
  const stayingMember = storeReceivedKey(null, exportSenderKey(st));
  const after = await sealGroup(me(A), 'z', 'g1', st, { text: 'secret plans' });
  await assert.rejects(openGroup(after, A.sigPk, removedMemberState), /no sender key/);
  assert.equal((await openGroup(after, A.sigPk, stayingMember)).payload.text, 'secret plans');
});

test('late requester can catch up from recent history (but no further back than the sender kept)', async () => {
  const A = dev('alice'), st = newSenderKey();
  const msgs = []; for (let i = 0; i < 10; i++) msgs.push(await sealGroup(me(A), 'm' + i, 'g', st, { i }));
  const rs = storeReceivedKey(null, exportSenderKey(st, 6)); // asked for message 6 onwards
  assert.equal((await openGroup(msgs[6], A.sigPk, rs)).payload.i, 6);
  await assert.rejects(openGroup(msgs[5], A.sigPk, rs), /no sender key|replayed/);
});

test('scale: one message to a 3,500-member group is constant-size; key distribution reuses PQ sessions', async () => {
  const A = dev('alice'), st = newSenderKey();
  const t0 = Date.now();
  const env = await sealGroup(me(A), 'big', 'g3500', st, { type: 'msg', text: 'Hello 3,500 people! 👋' });
  const size = JSON.stringify(env).length;
  assert.ok(size < 6000, 'group message is ~5 KB regardless of member count (got ' + size + ')');
  // distributing the chain key to 3,500 member devices over existing ratchet sessions, in batches of 1,000
  const members = Array.from({ length: 3500 }, (_, i) => ({ user: 'u' + i, device: C.randId(8) }));
  const sessions = members.map((m) => { const s = newSession(m.user, m.device); s.theirR = { id: 0, pk: C.b64(C.ml_kem768.keygen().publicKey) }; return s; }); // sessions already set up
  let bytes = 0;
  const t1 = Date.now();
  for (let i = 0; i < members.length; i += 1000) {
    const batch = members.slice(i, i + 1000).map((m, j) => ({ user: m.user, device: m.device, session: sessions[i + j] }));
    const e = await seal(me(A), 'dist' + i, batch, { type: 'skey', g: 'g3500', ...exportSenderKey(st) });
    bytes += JSON.stringify(e).length;
  }
  const distMs = Date.now() - t1;
  console.log(`   group message: ${size} B · key distribution to 3,500 devices: ${(bytes / 1048576).toFixed(1)} MB in ${distMs} ms (one-time per chain)`);
  assert.ok(Date.now() - t0 < 120000);
});
