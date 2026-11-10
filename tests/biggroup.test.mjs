// 3,500-member groups through the real server: user-level fan-out ({u}) to ~7,000 devices, bulk lookup/bundles,
// sender-key (v3) envelopes, spoofing and quota checks.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs'; import os from 'node:os'; import path from 'node:path';
import * as C from '../src/shared/crypto.js';
import { openStore } from '../server/store.js';
import { newSenderKey, exportSenderKey, sealGroup, openGroup, storeReceivedKey } from '../src/shared/senderkey.js';
import { startServer, Client } from './helpers.mjs';

const N = 3500;
async function bigGroup(pg) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qchat-big-'));
  const where = pg ? { databaseUrl: pg } : { dataDir: dir };
  if (pg) { const s0 = await openStore(where); for (const t of ['queue', 'otpks', 'devices', 'users']) await s0.raw?.(`DELETE FROM ${t}`); await s0.close?.(); }
  // seed 3,496 members with 2 devices each straight into the chat database (registration is tested elsewhere)
  const store = await openStore(where);
  const fake = { sigPk: 'x', name: 'seed' };
  const seeded = [];
  for (let i = 0; i < N - 4; i++) {
    const u = 'm' + String(i).padStart(4, '0'); seeded.push(u);
    await store.createUser(u, 'aik', { user: u, version: 1, devices: ['d' + i + 'a', 'd' + i + 'b'] }, { displayName: u });
    await store.putDevice(u, 'd' + i + 'a', fake, {}); await store.putDevice(u, 'd' + i + 'b', fake, {});
  }
  await store.close?.();
  const s = await startServer(3207, { DATA_DIR: dir, SEND_PER_MIN: '100000', ...(pg ? { DATABASE_URL: pg } : {}) });
  try {
    const mk = async (name) => { const c = new Client(3207, name, C.accountKeys(C.newAccountSeeds())); assert.equal((await c.login({ register: true })).t, 'ready'); return c; };
    const alice = await mk('alice'), bob = await mk('bob'), carol = await mk('carol'), mallory = await mk('mallory');
    const members = [...seeded, 'bob', 'carol', 'mallory'];
    assert.equal(members.length + 1, N);

    // bulk lookup: 500 names per request
    const lk = await alice.rpc({ t: 'lookup', usernames: members.slice(0, 500) }, 'lookup');
    assert.equal(lk.users.length, 500);
    // bulk bundles for the real members
    const bd = await alice.rpc({ t: 'bundle', users: [{ username: 'bob' }, { username: 'carol' }] }, 'bundle');
    assert.deepEqual(bd.bundles.map((b) => b.username).sort(), ['bob', 'carol']);

    // alice's sender key goes to bob/carol over the PQ ratchet (pairwise)
    const st = newSenderKey();
    await alice.sendTo('bob', { type: 'skey', g: 'G', ...exportSenderKey(st) });
    await alice.sendTo('carol', { type: 'skey', g: 'G', ...exportSenderKey(st) });
    const aliceCert = (await bob.rpc({ t: 'lookup', username: 'alice' }, 'lookup')).user.devices[0].cert;
    const bobKey = (await bob.receive(aliceCert)).payload; const carolKey = (await carol.receive(aliceCert)).payload;

    // one group message → the whole group, addressed by user ({u}); the server expands to every device
    const env = await sealGroup(alice.me(), 'big1', 'G', st, { type: 'msg', g: 'G', text: 'hello 3,500 👋' });
    const size = JSON.stringify(env).length;
    const t0 = Date.now();
    alice.sendRaw({ t: 'send', id: 'big1', to: members.map((u) => ({ u })), env, push: 'msg' });
    const sent = await alice.next((m) => m.t === 'sent' && m.id === 'big1', 60000);
    const ms = Date.now() - t0;
    assert.ok(sent.ok, JSON.stringify(sent));
    for (const [c, k] of [[bob, bobKey], [carol, carolKey]]) {
      const m = await c.next((x) => x.t === 'env' && x.id === 'big1');
      const r = await openGroup(m.env, aliceCert.sigPk, storeReceivedKey(null, k));
      assert.equal(r.payload.text, 'hello 3,500 👋');
    }
    const check = await openStore(where);
    const q = Number((await check.queueStats()).n);
    await check.close?.();
    assert.ok(q >= (N - 4) * 2 + 3, 'queued for every device: ' + q);
    console.log(`   one ${size} B message → ${q} device queues (3,500 members) in ${ms} ms`);

    // mallory can't post a v3 message in alice's name
    const forged = await sealGroup(mallory.me(), 'f1', 'G', newSenderKey(), { type: 'msg', g: 'G', text: 'fake' });
    mallory.sendRaw({ t: 'send', id: 'f1', to: [{ u: 'bob' }], env: { ...forged, from: 'alice' } });
    assert.equal((await mallory.next((m) => m.t === 'sent' && m.id === 'f1')).ok, false);
    // malformed v3 rejected
    mallory.sendRaw({ t: 'send', id: 'f2', to: [{ u: 'bob' }], env: { v: 3, from: 'mallory', g: 'G' } });
    assert.equal((await mallory.next((m) => m.t === 'sent' && m.id === 'f2')).ok, false);
    for (const c of [alice, bob, carol, mallory]) c.close();
  } finally { s.kill(); }
}
test('a 3,500-member group: one constant-size message reaches every member device (SQLite)', () => bigGroup(null));
test('a 3,500-member group on Postgres', { skip: !process.env.QCHAT_TEST_PG && 'set QCHAT_TEST_PG' }, () => bigGroup(process.env.QCHAT_TEST_PG));

test('delivery quota stops one account from flooding big groups', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qchat-q-'));
  const s = await startServer(3208, { DATA_DIR: dir, DELIVERIES_PER_HOUR: '5' });
  try {
    const mk = async (name) => { const c = new Client(3208, name, C.accountKeys(C.newAccountSeeds())); await c.login({ register: true }); return c; };
    const a = await mk('spammer'); const others = []; for (const n of ['vic1', 'vic2', 'vic3']) others.push(await mk(n));
    const st = newSenderKey(); let ok = 0, limited = 0;
    for (let i = 0; i < 4; i++) {
      const env = await sealGroup(a.me(), 's' + i, 'G', st, { type: 'msg', g: 'G', text: 'buy now' });
      a.sendRaw({ t: 'send', id: 's' + i, to: others.map((c) => ({ u: c.user })), env });
      const r = await a.next((m) => m.t === 'sent' && m.id === 's' + i);
      if (r.ok) ok++; else if (r.error === 'rate_limited') limited++;
    }
    assert.equal(ok, 1); assert.equal(limited, 3);
    for (const c of [a, ...others]) c.close();
  } finally { s.kill(); }
});
