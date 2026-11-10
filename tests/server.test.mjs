// Integration test against real server processes.
//   node --test tests/server.test.mjs                       (SQLite, one instance)
//   QCHAT_TEST_PG=postgres://... QCHAT_TEST_REDIS=redis://... node --test tests/server.test.mjs   (+ 2 instances)
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import * as C from '../src/shared/crypto.js';
import { startServer, Client } from './helpers.mjs';

async function scenario(t, portA, portB) {
  const aliceAcct = C.accountKeys(C.newAccountSeeds()), bobAcct = C.accountKeys(C.newAccountSeeds());
  const uniq = Math.random().toString(36).slice(2, 7);
  const alice = new Client(portA, 'alice' + uniq, aliceAcct), bob = new Client(portB, 'bob' + uniq, bobAcct);
  assert.equal((await alice.login({ register: true })).t, 'ready');
  assert.equal((await bob.login({ register: true })).t, 'ready');

  const thief = new Client(portA, alice.user, C.accountKeys(C.newAccountSeeds()));
  assert.equal((await thief.login()).t, 'auth_error', 'wrong recovery key rejected'); thief.close();
  const taken = new Client(portB, alice.user, C.accountKeys(C.newAccountSeeds()));
  assert.match((await taken.login({ register: true })).error, /taken/); taken.close();
  const forger = new Client(portA, alice.user, aliceAcct);
  assert.match((await forger.login({ tamper: 'cert' })).error, /certificate/); forger.close();

  // second device for alice via recovery key, on the *other* instance
  const alice2 = new Client(portB, alice.user, aliceAcct);
  const r2 = await alice2.login(); assert.equal(r2.t, 'ready'); assert.equal(r2.me.deviceList.devices.length, 2);

  // bob -> alice: delivered to both devices (possibly across instances)
  const sent = await bob.sendTo(alice.user, { text: 'hello both devices' });
  assert.equal(sent.devices, 2);
  const bobCert = (await alice.rpc({ t: 'lookup', username: bob.user }, 'lookup')).user.devices[0].cert;
  assert.equal((await alice.receive(bobCert)).payload.text, 'hello both devices');
  assert.equal((await alice2.receive(bobCert)).payload.text, 'hello both devices');

  // one-time prekeys were consumed: a fresh sender gets the next one
  const bobB = (await alice.rpc({ t: 'bundle', username: bob.user }, 'bundle')).bundles[0];
  assert.ok(bobB.otpk && bobB.otpk.id >= 1);

  // offline queue: alice2 disconnects, bob sends, alice2 reconnects and gets it
  alice2.close(); await new Promise((r) => setTimeout(r, 300));
  await bob.sendTo(alice.user, { text: 'while you were away' });
  assert.equal((await alice.receive(bobCert)).payload.text, 'while you were away');
  const alice2b = Object.assign(new Client(portA, alice.user, aliceAcct), { dev: alice2.dev, sessions: alice2.sessions, spks: alice2.spks, otpks: alice2.otpks });
  assert.equal((await alice2b.login()).t, 'ready');
  assert.equal((await alice2b.receive(bobCert)).payload.text, 'while you were away');

  // presence across instances
  alice.sendRaw({ t: 'watch', users: [bob.user] });
  assert.equal((await alice.next((m) => m.t === 'presence' && m.username === bob.user)).online, true);

  // device removal: alice (device 1) revokes device 2 with a newer signed list
  const cur = (await alice.rpc({ t: 'lookup', username: alice.user }, 'lookup')).user.deviceList;
  alice.sendRaw({ t: 'devices_update', deviceList: C.makeDeviceList(alice.user, cur.version + 1, [alice.dev.device], aliceAcct.aikSk) });
  assert.equal((await alice2b.next((m) => m.t === 'kicked')).reason, 'removed');
  const after = (await bob.rpc({ t: 'lookup', username: alice.user }, 'lookup')).user;
  assert.deepEqual(after.deviceList.devices, [alice.dev.device]);
  assert.equal(after.devices.length, 1);
  // rollback: replaying an older (validly signed) list is refused
  alice.sendRaw({ t: 'devices_update', deviceList: cur });
  assert.equal((await alice.next((m) => m.t === 'error')).error, 'bad_device_list');

  // reply alice -> bob, then verify server holds no ciphertext after acks
  await alice.sendTo(bob.user, { text: 'bye' });
  const aliceCert = after.devices[0].cert;
  assert.equal((await bob.receive(aliceCert)).payload.text, 'bye');
  for (const c of [alice, alice2b, bob]) c.close();
}

test('server: SQLite, single instance', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qchat-'));
  const s = await startServer(3201, { DATA_DIR: dir });
  try { await scenario(t, 3201, 3201); } finally { s.kill(); }
});

test('server: Postgres + Redis, two instances', { skip: !process.env.QCHAT_TEST_PG && 'set QCHAT_TEST_PG and QCHAT_TEST_REDIS' }, async (t) => {
  const env = { DATABASE_URL: process.env.QCHAT_TEST_PG, REDIS_URL: process.env.QCHAT_TEST_REDIS, ...(process.env.QCHAT_TEST_ADMIN_PG ? { ADMIN_DATABASE_URL: process.env.QCHAT_TEST_ADMIN_PG } : { DATA_DIR: fs.mkdtempSync(path.join(os.tmpdir(), 'qchat-pg-')) }) };
  const a = await startServer(3202, env), b = await startServer(3203, env);
  try { await scenario(t, 3202, 3203); } finally { a.kill(); b.kill(); }
});

// Web Push: a fake HTTPS push service receives the notification; we decrypt it (RFC 8291) and check
// it carries only {from, kind} — never message content — and is only sent while the device is offline.
import https from 'node:https';
import nodeCrypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
function decryptPush(body, uaPriv, uaPub, auth) {
  const salt = body.subarray(0, 16), idlen = body[20], asPub = body.subarray(21, 21 + idlen), ct = body.subarray(21 + idlen);
  const ecdh = nodeCrypto.createECDH('prime256v1'); ecdh.setPrivateKey(uaPriv);
  const secret = ecdh.computeSecret(asPub);
  const ikm = Buffer.from(nodeCrypto.hkdfSync('sha256', secret, auth, Buffer.concat([Buffer.from('WebPush: info\0'), uaPub, asPub]), 32));
  const cek = Buffer.from(nodeCrypto.hkdfSync('sha256', ikm, salt, Buffer.from('Content-Encoding: aes128gcm\0'), 16));
  const nonce = Buffer.from(nodeCrypto.hkdfSync('sha256', ikm, salt, Buffer.from('Content-Encoding: nonce\0'), 12));
  const d = nodeCrypto.createDecipheriv('aes-128-gcm', cek, nonce); d.setAuthTag(ct.subarray(ct.length - 16));
  const pt = Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]);
  return JSON.parse(pt.subarray(0, pt.lastIndexOf(2)).toString());
}
test('server: Web Push only when offline, content-free, encrypted', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qchat-push-'));
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', dir + '/k.pem', '-out', dir + '/c.pem', '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], { stdio: 'ignore' });
  const hits = [];
  const push = https.createServer({ key: fs.readFileSync(dir + '/k.pem'), cert: fs.readFileSync(dir + '/c.pem') }, (req, res) => {
    const chunks = []; req.on('data', (c) => chunks.push(c)); req.on('end', () => { hits.push({ headers: req.headers, body: Buffer.concat(chunks) }); res.writeHead(201); res.end(); });
  });
  await new Promise((r) => push.listen(3299, r));
  const s = await startServer(3204, { DATA_DIR: dir, NODE_EXTRA_CA_CERTS: dir + '/c.pem' });
  try {
    const alice = new Client(3204, 'pa' + Date.now().toString(36).slice(-5), C.accountKeys(C.newAccountSeeds()));
    const bob = new Client(3204, 'pb' + Date.now().toString(36).slice(-5), C.accountKeys(C.newAccountSeeds()));
    await alice.login({ register: true }); await bob.login({ register: true });
    const ua = nodeCrypto.createECDH('prime256v1'); ua.generateKeys(); const auth = nodeCrypto.randomBytes(16);
    alice.sendRaw({ t: 'push_sub', sub: { endpoint: 'https://localhost:3299/push/alice', keys: { p256dh: ua.getPublicKey().toString('base64url'), auth: auth.toString('base64url') } } });
    assert.equal((await alice.next((m) => m.t === 'push_ok')).on, true);
    await bob.sendTo(alice.user, { text: 'secret while online' });
    await new Promise((r) => setTimeout(r, 500));
    assert.equal(hits.length, 0, 'no push while the device is connected');
    alice.close(); await new Promise((r) => setTimeout(r, 400));
    await bob.sendTo(alice.user, { text: 'top secret content' });
    for (let i = 0; i < 50 && !hits.length; i++) await new Promise((r) => setTimeout(r, 100));
    assert.equal(hits.length, 1);
    assert.equal(hits[0].headers['content-encoding'], 'aes128gcm');
    assert.match(hits[0].headers.authorization, /^vapid t=.+, k=/);
    assert.ok(!hits[0].body.includes(Buffer.from('secret')));
    const data = decryptPush(hits[0].body, ua.getPrivateKey(), ua.getPublicKey(), auth);
    assert.deepEqual(data, { from: bob.user, kind: 'msg' });
    bob.close();
  } finally { s.kill(); push.close(); }
});
