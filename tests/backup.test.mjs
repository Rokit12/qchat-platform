// Encrypted server backup: owner-only, size-limited, opaque, removed with the account.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs'; import os from 'node:os'; import path from 'node:path';
import * as C from '../src/shared/crypto.js';
import { openStore } from '../server/store.js';
import { startServer, Client } from './helpers.mjs';

test('encrypted backup: only the owner can fetch it; limits; deleted with the account', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qchat-bk-'));
  const s = await startServer(3209, { DATA_DIR: dir, BACKUP_MAX_BYTES: '4000' });
  try {
    const mk = async (n) => { const c = new Client(3209, n, C.accountKeys(C.newAccountSeeds())); await c.login({ register: true }); return c; };
    const alice = await mk('alice'), eve = await mk('evelyn');
    const key = alice.acct.backupKey;
    const { iv, ct } = await C.aesEncrypt(key, C.te.encode(JSON.stringify({ msgs: { 'dm:bob': [{ text: 'secret' }] } })), C.te.encode('qchat-cloud-v1|alice'));
    assert.equal((await alice.rpc({ t: 'backup_put', iv: C.b64(iv), ct: C.b64(ct) }, 'backup_ok')).ok, true);
    // stored opaque
    const st = await openStore({ dataDir: dir }); const raw = await st.getBackup('alice'); await st.close();
    assert.ok(raw && !raw.data.includes('secret'));
    // owner gets it back and can decrypt; someone else gets nothing
    const got = await alice.rpc({ t: 'backup_get' }, 'backup');
    assert.match(C.td.decode(await C.aesDecrypt(key, C.unb64(got.iv), C.unb64(got.ct), C.te.encode('qchat-cloud-v1|alice'))), /secret/);
    assert.equal((await eve.rpc({ t: 'backup_get' }, 'backup')).none, true);
    // too large / malformed
    assert.equal((await alice.rpc({ t: 'backup_put', iv: C.b64(iv), ct: 'A'.repeat(5000) }, 'backup_ok')).error, 'too_large');
    assert.equal((await alice.rpc({ t: 'backup_put', iv: '<script>', ct: 'x' }, 'backup_ok')).ok, false);
    // deleting the account deletes the backup
    alice.sendRaw({ t: 'delete_account' }); await alice.next((m) => m.t === 'deleted');
    const st2 = await openStore({ dataDir: dir }); assert.equal(await st2.getBackup('alice'), null); await st2.close();
    eve.close(); alice.close();
  } finally { s.kill(); }
});
