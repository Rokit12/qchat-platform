// Storage: SQLite (default, zero-config) or PostgreSQL (set DATABASE_URL) for multi-server deployments.
// The server stores only public keys, signed device lists, profiles and *undelivered ciphertext*.
import fs from 'node:fs';
import path from 'node:path';

const SCHEMA = (serial, text = 'TEXT', big = 'BIGINT') => `
CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, aik ${text} NOT NULL, device_list ${text} NOT NULL, profile ${text} NOT NULL,
  hide_last_seen INTEGER NOT NULL DEFAULT 0, last_seen ${big}, created_at ${big} NOT NULL);
CREATE TABLE IF NOT EXISTS devices (username TEXT NOT NULL, device TEXT NOT NULL, cert ${text} NOT NULL, spk ${text} NOT NULL,
  push ${text}, created_at ${big} NOT NULL, PRIMARY KEY (username, device));
CREATE TABLE IF NOT EXISTS otpks (username TEXT NOT NULL, device TEXT NOT NULL, id INTEGER NOT NULL, pk ${text} NOT NULL, PRIMARY KEY (username, device, id));
CREATE TABLE IF NOT EXISTS queue (seq ${serial}, username TEXT NOT NULL, device TEXT NOT NULL, id TEXT NOT NULL, item ${text} NOT NULL, ts ${big} NOT NULL);
CREATE INDEX IF NOT EXISTS queue_dev ON queue (username, device, seq);
CREATE INDEX IF NOT EXISTS queue_ts ON queue (ts);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value ${text} NOT NULL);
CREATE TABLE IF NOT EXISTS pin_recovery (username TEXT PRIMARY KEY, salt TEXT NOT NULL, verifier TEXT NOT NULL, share ${text} NOT NULL, blob ${text} NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0, locked_until ${big} NOT NULL DEFAULT 0, updated ${big} NOT NULL);
CREATE TABLE IF NOT EXISTS reports (reporter TEXT NOT NULL, target TEXT NOT NULL, reason TEXT, ts ${big} NOT NULL, PRIMARY KEY (reporter, target));`;

const rowUser = (r) => r && ({ username: r.username, aik: r.aik, deviceList: JSON.parse(r.device_list), profile: JSON.parse(r.profile), hideLastSeen: !!r.hide_last_seen, lastSeen: r.last_seen == null ? null : Number(r.last_seen), createdAt: Number(r.created_at), suspendedUntil: Number(r.suspended_until || 0), suspendReason: r.suspend_reason || '' });
// additive migrations for databases created by older versions (errors = already applied)
const MIGRATIONS = (big) => [`ALTER TABLE users ADD COLUMN suspended_until ${big} NOT NULL DEFAULT 0`, 'ALTER TABLE users ADD COLUMN suspend_reason TEXT'];
const SORTS = { created: 'created_at DESC', created_asc: 'created_at ASC', seen: 'last_seen DESC', name: 'username ASC' }; // whitelist: never interpolate user input into SQL
const rowDev = (r) => ({ device: r.device, cert: JSON.parse(r.cert), spk: JSON.parse(r.spk), push: r.push ? JSON.parse(r.push) : null });

// Minimal async interface shared by both backends: q(sql, params) -> rows, run(sql, params), tx(fn)
function api(db) {
  return {
    kind: db.kind,
    raw: (sql) => db.run(sql), // tests only
    async getUser(u) { return rowUser((await db.q('SELECT * FROM users WHERE username=$1', [u]))[0]); },
    async createUser(u, aik, deviceList, profile) {
      await db.run('INSERT INTO users (username, aik, device_list, profile, created_at) VALUES ($1,$2,$3,$4,$5)', [u, aik, JSON.stringify(deviceList), JSON.stringify(profile), Date.now()]);
    },
    async updateUser(u, f) {
      const sets = [], vals = [];
      const add = (col, v) => { vals.push(v); sets.push(`${col}=$${vals.length}`); };
      if (f.deviceList) add('device_list', JSON.stringify(f.deviceList));
      if (f.profile) add('profile', JSON.stringify(f.profile));
      if (f.hideLastSeen !== undefined) add('hide_last_seen', f.hideLastSeen ? 1 : 0);
      if (f.lastSeen !== undefined) add('last_seen', f.lastSeen);
      if (!sets.length) return;
      vals.push(u); await db.run(`UPDATE users SET ${sets.join(',')} WHERE username=$${vals.length}`, vals);
    },
    async deleteUser(u) {
      await db.tx(async (t) => { for (const tb of ['otpks', 'devices', 'queue', 'users', 'pin_recovery']) await t.run(`DELETE FROM ${tb} WHERE username=$1`, [u]); await t.run('DELETE FROM reports WHERE reporter=$1 OR target=$1', [u]); });
    },
    async getDevices(u) { return (await db.q('SELECT * FROM devices WHERE username=$1 ORDER BY created_at', [u])).map(rowDev); },
    async getDevicesMany(users) { // bulk lookup for large-group fan-out (chunked IN so it stays fast at 3,500+ members)
      const out = new Map(users.map((u) => [u, []]));
      for (let i = 0; i < users.length; i += 500) {
        const c = users.slice(i, i + 500);
        const rows = await db.q(`SELECT * FROM devices WHERE username IN (${c.map((_, j) => '$' + (j + 1)).join(',')}) ORDER BY created_at`, c);
        for (const r of rows) out.get(r.username)?.push(rowDev(r));
      }
      return out;
    },
    async getDevice(u, d) { const r = (await db.q('SELECT * FROM devices WHERE username=$1 AND device=$2', [u, d]))[0]; return r ? rowDev(r) : null; },
    async putDevice(u, d, cert, spk) {
      await db.run('INSERT INTO devices (username, device, cert, spk, created_at) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (username, device) DO UPDATE SET cert=excluded.cert, spk=excluded.spk', [u, d, JSON.stringify(cert), JSON.stringify(spk), Date.now()]);
    },
    async removeDevice(u, d) {
      await db.tx(async (t) => { for (const tb of ['otpks', 'queue', 'devices']) await t.run(`DELETE FROM ${tb} WHERE username=$1 AND device=$2`, [u, d]); });
    },
    async setSpk(u, d, spk) { await db.run('UPDATE devices SET spk=$1 WHERE username=$2 AND device=$3', [JSON.stringify(spk), u, d]); },
    async setPush(u, d, sub) { await db.run('UPDATE devices SET push=$1 WHERE username=$2 AND device=$3', [sub ? JSON.stringify(sub) : null, u, d]); },
    async addOtpks(u, d, list) {
      await db.tx(async (t) => { for (const k of list) await t.run('INSERT INTO otpks (username, device, id, pk) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING', [u, d, k.id, JSON.stringify(k)]); });
    },
    async countOtpks(u, d) { return Number((await db.q('SELECT COUNT(*) AS n FROM otpks WHERE username=$1 AND device=$2', [u, d]))[0].n); },
    async takeOtpk(u, d) { // atomic: each one-time prekey is handed out at most once
      const rows = await db.takeOtpk(u, d);
      return rows[0] ? JSON.parse(rows[0].pk) : null;
    },
    async enqueue(u, d, item) { await db.run('INSERT INTO queue (username, device, id, item, ts) VALUES ($1,$2,$3,$4,$5)', [u, d, item.id, JSON.stringify(item), item.ts]); },
    async queueCountsMany(users) { // Map "user:device" -> queued items
      const out = new Map();
      for (let i = 0; i < users.length; i += 500) {
        const c = users.slice(i, i + 500);
        for (const r of await db.q(`SELECT username, device, COUNT(*) AS n FROM queue WHERE username IN (${c.map((_, j) => '$' + (j + 1)).join(',')}) GROUP BY username, device`, c)) out.set(r.username + ':' + r.device, Number(r.n));
      }
      return out;
    },
    async enqueueMany(targets, item) { // one transaction for a whole group fan-out
      const json = JSON.stringify(item);
      for (let i = 0; i < targets.length; i += 1000) {
        await db.tx(async (t) => { for (const r of targets.slice(i, i + 1000)) await t.run('INSERT INTO queue (username, device, id, item, ts) VALUES ($1,$2,$3,$4,$5)', [r.u, r.d, item.id, json, item.ts]); });
      }
    },
    async listQueue(u, d, limit = 500) { return (await db.q('SELECT item FROM queue WHERE username=$1 AND device=$2 ORDER BY seq LIMIT ' + Number(limit), [u, d])).map((r) => JSON.parse(r.item)); },
    async ackQueue(u, d, ids) {
      if (!ids.length) return;
      const ph = ids.map((_, i) => `$${i + 3}`).join(',');
      await db.run(`DELETE FROM queue WHERE username=$1 AND device=$2 AND id IN (${ph})`, [u, d, ...ids]);
    },
    async queueStats() { return (await db.q('SELECT COUNT(*) AS n FROM queue'))[0]; },
    async purgeQueue(olderThan) { await db.run('DELETE FROM queue WHERE ts < $1', [olderThan]); },
    async getPin(u) { const r = (await db.q('SELECT * FROM pin_recovery WHERE username=$1', [u]))[0]; return r ? { salt: r.salt, verifier: r.verifier, share: r.share, blob: JSON.parse(r.blob), attempts: Number(r.attempts), lockedUntil: Number(r.locked_until) } : null; },
    async setPin(u, p) {
      await db.run('INSERT INTO pin_recovery (username, salt, verifier, share, blob, attempts, locked_until, updated) VALUES ($1,$2,$3,$4,$5,0,0,$6) ON CONFLICT (username) DO UPDATE SET salt=excluded.salt, verifier=excluded.verifier, share=excluded.share, blob=excluded.blob, attempts=0, locked_until=0, updated=excluded.updated',
        [u, p.salt, p.verifier, p.share, JSON.stringify(p.blob), Date.now()]);
    },
    async deletePin(u) { await db.run('DELETE FROM pin_recovery WHERE username=$1', [u]); },
    async pinFailed(u, lockFor) { // atomic increment so parallel guesses on several servers can't skip the counter
      const rows = await db.q('UPDATE pin_recovery SET attempts = attempts + 1 WHERE username=$1 RETURNING attempts', [u]);
      const n = rows[0] ? Number(rows[0].attempts) : 0;
      const until = lockFor(n); if (until) await db.run('UPDATE pin_recovery SET locked_until=$1 WHERE username=$2', [Date.now() + until, u]);
      return n;
    },
    async pinSucceeded(u) { await db.run('UPDATE pin_recovery SET attempts=0, locked_until=0 WHERE username=$1', [u]); },
    async addReport(reporter, target, reason) { await db.run('INSERT INTO reports (reporter, target, reason, ts) VALUES ($1,$2,$3,$4) ON CONFLICT (reporter, target) DO UPDATE SET reason=excluded.reason, ts=excluded.ts', [reporter, target, reason, Date.now()]); },
    async countReports(target, since) { return Number((await db.q('SELECT COUNT(*) AS n FROM reports WHERE target=$1 AND ts >= $2', [target, since]))[0].n); },
    async queueCount(u, d) { return Number((await db.q('SELECT COUNT(*) AS n FROM queue WHERE username=$1 AND device=$2', [u, d]))[0].n); },
    async ping() { const t = Date.now(); await db.q('SELECT 1 AS ok'); return Date.now() - t; },
    async setSuspension(u, until, reason) { await db.run('UPDATE users SET suspended_until=$1, suspend_reason=$2 WHERE username=$3', [until, reason || null, u]); },
    async listUsers({ q = '', status = '', sort = 'created', limit = 50, offset = 0 } = {}) {
      const vals = [], where = [];
      if (q) { vals.push('%' + String(q).toLowerCase().replace(/[\\%_]/g, (c) => '\\' + c) + '%'); where.push(`(username LIKE $${vals.length} ESCAPE '\\' OR LOWER(profile) LIKE $${vals.length} ESCAPE '\\')`); }
      if (status === 'suspended') { vals.push(Date.now()); where.push(`suspended_until > $${vals.length}`); }
      if (status === 'active') { vals.push(Date.now()); where.push(`suspended_until <= $${vals.length}`); }
      const w = where.length ? 'WHERE ' + where.join(' AND ') : '';
      const total = Number((await db.q(`SELECT COUNT(*) AS n FROM users ${w}`, vals))[0].n);
      const rows = await db.q(`SELECT * FROM users ${w} ORDER BY ${SORTS[sort] || SORTS.created} LIMIT ${Math.min(Math.max(Number(limit) || 50, 1), 200)} OFFSET ${Math.max(Number(offset) || 0, 0)}`, vals);
      return { total, users: rows.map(rowUser) };
    },
    async countsFor(usernames) { // devices, PIN and reports for a page of users
      if (!usernames.length) return {};
      const ph = usernames.map((_, i) => '$' + (i + 1)).join(',');
      const out = Object.fromEntries(usernames.map((u) => [u, { devices: 0, pin: false, reports: 0 }]));
      for (const r of await db.q(`SELECT username, COUNT(*) AS n FROM devices WHERE username IN (${ph}) GROUP BY username`, usernames)) out[r.username].devices = Number(r.n);
      for (const r of await db.q(`SELECT username FROM pin_recovery WHERE username IN (${ph})`, usernames)) out[r.username].pin = true;
      for (const r of await db.q(`SELECT target, COUNT(*) AS n FROM reports WHERE target IN (${ph}) GROUP BY target`, usernames)) out[r.target].reports = Number(r.n);
      return out;
    },
    async listReports(target) { return (await db.q('SELECT reporter, reason, ts FROM reports WHERE target=$1 ORDER BY ts DESC LIMIT 100', [target])).map((r) => ({ reporter: r.reporter, reason: r.reason, ts: Number(r.ts) })); },
    async clearReports(target) { await db.run('DELETE FROM reports WHERE target=$1', [target]); },
    async totals() {
      const one = async (sql, p = []) => Number((await db.q(sql, p))[0].n);
      return { users: await one('SELECT COUNT(*) AS n FROM users'), devices: await one('SELECT COUNT(*) AS n FROM devices'), pinUsers: await one('SELECT COUNT(*) AS n FROM pin_recovery'),
        suspended: await one('SELECT COUNT(*) AS n FROM users WHERE suspended_until > $1', [Date.now()]), queued: await one('SELECT COUNT(*) AS n FROM queue'),
        new24h: await one('SELECT COUNT(*) AS n FROM users WHERE created_at > $1', [Date.now() - 864e5]), new7d: await one('SELECT COUNT(*) AS n FROM users WHERE created_at > $1', [Date.now() - 7 * 864e5]) };
    },
    async userCreatedSince(ts) { return (await db.q('SELECT created_at FROM users WHERE created_at > $1', [ts])).map((r) => Number(r.created_at)); },
    async deviceNames() { return (await db.q('SELECT cert FROM devices')).map((r) => { try { return JSON.parse(r.cert).name || ''; } catch { return ''; } }); },
    async getMeta(k) { const r = (await db.q('SELECT value FROM meta WHERE key=$1', [k]))[0]; return r ? JSON.parse(r.value) : null; },
    async initMeta(k, v) { // first writer wins (safe when many instances start together)
      await db.run('INSERT INTO meta (key, value) VALUES ($1,$2) ON CONFLICT (key) DO NOTHING', [k, JSON.stringify(v)]);
      return this.getMeta(k);
    },
    async setMeta(k, v) { await db.run('INSERT INTO meta (key, value) VALUES ($1,$2) ON CONFLICT (key) DO UPDATE SET value=excluded.value', [k, JSON.stringify(v)]); },
    close: () => db.close(),
  };
}

export async function sqlite(file, schema = SCHEMA, migrations = MIGRATIONS) {
  const { DatabaseSync } = await import('node:sqlite');
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const d = new DatabaseSync(file);
  d.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=5000; PRAGMA foreign_keys=OFF;');
  d.exec(schema('INTEGER PRIMARY KEY AUTOINCREMENT'));
  for (const m of migrations('INTEGER')) { try { d.exec(m); } catch {} }
  const conv = (sql) => sql.replace(/\$(\d+)/g, '?$1');
  const cache = new Map();
  const st = (sql) => { let s = cache.get(sql); if (!s) { s = d.prepare(conv(sql)); cache.set(sql, s); } return s; };
  const db = {
    kind: 'sqlite',
    q: async (sql, p = []) => st(sql).all(...p),
    run: async (sql, p = []) => { st(sql).run(...p); },
    tx: async (fn) => { d.exec('BEGIN'); try { await fn(db); d.exec('COMMIT'); } catch (e) { d.exec('ROLLBACK'); throw e; } },
    takeOtpk: async (u, dv) => st('DELETE FROM otpks WHERE rowid = (SELECT rowid FROM otpks WHERE username=$1 AND device=$2 ORDER BY id LIMIT 1) RETURNING pk').all(u, dv),
    close: async () => d.close(),
  };
  return db;
}

export async function postgres(url, schema = SCHEMA, migrations = MIGRATIONS, lockId = 727274001) {
  const { default: pg } = await import('pg');
  const pool = new pg.Pool({ connectionString: url, max: Number(process.env.PG_POOL || 10) });
  { // several instances may boot at once: serialize schema creation with an advisory lock
    const c = await pool.connect();
    try {
      await c.query('SELECT pg_advisory_lock($1)', [lockId]); await c.query(schema('BIGSERIAL PRIMARY KEY'));
      for (const m of migrations('BIGINT')) await c.query(m.replace('ADD COLUMN', 'ADD COLUMN IF NOT EXISTS'));
    } finally { await c.query('SELECT pg_advisory_unlock($1)', [lockId]).catch(() => {}); c.release(); }
  }
  const db = {
    kind: 'postgres',
    q: async (sql, p = []) => (await pool.query(sql, p)).rows,
    run: async (sql, p = []) => { await pool.query(sql, p); },
    tx: async (fn) => {
      const c = await pool.connect();
      try { await c.query('BEGIN'); await fn({ run: (s, p) => c.query(s, p), q: async (s, p) => (await c.query(s, p)).rows }); await c.query('COMMIT'); }
      catch (e) { await c.query('ROLLBACK'); throw e; } finally { c.release(); }
    },
    takeOtpk: async (u, dv) => (await pool.query('DELETE FROM otpks WHERE (username, device, id) IN (SELECT username, device, id FROM otpks WHERE username=$1 AND device=$2 ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING pk', [u, dv])).rows,
    close: () => pool.end(),
  };
  return db;
}

export async function openStore({ databaseUrl, dataDir }) {
  const db = databaseUrl ? await postgres(databaseUrl) : await sqlite(path.join(dataDir, 'qchat.db'));
  return api(db);
}
