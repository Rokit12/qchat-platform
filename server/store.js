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
CREATE TABLE IF NOT EXISTS security_events (seq ${serial}, ts ${big} NOT NULL, type TEXT NOT NULL, severity TEXT NOT NULL, username TEXT, ip_hash TEXT, detail ${text});
CREATE INDEX IF NOT EXISTS sec_ts ON security_events (ts);
CREATE INDEX IF NOT EXISTS sec_user ON security_events (username, ts);
CREATE TABLE IF NOT EXISTS reports (reporter TEXT NOT NULL, target TEXT NOT NULL, reason TEXT, ts ${big} NOT NULL, PRIMARY KEY (reporter, target));`;

const rowUser = (r) => r && ({ username: r.username, aik: r.aik, deviceList: JSON.parse(r.device_list), profile: JSON.parse(r.profile), hideLastSeen: !!r.hide_last_seen, lastSeen: r.last_seen == null ? null : Number(r.last_seen), createdAt: Number(r.created_at) });
const rowDev = (r) => ({ device: r.device, cert: JSON.parse(r.cert), spk: JSON.parse(r.spk), push: r.push ? JSON.parse(r.push) : null });

// Minimal async interface shared by both backends: q(sql, params) -> rows, run(sql, params), tx(fn)
function api(db) {
  return {
    kind: db.kind,
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
      await db.tx(async (t) => { for (const tb of ['otpks', 'devices', 'queue', 'users']) await t.run(`DELETE FROM ${tb} WHERE username=$1`, [u]); await t.run('DELETE FROM reports WHERE reporter=$1 OR target=$1', [u]); });
    },
    async getDevices(u) { return (await db.q('SELECT * FROM devices WHERE username=$1 ORDER BY created_at', [u])).map(rowDev); },
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
    async listQueue(u, d, limit = 500) { return (await db.q('SELECT item FROM queue WHERE username=$1 AND device=$2 ORDER BY seq LIMIT ' + Number(limit), [u, d])).map((r) => JSON.parse(r.item)); },
    async ackQueue(u, d, ids) {
      if (!ids.length) return;
      const ph = ids.map((_, i) => `$${i + 3}`).join(',');
      await db.run(`DELETE FROM queue WHERE username=$1 AND device=$2 AND id IN (${ph})`, [u, d, ...ids]);
    },
    async queueStats() { return (await db.q('SELECT COUNT(*) AS n FROM queue'))[0]; },
    async purgeQueue(olderThan) { await db.run('DELETE FROM queue WHERE ts < $1', [olderThan]); },
    async addSecurityEvent(e) { await db.run('INSERT INTO security_events (ts, type, severity, username, ip_hash, detail) VALUES ($1,$2,$3,$4,$5,$6)', [e.ts, e.type, e.severity, e.username, e.ipHash, JSON.stringify(e.detail || {})]); },
    async listSecurityEvents({ since = 0, username, limit = 200, minSeverity } = {}) {
      const sev = ['info', 'low', 'medium', 'high', 'critical']; const allowed = minSeverity ? sev.slice(sev.indexOf(minSeverity)) : sev;
      const vals = [since, ...allowed]; let sql = `SELECT * FROM security_events WHERE ts >= $1 AND severity IN (${allowed.map((_, i) => '$' + (i + 2)).join(',')})`;
      if (username) { vals.push(username); sql += ` AND username = $${vals.length}`; }
      sql += ' ORDER BY seq DESC LIMIT ' + Math.min(Number(limit) || 200, 1000);
      return (await db.q(sql, vals)).map((r) => ({ id: Number(r.seq), ts: Number(r.ts), type: r.type, severity: r.severity, username: r.username, ipHash: r.ip_hash, detail: JSON.parse(r.detail || '{}') }));
    },
    async purgeSecurityEvents(olderThan) { await db.run('DELETE FROM security_events WHERE ts < $1', [olderThan]); },
    async addReport(reporter, target, reason) { await db.run('INSERT INTO reports (reporter, target, reason, ts) VALUES ($1,$2,$3,$4) ON CONFLICT (reporter, target) DO UPDATE SET reason=excluded.reason, ts=excluded.ts', [reporter, target, reason, Date.now()]); },
    async countReports(target, since) { return Number((await db.q('SELECT COUNT(*) AS n FROM reports WHERE target=$1 AND ts >= $2', [target, since]))[0].n); },
    async queueCount(u, d) { return Number((await db.q('SELECT COUNT(*) AS n FROM queue WHERE username=$1 AND device=$2', [u, d]))[0].n); },
    async getMeta(k) { const r = (await db.q('SELECT value FROM meta WHERE key=$1', [k]))[0]; return r ? JSON.parse(r.value) : null; },
    async initMeta(k, v) { // first writer wins (safe when many instances start together)
      await db.run('INSERT INTO meta (key, value) VALUES ($1,$2) ON CONFLICT (key) DO NOTHING', [k, JSON.stringify(v)]);
      return this.getMeta(k);
    },
    async setMeta(k, v) { await db.run('INSERT INTO meta (key, value) VALUES ($1,$2) ON CONFLICT (key) DO UPDATE SET value=excluded.value', [k, JSON.stringify(v)]); },
    close: () => db.close(),
  };
}

async function sqlite(file) {
  const { DatabaseSync } = await import('node:sqlite');
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const d = new DatabaseSync(file);
  d.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=5000; PRAGMA foreign_keys=OFF;');
  d.exec(SCHEMA('INTEGER PRIMARY KEY AUTOINCREMENT'));
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

async function postgres(url) {
  const { default: pg } = await import('pg');
  const pool = new pg.Pool({ connectionString: url, max: Number(process.env.PG_POOL || 10) });
  { // several instances may boot at once: serialize schema creation with an advisory lock
    const c = await pool.connect();
    try { await c.query('SELECT pg_advisory_lock(727274001)'); await c.query(SCHEMA('BIGSERIAL PRIMARY KEY')); }
    finally { await c.query('SELECT pg_advisory_unlock(727274001)').catch(() => {}); c.release(); }
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
