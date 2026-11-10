// Independent admin & analytics database.
// Kept apart from the chat database (its own SQLite file, or its own Postgres via ADMIN_DATABASE_URL with
// its own credentials), so admin accounts, the audit trail and activity history can't be read or altered
// through the chat database, and vice versa.
import path from 'node:path';
import { sqlite, postgres } from './store.js';

const SCHEMA = (serial, text = 'TEXT', big = 'BIGINT') => `
CREATE TABLE IF NOT EXISTS admin_users (id ${serial}, username TEXT NOT NULL UNIQUE, pw_hash TEXT NOT NULL, totp_enc TEXT NOT NULL, role TEXT NOT NULL,
  disabled INTEGER NOT NULL DEFAULT 0, failed INTEGER NOT NULL DEFAULT 0, locked_until ${big} NOT NULL DEFAULT 0, totp_last ${big} NOT NULL DEFAULT 0,
  created ${big} NOT NULL, last_login ${big});
CREATE TABLE IF NOT EXISTS admin_sessions (token_hash TEXT PRIMARY KEY, admin_id ${big} NOT NULL, created ${big} NOT NULL, last_seen ${big} NOT NULL, expires ${big} NOT NULL, ip_hash TEXT, ua TEXT);
CREATE TABLE IF NOT EXISTS admin_audit (seq ${serial}, ts ${big} NOT NULL, admin TEXT NOT NULL, action TEXT NOT NULL, target TEXT, detail ${text}, ip_hash TEXT);
CREATE TABLE IF NOT EXISTS security_events (seq ${serial}, ts ${big} NOT NULL, type TEXT NOT NULL, severity TEXT NOT NULL, username TEXT, ip_hash TEXT, detail ${text});
CREATE INDEX IF NOT EXISTS sec_ts ON security_events (ts);
CREATE INDEX IF NOT EXISTS sec_user ON security_events (username, ts);
CREATE TABLE IF NOT EXISTS activity (seq ${serial}, ts ${big} NOT NULL, username TEXT NOT NULL, type TEXT NOT NULL, detail ${text}, ip_hash TEXT);
CREATE INDEX IF NOT EXISTS act_user ON activity (username, ts);
CREATE INDEX IF NOT EXISTS act_ts ON activity (ts);
CREATE TABLE IF NOT EXISTS stats_daily (day TEXT NOT NULL, metric TEXT NOT NULL, value ${big} NOT NULL, PRIMARY KEY (day, metric));
CREATE TABLE IF NOT EXISTS user_daily (day TEXT NOT NULL, username TEXT NOT NULL, sent ${big} NOT NULL, PRIMARY KEY (day, username));
CREATE TABLE IF NOT EXISTS daily_active (day TEXT NOT NULL, username TEXT NOT NULL, PRIMARY KEY (day, username));
CREATE TABLE IF NOT EXISTS health (seq ${serial}, ts ${big} NOT NULL, service TEXT NOT NULL, ok INTEGER NOT NULL, latency INTEGER, detail TEXT);
CREATE INDEX IF NOT EXISTS health_svc ON health (service, ts);
CREATE TABLE IF NOT EXISTS incidents (id ${serial}, service TEXT NOT NULL, started ${big} NOT NULL, ended ${big}, detail TEXT);
CREATE TABLE IF NOT EXISTS instances (id TEXT PRIMARY KEY, host TEXT, started ${big} NOT NULL, last_seen ${big} NOT NULL, connections INTEGER, users INTEGER);
CREATE TABLE IF NOT EXISTS admin_meta (key TEXT PRIMARY KEY, value ${text} NOT NULL);`;

export const day = (ts = Date.now()) => new Date(ts).toISOString().slice(0, 10);
const SEV = ['info', 'low', 'medium', 'high', 'critical'];

export async function openAdminStore({ adminDatabaseUrl, dataDir }) {
  const MIG = () => ['ALTER TABLE admin_users ADD COLUMN totp_enrolled INTEGER NOT NULL DEFAULT 1'];
  const db = adminDatabaseUrl ? await postgres(adminDatabaseUrl, SCHEMA, MIG, 727274002) : await sqlite(path.join(dataDir, 'admin.db'), SCHEMA, MIG);
  const json = (s) => { try { return JSON.parse(s || '{}'); } catch { return {}; } };
  return {
    kind: db.kind,
    async ping() { const t = Date.now(); await db.q('SELECT 1 AS ok'); return Date.now() - t; },
    // ---- admin accounts & sessions ----
    async countAdmins() { return Number((await db.q('SELECT COUNT(*) AS n FROM admin_users'))[0].n); },
    async createAdmin(a) { await db.run('INSERT INTO admin_users (username, pw_hash, totp_enc, role, created, totp_enrolled) VALUES ($1,$2,$3,$4,$5,$6)', [a.username, a.pwHash, a.totpEnc, a.role, Date.now(), a.enrolled === false ? 0 : 1]); },
    async getAdmin(username) { return (await db.q('SELECT * FROM admin_users WHERE username=$1', [username]))[0] || null; },
    async getAdminById(id) { return (await db.q('SELECT * FROM admin_users WHERE id=$1', [id]))[0] || null; },
    async listAdmins() { return (await db.q('SELECT id, username, role, disabled, created, last_login, locked_until FROM admin_users ORDER BY id')).map((r) => ({ ...r, id: Number(r.id), created: Number(r.created), last_login: r.last_login ? Number(r.last_login) : null, locked_until: Number(r.locked_until) })); },
    async updateAdmin(id, f) {
      const sets = [], vals = []; for (const [k, v] of Object.entries(f)) { if (!['failed', 'locked_until', 'last_login', 'disabled', 'role', 'totp_last', 'pw_hash', 'totp_enc', 'totp_enrolled'].includes(k)) continue; vals.push(v); sets.push(`${k}=$${vals.length}`); }
      if (sets.length) { vals.push(id); await db.run(`UPDATE admin_users SET ${sets.join(',')} WHERE id=$${vals.length}`, vals); }
    },
    async createSession(s) { await db.run('INSERT INTO admin_sessions (token_hash, admin_id, created, last_seen, expires, ip_hash, ua) VALUES ($1,$2,$3,$3,$4,$5,$6)', [s.tokenHash, s.adminId, Date.now(), s.expires, s.ipHash, s.ua]); },
    async getSession(tokenHash) { return (await db.q('SELECT * FROM admin_sessions WHERE token_hash=$1', [tokenHash]))[0] || null; },
    async touchSession(tokenHash) { await db.run('UPDATE admin_sessions SET last_seen=$1 WHERE token_hash=$2', [Date.now(), tokenHash]); },
    async deleteSession(tokenHash) { await db.run('DELETE FROM admin_sessions WHERE token_hash=$1', [tokenHash]); },
    async deleteSessionsFor(adminId) { await db.run('DELETE FROM admin_sessions WHERE admin_id=$1', [adminId]); },
    async purgeSessions() { await db.run('DELETE FROM admin_sessions WHERE expires < $1', [Date.now()]); },
    // ---- audit ----
    async audit(admin, action, target, detail, ipHash) { await db.run('INSERT INTO admin_audit (ts, admin, action, target, detail, ip_hash) VALUES ($1,$2,$3,$4,$5,$6)', [Date.now(), admin, action, target || null, JSON.stringify(detail || {}), ipHash || null]); },
    async listAudit(limit = 200) { return (await db.q(`SELECT * FROM admin_audit ORDER BY seq DESC LIMIT ${Math.min(Number(limit) || 200, 1000)}`)).map((r) => ({ ts: Number(r.ts), admin: r.admin, action: r.action, target: r.target, detail: json(r.detail), ipHash: r.ip_hash })); },
    // ---- security events (written by server/security.js) ----
    async addSecurityEvent(e) { await db.run('INSERT INTO security_events (ts, type, severity, username, ip_hash, detail) VALUES ($1,$2,$3,$4,$5,$6)', [e.ts, e.type, e.severity, e.username, e.ipHash, JSON.stringify(e.detail || {})]); },
    async listSecurityEvents({ since = 0, username, limit = 200, minSeverity } = {}) {
      const allowed = minSeverity && SEV.includes(minSeverity) ? SEV.slice(SEV.indexOf(minSeverity)) : SEV;
      const vals = [Number(since) || 0, ...allowed]; let sql = `SELECT * FROM security_events WHERE ts >= $1 AND severity IN (${allowed.map((_, i) => '$' + (i + 2)).join(',')})`;
      if (username) { vals.push(String(username)); sql += ` AND username = $${vals.length}`; }
      sql += ' ORDER BY seq DESC LIMIT ' + Math.min(Number(limit) || 200, 1000);
      return (await db.q(sql, vals)).map((r) => ({ id: Number(r.seq), ts: Number(r.ts), type: r.type, severity: r.severity, username: r.username, ipHash: r.ip_hash, detail: json(r.detail) }));
    },
    async securityCounts(since) { return (await db.q('SELECT type, severity, COUNT(*) AS n FROM security_events WHERE ts >= $1 GROUP BY type, severity', [since])).map((r) => ({ type: r.type, severity: r.severity, n: Number(r.n) })); },
    // ---- user activity (metadata only — message content is end-to-end encrypted and never seen) ----
    async addActivity(a) { await db.run('INSERT INTO activity (ts, username, type, detail, ip_hash) VALUES ($1,$2,$3,$4,$5)', [Date.now(), a.username, a.type, JSON.stringify(a.detail || {}), a.ipHash || null]); },
    async listActivity({ username, limit = 200, since = 0 } = {}) {
      const vals = [Number(since) || 0]; let sql = 'SELECT * FROM activity WHERE ts >= $1';
      if (username) { vals.push(String(username)); sql += ' AND username = $2'; }
      return (await db.q(sql + ` ORDER BY seq DESC LIMIT ${Math.min(Number(limit) || 200, 1000)}`, vals)).map((r) => ({ ts: Number(r.ts), username: r.username, type: r.type, detail: json(r.detail), ipHash: r.ip_hash }));
    },
    // ---- analytics ----
    async incrStats(entries) { // [[day, metric, n]]
      await db.tx(async (t) => { for (const [d, m, n] of entries) await t.run('INSERT INTO stats_daily (day, metric, value) VALUES ($1,$2,$3) ON CONFLICT (day, metric) DO UPDATE SET value = stats_daily.value + excluded.value', [d, m, n]); });
    },
    async incrUserDaily(entries) { // [[day, user, n]]
      await db.tx(async (t) => { for (const [d, u, n] of entries) await t.run('INSERT INTO user_daily (day, username, sent) VALUES ($1,$2,$3) ON CONFLICT (day, username) DO UPDATE SET sent = user_daily.sent + excluded.sent', [d, u, n]); });
    },
    async markActive(d, users) { await db.tx(async (t) => { for (const u of users) await t.run('INSERT INTO daily_active (day, username) VALUES ($1,$2) ON CONFLICT DO NOTHING', [d, u]); }); },
    async statsSeries(fromDay) {
      const rows = await db.q('SELECT day, metric, value FROM stats_daily WHERE day >= $1', [fromDay]);
      const dau = await db.q('SELECT day, COUNT(*) AS n FROM daily_active WHERE day >= $1 GROUP BY day', [fromDay]);
      return { stats: rows.map((r) => ({ day: r.day, metric: r.metric, value: Number(r.value) })), dau: dau.map((r) => ({ day: r.day, n: Number(r.n) })) };
    },
    async userSeries(username, fromDay) { return (await db.q('SELECT day, sent FROM user_daily WHERE username=$1 AND day >= $2 ORDER BY day', [username, fromDay])).map((r) => ({ day: r.day, sent: Number(r.sent) })); },
    async activeDays(username) { return Number((await db.q('SELECT COUNT(*) AS n FROM daily_active WHERE username=$1', [username]))[0].n); },
    async topSenders(fromDay, limit = 10) { return (await db.q(`SELECT username, SUM(sent) AS n FROM user_daily WHERE day >= $1 GROUP BY username ORDER BY n DESC LIMIT ${Number(limit)}`, [fromDay])).map((r) => ({ username: r.username, n: Number(r.n) })); },
    async forgetUser(u) { for (const t of ['activity', 'user_daily', 'daily_active']) await db.run(`DELETE FROM ${t} WHERE username=$1`, [u]); },
    // ---- service health ----
    async addHealth(rows) { await db.tx(async (t) => { for (const h of rows) await t.run('INSERT INTO health (ts, service, ok, latency, detail) VALUES ($1,$2,$3,$4,$5)', [h.ts, h.service, h.ok ? 1 : 0, h.latency ?? null, h.detail || null]); }); },
    async healthSince(since) { return (await db.q('SELECT ts, service, ok, latency, detail FROM health WHERE ts >= $1 ORDER BY ts', [since])).map((r) => ({ ts: Number(r.ts), service: r.service, ok: !!Number(r.ok), latency: r.latency == null ? null : Number(r.latency), detail: r.detail })); },
    async lastHealth() { return (await db.q('SELECT h.service, h.ts, h.ok, h.latency, h.detail FROM health h JOIN (SELECT service, MAX(seq) AS m FROM health GROUP BY service) x ON h.seq = x.m')).map((r) => ({ service: r.service, ts: Number(r.ts), ok: !!Number(r.ok), latency: r.latency == null ? null : Number(r.latency), detail: r.detail })); },
    async healthBuckets(since, bucketMs) { // aggregated in SQL — integer division buckets work in SQLite and Postgres
      const b = Math.max(60000, Math.floor(Number(bucketMs)));
      return (await db.q(`SELECT service, ts / ${b} AS b, SUM(ok) AS ok, COUNT(*) AS total, AVG(latency) AS lat FROM health WHERE ts >= $1 GROUP BY service, ts / ${b}`, [since]))
        .map((r) => ({ service: r.service, b: Number(r.b), ok: Number(r.ok), total: Number(r.total), lat: r.lat == null ? null : Math.round(Number(r.lat)) }));
    },
    async openIncident(service, detail) { await db.run('INSERT INTO incidents (service, started, detail) VALUES ($1,$2,$3)', [service, Date.now(), detail || null]); },
    async closeIncident(service) { await db.run('UPDATE incidents SET ended=$1 WHERE service=$2 AND ended IS NULL', [Date.now(), service]); },
    async openIncidents() { return (await db.q('SELECT * FROM incidents WHERE ended IS NULL')).map((r) => ({ id: Number(r.id), service: r.service, started: Number(r.started), detail: r.detail })); },
    async listIncidents(since) { return (await db.q('SELECT * FROM incidents WHERE started >= $1 OR ended IS NULL ORDER BY started DESC LIMIT 100', [since])).map((r) => ({ id: Number(r.id), service: r.service, started: Number(r.started), ended: r.ended == null ? null : Number(r.ended), detail: r.detail })); },
    async heartbeat(i) { await db.run('INSERT INTO instances (id, host, started, last_seen, connections, users) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (id) DO UPDATE SET last_seen=excluded.last_seen, connections=excluded.connections, users=excluded.users', [i.id, i.host, i.started, Date.now(), i.connections, i.users]); },
    async listInstances(since) { return (await db.q('SELECT * FROM instances WHERE last_seen >= $1 ORDER BY started', [since])).map((r) => ({ id: r.id, host: r.host, started: Number(r.started), lastSeen: Number(r.last_seen), connections: Number(r.connections), users: Number(r.users) })); },
    async purge() {
      const now = Date.now();
      await db.run('DELETE FROM health WHERE ts < $1', [now - 31 * 864e5]);
      await db.run('DELETE FROM security_events WHERE ts < $1', [now - 90 * 864e5]);
      await db.run('DELETE FROM activity WHERE ts < $1', [now - 180 * 864e5]);
      await db.run('DELETE FROM instances WHERE last_seen < $1', [now - 7 * 864e5]);
      await db.run('DELETE FROM admin_sessions WHERE expires < $1', [now]);
    },
    async getMeta(k) { const r = (await db.q('SELECT value FROM admin_meta WHERE key=$1', [k]))[0]; return r ? JSON.parse(r.value) : null; },
    async initMeta(k, v) { await db.run('INSERT INTO admin_meta (key, value) VALUES ($1,$2) ON CONFLICT (key) DO NOTHING', [k, JSON.stringify(v)]); return this.getMeta(k); },
    close: () => db.close(),
  };
}
