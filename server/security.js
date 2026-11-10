// Server-side defences: rate limiting, automatic IP bans, proof-of-work, intrusion detection & alerting.
// Shared across instances through Redis when REDIS_URL is set (so an attacker can't spread load).
import crypto from 'node:crypto';

const cfg = (k, d) => (process.env[k] !== undefined ? Number(process.env[k]) : d);
export const LIMITS = {
  connPerIp: cfg('MAX_CONN_PER_IP', 30),            // concurrent WebSockets per IP
  connRatePerIp: cfg('CONN_RATE_PER_IP', 60),       // new WebSockets per IP per minute
  httpRatePerIp: cfg('HTTP_RATE_PER_IP', 600),      // HTTP requests per IP per minute
  authFailPerIp: cfg('AUTH_FAIL_PER_IP', 20),       // failed logins per IP per 10 min before a ban
  enrollFailPerUser: cfg('ENROLL_FAIL_PER_USER', 5),// wrong recovery keys per username per 15 min before lockout
  regPerIpHour: cfg('REG_PER_IP_HOUR', 10),         // new accounts per IP per hour
  powBits: cfg('POW_BITS', 18),                     // proof-of-work difficulty for enrolment (~0.5 s in a browser)
  powBitsMax: cfg('POW_BITS_MAX', 24),
  lookupPerMin: cfg('LOOKUP_PER_MIN', 120),         // username lookups per account per minute (anti-enumeration)
  newContactsPerDay: cfg('NEW_CONTACTS_PER_DAY', 300),
  newContactsPerDayNew: cfg('NEW_CONTACTS_PER_DAY_NEW_ACCOUNT', 60),
  newContactsPerDayReported: cfg('NEW_CONTACTS_PER_DAY_REPORTED', 10),
  sendPerMin: cfg('SEND_PER_MIN', 900),
  strikeBan: cfg('STRIKE_BAN', 40),                 // strike points in 10 min that trigger a ban
  banSeconds: cfg('BAN_SECONDS', 900),
};
const SEVERITY = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const SCANNER_PATHS = /(^|\/)(\.env|\.git|\.svn|\.htaccess|\.DS_Store|wp-(admin|login|content|includes)|xmlrpc\.php|phpmyadmin|pma|adminer|cgi-bin|vendor\/phpunit|actuator|server-status|config\.(json|php|yml)|backup|\.aws|\.ssh|id_rsa|etc\/passwd|boaform|HNAP1|owa|autodiscover)/i;

export function createSecurity({ store, bus }) {
  const redis = bus.kind === 'redis' ? bus.pub : null;
  const mem = new Map(); // key -> { n, exp }
  const ipSecret = process.env.IP_HASH_SECRET || crypto.randomBytes(32).toString('hex');
  const ipHash = (ip) => crypto.createHmac('sha256', ipSecret).update(String(ip)).digest('hex').slice(0, 16);
  setInterval(() => { const now = Date.now(); for (const [k, v] of mem) if (v.exp < now) mem.delete(k); }, 60000).unref();

  async function hit(key, windowSec, by = 1) {
    if (redis) { const k = 'qchat:rl:' + key; const n = await redis.incrBy(k, by); if (n === by) await redis.expire(k, windowSec); return n; }
    const now = Date.now(); let e = mem.get(key);
    if (!e || e.exp < now) { e = { n: 0, exp: now + windowSec * 1000 }; mem.set(key, e); }
    e.n += by; return e.n;
  }
  async function peek(key) { if (redis) return Number(await redis.get('qchat:rl:' + key)) || 0; const e = mem.get(key); return e && e.exp > Date.now() ? e.n : 0; }
  async function reset(key) { if (redis) await redis.del('qchat:rl:' + key); else mem.delete(key); }
  /** true if under the limit */
  const allow = async (key, limit, windowSec, by) => (await hit(key, windowSec, by)) <= limit;

  // ---------- bans ----------
  const localBans = new Map();
  async function isBanned(ip) {
    if (redis) return !!(await redis.exists('qchat:ban:' + ip));
    const t = localBans.get(ip); if (!t) return false; if (t < Date.now()) { localBans.delete(ip); return false; } return true;
  }
  async function ban(ip, seconds, reason) {
    const prior = await hit('bans:' + ip, 86400); const secs = Math.min(seconds * 2 ** (prior - 1), 86400); // escalate repeat offenders
    if (redis) await redis.set('qchat:ban:' + ip, reason, { EX: secs }); else localBans.set(ip, Date.now() + secs * 1000);
    await event('ip_banned', 'high', { ip, detail: { reason, seconds: secs } });
  }
  async function unban(ip) { if (redis) await redis.del('qchat:ban:' + ip); else localBans.delete(ip); await reset('strikes:' + ip); }
  async function listBans() {
    if (redis) { const keys = await redis.keys('qchat:ban:*'); return Promise.all(keys.map(async (k) => ({ ip: k.slice(10), reason: await redis.get(k), ttl: await redis.ttl(k) }))); }
    return [...localBans].filter(([, t]) => t > Date.now()).map(([ip, t]) => ({ ip, ttl: Math.round((t - Date.now()) / 1000) }));
  }
  /** Add suspicion points to an IP; enough points within 10 minutes → automatic ban. */
  async function strike(ip, points, reason) {
    if (!ip) return false;
    const n = await hit('strikes:' + ip, 600, points);
    if (n >= LIMITS.strikeBan) { await reset('strikes:' + ip); await ban(ip, LIMITS.banSeconds, reason); return true; }
    return false;
  }

  // ---------- proof of work (raises the cost of mass sign-ups & key-guessing) ----------
  async function powBits() {
    const recent = await peek('enroll:global'); // adaptive: more enrolments per minute → harder puzzles
    return Math.min(LIMITS.powBitsMax, LIMITS.powBits + (recent > 120 ? 4 : recent > 30 ? 2 : 0));
  }
  function verifyPow(nonce, user, device, counter, bits) {
    if (!bits) return true;
    if (!Number.isSafeInteger(counter) || counter < 0) return false;
    const h = crypto.createHash('sha256').update(`qchat-pow|${nonce}|${user}|${device}|${counter}`).digest();
    let zeros = 0; for (const b of h) { if (b === 0) { zeros += 8; continue; } zeros += Math.clz32(b) - 24; break; }
    return zeros >= bits;
  }

  // ---------- intrusion detection log ----------
  const listeners = new Set();
  async function event(type, severity, { ip, user, detail } = {}) {
    const e = { ts: Date.now(), type, severity, username: user || null, ipHash: ip ? ipHash(ip) : null, detail: detail || {} };
    console.log(JSON.stringify({ level: 'security', ...e }));
    await store.addSecurityEvent(e).catch((err) => console.error('security log', err.message));
    for (const l of listeners) l(e);
    if (SEVERITY[severity] >= SEVERITY.high && process.env.SECURITY_WEBHOOK_URL) {
      fetch(process.env.SECURITY_WEBHOOK_URL, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ text: `🚨 QChat security: ${type} (${severity})${user ? ' user=' + user : ''}`, event: e }) }).catch(() => {});
    }
    return e;
  }
  const isScannerPath = (p) => SCANNER_PATHS.test(p);

  return { hit, allow, peek, reset, isBanned, ban, unban, listBans, strike, powBits, verifyPow, event, onEvent: (f) => listeners.add(f), ipHash, isScannerPath };
}

export function clientIp(req) {
  const hdr = process.env.TRUSTED_IP_HEADER; // e.g. cf-connecting-ip behind Cloudflare
  if (hdr && req.headers[hdr]) return String(req.headers[hdr]).split(',')[0].trim();
  if (process.env.TRUST_PROXY === '1' && req.headers['x-forwarded-for']) { const parts = String(req.headers['x-forwarded-for']).split(',').map((s) => s.trim()); return parts[parts.length - 1 - Number(process.env.PROXY_HOPS || 0)] || parts[0]; }
  return (req.socket.remoteAddress || '').replace(/^::ffff:/, '');
}
export const timingSafeEqual = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };
