// Service health monitor: checks every component, records uptime history and opens/closes incidents.
// One instance (the "leader", elected through the shared admin DB) checks shared services so results
// aren't duplicated; every instance reports its own heartbeat.
import net from 'node:net';
import os from 'node:os';
import WebSocket from 'ws';

export const SERVICES = [
  { id: 'api', name: 'App servers', public: 'App' },
  { id: 'realtime', name: 'Real-time messaging relay', public: 'Messaging' },
  { id: 'database', name: 'Chat database', public: 'Accounts & message delivery' },
  { id: 'admin_database', name: 'Admin & analytics database', public: null },
  { id: 'redis', name: 'Redis (multi-server sync)', public: null },
  { id: 'turn', name: 'Call relay (TURN)', public: 'Voice & video calls' },
  { id: 'push', name: 'Push notifications', public: 'Notifications' },
];
const INTERVAL = Number(process.env.MONITOR_INTERVAL_MS || 30000);
const withTimeout = (p, ms = 4000) => Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error('timeout after ' + ms + ' ms')), ms))]);

export function createMonitor({ store, adminStore, bus, sec, port, instanceId, localStats, vapidReady }) {
  const started = Date.now();
  const fails = {}; const live = {}; let leader = false, timer = null, cache = null, cacheAt = 0;
  const configured = (id) => (id === 'redis' ? bus.kind === 'redis' : id === 'turn' ? !!process.env.TURN_URL : true);

  async function probe(id) {
    const t = Date.now();
    switch (id) {
      case 'api': { const n = (await adminStore.listInstances(Date.now() - 3 * INTERVAL)).length || 1; return { detail: `${n} instance${n === 1 ? '' : 's'} running` }; }
      case 'database': await withTimeout(store.ping()); return { latency: Date.now() - t };
      case 'admin_database': await withTimeout(adminStore.ping()); return { latency: Date.now() - t };
      case 'redis': await withTimeout(bus.pub.ping()); return { latency: Date.now() - t };
      case 'realtime': await withTimeout(new Promise((res, rej) => { const ws = new WebSocket(`ws://127.0.0.1:${port}`); ws.on('open', () => { ws.close(); res(); }); ws.on('error', rej); ws.on('unexpected-response', (_, r) => rej(new Error('HTTP ' + r.statusCode))); })); return { latency: Date.now() - t };
      case 'turn': {
        const u = process.env.TURN_URL.split(',')[0].replace(/^turns?:/, ''); const [host, rest] = u.split(':'); const p = Number((rest || '3478').split('?')[0]);
        await withTimeout(new Promise((res, rej) => { const s = net.connect(p, host, () => { s.end(); res(); }); s.on('error', rej); })); return { latency: Date.now() - t };
      }
      case 'push': if (!vapidReady()) throw new Error('VAPID keys missing'); return { detail: 'configured' };
    }
  }
  async function tick() {
    const ls = localStats();
    try { await adminStore.heartbeat({ id: instanceId, host: os.hostname(), started, connections: ls.connections, users: ls.users }); } catch {}
    try { const alive = await adminStore.listInstances(Date.now() - 3 * INTERVAL); leader = !alive.length || alive.sort((a, b) => (a.id < b.id ? -1 : 1))[0].id === instanceId; } catch { leader = true; }
    if (!leader) return;
    const rows = [];
    for (const s of SERVICES) {
      if (!configured(s.id)) continue;
      let ok = true, latency = null, detail = null;
      try { const r = await probe(s.id); latency = r.latency ?? null; detail = r.detail || null; } catch (e) { ok = false; detail = String(e.message || e).slice(0, 200); }
      rows.push({ ts: Date.now(), service: s.id, ok, latency, detail });
      live[s.id] = { ok, latency, detail, ts: Date.now() };
      // incidents: 2 consecutive failures open one; the first success closes it
      if (!ok) {
        fails[s.id] = (fails[s.id] || 0) + 1;
        if (fails[s.id] === 2) { await adminStore.openIncident(s.id, detail).catch(() => {}); await sec.event('service_down', 'critical', { detail: { service: s.name, error: detail } }).catch(() => {}); }
      } else {
        if ((fails[s.id] || 0) >= 2) { await adminStore.closeIncident(s.id).catch(() => {}); await sec.event('service_recovered', 'high', { detail: { service: s.name } }).catch(() => {}); }
        fails[s.id] = 0;
      }
    }
    try { await adminStore.addHealth(rows); } catch (e) { console.error('health log', e.message); }
    cache = null;
  }
  function start() { tick(); timer = setInterval(tick, INTERVAL); timer.unref?.(); }

  /** Full status (admin) — cached for 20 s. */
  async function status() {
    if (cache && Date.now() - cacheAt < 20000) return cache;
    const now = Date.now();
    const [b24, b30, last, incidents, instances] = await Promise.all([
      adminStore.healthBuckets(now - 864e5, 1800e3), adminStore.healthBuckets(now - 30 * 864e5, 864e5), adminStore.lastHealth(), adminStore.listIncidents(now - 30 * 864e5), adminStore.listInstances(now - 3 * INTERVAL),
    ]);
    const services = SERVICES.map((s) => {
      if (!configured(s.id)) return { ...s, state: 'not_configured' };
      const cur = live[s.id] || last.find((l) => l.service === s.id);
      const mine24 = b24.filter((r) => r.service === s.id), mine30 = b30.filter((r) => r.service === s.id);
      const pct = (rows) => { const t = rows.reduce((a, r) => a + r.total, 0); return t ? Math.round((rows.reduce((a, r) => a + r.ok, 0) / t) * 10000) / 100 : null; };
      const bars = (rows, n, size) => Array.from({ length: n }, (_, i) => {
        const b = Math.floor((now - (n - 1 - i) * size) / size); const r = rows.find((x) => x.b === b);
        return r ? (r.ok === r.total ? 'up' : r.ok === 0 ? 'down' : 'partial') : 'none';
      });
      const lat = mine24.filter((r) => r.lat != null);
      return {
        ...s, state: !cur ? 'unknown' : cur.ok ? 'up' : 'down', checkedAt: cur?.ts || null, latency: cur?.latency ?? null, detail: cur?.detail || null,
        uptime24h: pct(mine24), uptime30d: pct(mine30), avgLatency24h: lat.length ? Math.round(lat.reduce((a, r) => a + r.lat, 0) / lat.length) : null,
        bars24h: bars(mine24, 48, 1800e3), bars30d: bars(mine30, 30, 864e5),
      };
    });
    const down = services.filter((s) => s.state === 'down');
    cache = { overall: down.length ? (down.some((s) => ['api', 'realtime', 'database'].includes(s.id)) ? 'major_outage' : 'degraded') : 'operational', services, incidents, instances, checkedAt: now, intervalMs: INTERVAL };
    cacheAt = now; return cache;
  }
  /** Public status: no internals (hosts, latencies, error messages). */
  async function publicStatus() {
    const s = await status();
    return {
      overall: s.overall, checkedAt: s.checkedAt,
      services: s.services.filter((x) => x.public && x.state !== 'not_configured').map((x) => ({ name: x.public, state: x.state, uptime30d: x.uptime30d, bars30d: x.bars30d })),
      incidents: s.incidents.filter((i) => SERVICES.find((x) => x.id === i.service)?.public).slice(0, 10).map((i) => ({ service: SERVICES.find((x) => x.id === i.service).public, started: i.started, ended: i.ended })),
    };
  }
  return { start, tick, status, publicStatus, stop: () => clearInterval(timer) };
}
