// Cross-instance messaging + presence. In-memory by default; Redis (REDIS_URL) to run many servers.
import crypto from 'node:crypto';

const PRESENCE_TTL = 90_000;

class LocalBus {
  constructor() { this.handlers = new Map(); this.presence = new Map(); this.kind = 'local'; }
  async start(onEvent) { this.onEvent = onEvent; }
  async broadcast(ev) { this.onEvent?.(ev); }
  async subscribeUser(u, fn) { this.handlers.set(u, fn); }
  async unsubscribeUser(u) { this.handlers.delete(u); }
  async publishUser(u, msg) { this.handlers.get(u)?.(msg); }
  async setOnline(u, d, on) {
    const m = this.presence.get(u) || new Map();
    if (on) m.set(d, Date.now()); else m.delete(d);
    this.presence.set(u, m);
    this.onEvent?.({ u });
  }
  async refresh(list) { for (const [u, d] of list) this.presence.get(u)?.set(d, Date.now()); }
  async onlineDevices(u) { const m = this.presence.get(u); if (!m) return []; const now = Date.now(); return [...m].filter(([, t]) => now - t < PRESENCE_TTL).map(([d]) => d); }
  async close() {}
}

class RedisBus {
  constructor(url) { this.url = url; this.kind = 'redis'; this.id = crypto.randomBytes(6).toString('hex'); this.handlers = new Map(); }
  async start(onEvent) {
    const { createClient } = await import('redis');
    this.pub = createClient({ url: this.url }); this.sub = this.pub.duplicate();
    this.pub.on('error', (e) => console.error('redis', e.message)); this.sub.on('error', (e) => console.error('redis', e.message));
    await this.pub.connect(); await this.sub.connect();
    await this.sub.subscribe('qchat:events', (raw) => onEvent(JSON.parse(raw)));
  }
  async broadcast(ev) { await this.pub.publish('qchat:events', JSON.stringify(ev)); }
  async subscribeUser(u, fn) {
    if (this.handlers.has(u)) { this.handlers.set(u, fn); return; }
    this.handlers.set(u, fn);
    await this.sub.subscribe('qchat:u:' + u, (raw) => this.handlers.get(u)?.(JSON.parse(raw)));
  }
  async unsubscribeUser(u) { if (this.handlers.delete(u)) await this.sub.unsubscribe('qchat:u:' + u); }
  async publishUser(u, msg) { await this.pub.publish('qchat:u:' + u, JSON.stringify(msg)); }
  async setOnline(u, d, on) {
    if (on) await this.pub.zAdd('qchat:pres:' + u, { score: Date.now(), value: d }); else await this.pub.zRem('qchat:pres:' + u, d);
    await this.pub.pExpire('qchat:pres:' + u, PRESENCE_TTL * 2);
    await this.pub.publish('qchat:events', JSON.stringify({ u }));
  }
  async refresh(list) {
    if (!list.length) return;
    const m = this.pub.multi(); const now = Date.now();
    for (const [u, d] of list) { m.zAdd('qchat:pres:' + u, { score: now, value: d }); m.pExpire('qchat:pres:' + u, PRESENCE_TTL * 2); }
    await m.exec();
  }
  async onlineDevices(u) { return this.pub.zRangeByScore('qchat:pres:' + u, Date.now() - PRESENCE_TTL, '+inf'); }
  async close() { await this.sub.quit(); await this.pub.quit(); }
}

export function openBus(url) { return url ? new RedisBus(url) : new LocalBus(); }
