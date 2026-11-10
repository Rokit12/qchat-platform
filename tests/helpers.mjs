// Shared helpers for server/security integration tests.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import path from 'node:path';
import WebSocket from 'ws';
import * as C from '../src/shared/crypto.js';
import { newSession, needsBundle } from '../src/shared/ratchet.js';
import { seal, open } from '../src/shared/envelope.js';
export const TEST_ENV = { REG_PER_IP_HOUR: '1000', POW_BITS: '10', STRIKE_BAN: '100000', AUTH_FAIL_PER_IP: '100000', LOOKUP_PER_MIN: '100000' };
export const ROOT = path.join(path.dirname(new URL(import.meta.url).pathname), '..');
export async function startServer(port, env) {
  const p = spawn(process.execPath, ['server/index.js'], { cwd: ROOT, env: { ...process.env, ...TEST_ENV, PORT: String(port), ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
  let log = ''; p.stdout.on('data', (d) => (log += d)); p.stderr.on('data', (d) => (log += d));
  for (let i = 0; i < 100 && !log.includes('running'); i++) await new Promise((r) => setTimeout(r, 100));
  if (!log.includes('running')) throw new Error('server failed: ' + log);
  p.log = () => log; return p;
}

export class Client {
  constructor(port, user, acct) { this.port = port; this.user = user; this.acct = acct; this.dev = C.newDevice(); this.inbox = []; this.waiters = []; this.sessions = {}; this.spks = {}; this.otpks = {}; }
  connect() {
    this.ws = new WebSocket(`ws://localhost:${this.port}`);
    this.ws.on('message', (raw) => { const m = JSON.parse(raw); this.inbox.push(m); this.waiters = this.waiters.filter((w) => !w(m)); });
    return new Promise((r) => this.ws.on('open', r));
  }
  sendRaw(o) { this.ws.send(JSON.stringify(o)); }
  next(pred, ms = 5000) {
    const hit = this.inbox.findIndex(pred); if (hit >= 0) return Promise.resolve(this.inbox.splice(hit, 1)[0]);
    return new Promise((res, rej) => { const t = setTimeout(() => rej(new Error('timeout waiting in ' + this.user)), ms); this.waiters.push((m) => { if (!pred(m)) return false; clearTimeout(t); this.inbox.splice(this.inbox.indexOf(m), 1); res(m); return true; }); });
  }
  async login({ register = false, tamper } = {}) {
    await this.connect();
    this.sendRaw({ t: 'hello', user: this.user, device: this.dev.device });
    const ch = await this.next((m) => m.t === 'challenge' || m.t === 'auth_error');
    if (ch.t === 'auth_error') return ch;
    if (ch.deviceKnown) { this.sendRaw({ t: 'auth', sig: C.dsaSign(C.AUTH_DOMAIN, { user: this.user, device: this.dev.device, nonce: ch.nonce }, C.unb64(this.dev.sigSk)) }); }
    else {
      const prev = ch.deviceList; const version = prev ? prev.version + 1 : 1;
      const list = C.makeDeviceList(this.user, version, [...(prev?.devices || []), this.dev.device], this.acct.aikSk);
      const cert = C.makeCert(this.user, this.dev, tamper === 'cert' ? C.accountKeys(C.newAccountSeeds()).aikSk : this.acct.aikSk);
      const spk = C.makePrekey(this.user, this.dev.device, 'spk', 1, this.dev.sigSk); this.spks[1] = spk.sk;
      const otpks = []; for (let i = 1; i <= 3; i++) { const k = C.makePrekey(this.user, this.dev.device, 'otpk', i, this.dev.sigSk); this.otpks[i] = k.sk; otpks.push(k.pub); }
      const pow = tamper === 'pow' ? -1 : await C.solvePow(ch.nonce, this.user, this.dev.device, ch.pow);
      this.sendRaw({ t: 'enroll', pow, register, aik: C.b64(this.acct.aikPk), cert, deviceList: list, spk: spk.pub, otpks, profile: { displayName: this.displayName || this.user },
        aikSig: C.dsaSign(C.ENROLL_DOMAIN, { user: this.user, device: this.dev.device, nonce: ch.nonce, list: list.version }, this.acct.aikSk),
        sig: C.dsaSign(C.AUTH_DOMAIN, { user: this.user, device: this.dev.device, nonce: ch.nonce }, C.unb64(this.dev.sigSk)) });
    }
    return this.next((m) => m.t === 'ready' || m.t === 'auth_error');
  }
  me() { return { user: this.user, device: this.dev.device, sigSk: C.unb64(this.dev.sigSk) }; }
  keys() { return { getSpk: (id) => this.spks[id], getOtpk: (id) => this.otpks[id] }; }
  async rpc(o, t) { const rid = Math.random(); this.sendRaw({ ...o, rid }); return this.next((m) => m.t === t && m.rid === rid); }
  async sendTo(user, payload) {
    const look = (await this.rpc({ t: 'lookup', username: user }, 'lookup')).user;
    assert.ok(C.verifyDeviceList(look.deviceList, user, look.aik));
    const devices = look.devices.filter((d) => C.verifyCert(d.cert, user, look.aik));
    const needs = devices.filter((d) => needsBundle(this.sessions[user + ':' + d.device]));
    const bundles = needs.length ? (await this.rpc({ t: 'bundle', username: user, devices: needs.map((d) => d.device) }, 'bundle')).bundles : [];
    const recips = devices.map((d) => {
      const key = user + ':' + d.device; this.sessions[key] ||= newSession(user, d.device);
      const b = bundles.find((x) => x.device === d.device);
      return { user, device: d.device, session: this.sessions[key], bundle: b && { sigPk: d.cert.sigPk, spk: b.spk, otpk: b.otpk || undefined } };
    });
    const id = C.randId();
    const env = await seal(this.me(), id, recips, payload);
    this.sendRaw({ t: 'send', id, to: recips.map((r) => ({ u: r.user, d: r.device })), env, push: 'msg' });
    await this.next((m) => m.t === 'sent' && m.id === id);
    return { id, devices: devices.length };
  }
  async receive(senderCert) {
    const m = await this.next((x) => x.t === 'env');
    const key = m.from + ':' + m.fd;
    const r = await open(this.me(), m.env, senderCert.sigPk, this.sessions[key], this.keys());
    this.sessions[key] = r.session; if (r.usedOtpk != null) delete this.otpks[r.usedOtpk];
    this.sendRaw({ t: 'ack', ids: [m.id] });
    return { ...m, payload: r.payload };
  }
  close() { this.ws?.close(); }
}

