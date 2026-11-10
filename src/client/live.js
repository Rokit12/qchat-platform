// Live streaming from Status: one host streams camera + mic to their contacts, viewers send comments
// and hearts that pop up over the video for everyone.
//
// Security: same model as calls. Signalling, comments and hearts travel in ratchet-encrypted,
// ML-DSA-signed envelopes. Video/audio frames are AES-256-GCM encrypted in a Worker with a random
// media key that is delivered to each viewer inside the PQ ratchet. The relay server never sees
// the stream key, the title, or any comment.
//
// Topology: host -> each viewer (WebRTC, send-only). Good for small audiences (MAX_VIEWERS);
// a large broadcast would need an SFU that forwards the (still end-to-end encrypted) frames.
import { S, ME, DEV, sendPayload } from './core.js';
import { b64, unb64, rand, randId } from '../shared/crypto.js';
import { $, esc, fmtDur, toast } from './util.js';

const MAX_VIEWERS = 20, MAX_COMMENTS = 60, VIDEO_BITRATE = 900_000;
let ui = null; export function setLiveUI(x) { ui = x; }
export const lives = {};           // user -> { id, title, started, dev }  (contacts currently live)
let host = null;                    // my broadcast
let view = null;                    // the live I'm watching
let worker = null;
const pid = (u, d) => `${u}/${d}`;
const preview = () => !!window.__QCHAT_PREVIEW;
function getWorker() { worker ||= new Worker('e2ee-worker.js'); return worker; }
const useScript = () => typeof RTCRtpScriptTransform !== 'undefined';
function attach(side, op, peer) {
  if (useScript()) side.transform = new RTCRtpScriptTransform(getWorker(), { op, peer });
  else { const { readable, writable } = side.createEncodedStreams(); getWorker().postMessage({ op, peer, readable, writable }, [readable, writable]); }
}
const canRtc = () => !preview() && typeof RTCPeerConnection !== 'undefined' && (useScript() || (window.RTCRtpSender && 'createEncodedStreams' in RTCRtpSender.prototype));
async function waitIce(pc) {
  if (pc.iceGatheringState === 'complete') return;
  await new Promise((res) => { const t = setTimeout(res, 2500); pc.addEventListener('icegatheringstatechange', () => { if (pc.iceGatheringState === 'complete') { clearTimeout(t); res(); } }); });
}
const isLive = () => !!host;
export const watchingNow = () => !!view;

// ============================ host ============================
export async function goLive(title, audience, simStream) {
  if (host || view) return;
  let stream = simStream;
  if (!stream) {
    if (!canRtc()) return toast('Live streaming needs a browser with end-to-end encrypted media (recent Chrome, Edge, Firefox or Safari) over HTTPS.');
    try { stream = await navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: true, noiseSuppression: true }, video: { facingMode: 'user', width: { ideal: 720 }, height: { ideal: 1280 }, frameRate: { ideal: 30 } } }); }
    catch { return toast('Camera/microphone permission is needed to go live'); }
  }
  host = { id: randId(10), title: String(title || '').slice(0, 80), local: stream, peers: new Map(), viewers: new Map(), comments: [], started: Date.now(), facing: 'user', audience, sendKey: { id: 0, raw: rand(32) }, lastComment: new Map() };
  if (canRtc()) getWorker().postMessage({ op: 'sendKey', id: 0, key: host.sendKey.raw });
  ui.open({ role: 'host', user: ME(), title: host.title, stream, started: host.started });
  await sendPayload(audience, { type: 'live_start', live: host.id, title: host.title, started: host.started }, { push: 'live' });
  addComment({ id: randId(6), from: '', text: '🔴 You are live. Your contacts were notified.', sys: true });
}
export async function endLive() {
  if (!host) return; const h = host; host = null;
  for (const p of h.peers.values()) try { p.pc?.close(); } catch {}
  h.local.getTracks().forEach((t) => t.stop());
  getWorker().postMessage({ op: 'reset' });
  ui.close({ role: 'host', duration: Date.now() - h.started, viewers: h.maxViewers || h.viewers.size, comments: h.comments.length });
  await sendPayload(h.audience, { type: 'live_end', live: h.id });
}
export async function flipCamera() {
  if (!host || !navigator.mediaDevices?.getUserMedia) return;
  const facing = host.facing === 'user' ? 'environment' : 'user';
  let s; try { s = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { exact: facing }, width: { ideal: 720 }, height: { ideal: 1280 } } }); }
  catch { return toast('No other camera found'); }
  const track = s.getVideoTracks()[0], old = host.local.getVideoTracks()[0];
  for (const p of host.peers.values()) for (const snd of p.pc?.getSenders() || []) if (snd.track?.kind === 'video') await snd.replaceTrack(track);
  if (old) { host.local.removeTrack(old); old.stop(); }
  host.local.addTrack(track); host.facing = facing; ui.setLocal(host.local, facing);
}
export function toggleMic() { const t = host?.local.getAudioTracks()[0]; if (!t) return null; t.enabled = !t.enabled; return t.enabled; }

const viewerTargets = () => [...(host?.viewers.values() || [])].map((v) => ({ u: v.u, d: v.d }));
function toViewers(payload, except) {
  const targets = viewerTargets().filter((t) => !except || pid(t.u, t.d) !== except);
  if (!targets.length) return;
  return sendPayload([...new Set(targets.map((t) => t.u))], { type: payload.type, live: host.id, ...payload }, { ephemeral: true, devices: targets, self: false });
}
function broadcastStats() { if (!host) return; const n = new Set([...host.viewers.values()].map((v) => v.u)).size; host.maxViewers = Math.max(host.maxViewers || 0, n); ui.setViewers(n); toViewers({ type: 'live_stats', viewers: n }); }

async function hostJoin(from, fd, p) {
  const id = pid(from, fd);
  if (host.viewers.size >= MAX_VIEWERS && !host.viewers.has(id)) return sendPayload([from], { type: 'live_full', live: host.id }, { ephemeral: true, devices: [{ u: from, d: fd }], self: false });
  host.peers.get(id)?.pc?.close();
  host.viewers.set(id, { u: from, d: fd });
  const offer = { type: 'live_offer', live: host.id, title: host.title, started: host.started, comments: host.comments.slice(-30), viewers: new Set([...host.viewers.values()].map((v) => v.u)).size };
  if (canRtc()) {
    const pc = new RTCPeerConnection({ iceServers: S.ice || [] });
    host.peers.set(id, { pc, u: from, d: fd });
    for (const t of host.local.getTracks()) {
      const tr = pc.addTransceiver(t, { direction: 'sendonly', streams: [host.local] });
      attach(tr.sender, 'encode', id);
      if (t.kind === 'video') {
        try { const cs = RTCRtpReceiver.getCapabilities('video').codecs; tr.setCodecPreferences([...cs.filter((c) => /vp8/i.test(c.mimeType)), ...cs.filter((c) => /rtx|red|ulpfec/i.test(c.mimeType))]); } catch {}
        try { const prm = tr.sender.getParameters(); prm.encodings = [{ ...(prm.encodings?.[0] || {}), maxBitrate: VIDEO_BITRATE }]; await tr.sender.setParameters(prm); } catch {}
      }
    }
    pc.onconnectionstatechange = () => { if (['failed', 'closed'].includes(pc.connectionState)) dropViewer(id); };
    await pc.setLocalDescription(await pc.createOffer()); await waitIce(pc);
    Object.assign(offer, { sdp: pc.localDescription.sdp, key: b64(host.sendKey.raw), keyId: host.sendKey.id });
  } else host.peers.set(id, { pc: null, u: from, d: fd });
  await sendPayload([from], offer, { ephemeral: true, devices: [{ u: from, d: fd }], self: false });
  hostComment({ id: randId(6), from, text: 'joined', join: true });
  broadcastStats();
}
function dropViewer(id) { if (!host) return; host.peers.get(id)?.pc?.close(); host.peers.delete(id); if (host.viewers.delete(id)) broadcastStats(); }
function hostComment(c) {
  c.ts = Date.now(); host.comments.push(c); if (host.comments.length > MAX_COMMENTS) host.comments.shift();
  addComment(c); toViewers({ type: 'live_c', c });
}

// ============================ viewer ============================
export async function watch(user) {
  const l = lives[user]; if (!l || view || host) return;
  view = { id: l.id, host: user, dev: l.dev, title: l.title, started: l.started, pc: null, lastSend: 0 };
  ui.open({ role: 'viewer', user, title: l.title, started: l.started, connecting: true });
  await sendPayload([user], { type: 'live_join', live: l.id }, { ephemeral: true, devices: [{ u: user, d: l.dev }], self: false });
  view.timeout = setTimeout(() => { if (view && !view.joined) { leave(); toast(`${ui.name(user)}'s live isn't reachable right now`); } }, 15000);
}
export async function leave(silent) {
  if (!view) return; const v = view; view = null; clearTimeout(v.timeout);
  try { v.pc?.close(); } catch {} if (worker) worker.postMessage({ op: 'reset' });
  if (!silent) sendPayload([v.host], { type: 'live_leave', live: v.id }, { ephemeral: true, devices: [{ u: v.host, d: v.dev }], self: false });
  ui.close({ role: 'viewer' });
}
async function viewerOffer(from, fd, p) {
  view.joined = true; clearTimeout(view.timeout); view.title = p.title; view.started = p.started;
  ui.update({ title: p.title, started: p.started, viewers: p.viewers, connecting: !!p.sdp });
  for (const c of p.comments || []) addComment(c, true);
  if (!p.sdp) { // no media path (preview / host without WebRTC): show a stand-in stream if one is provided
    const sim = ui.simStream?.(from); if (sim) ui.setRemote(sim);
    return;
  }
  const id = pid(from, fd);
  const pc = view.pc = new RTCPeerConnection({ iceServers: S.ice || [] });
  getWorker().postMessage({ op: 'recvKey', peer: id, id: p.keyId, key: unb64(p.key) });
  const stream = new MediaStream();
  pc.ontrack = (e) => { attach(e.receiver, 'decode', id); stream.addTrack(e.track); ui.setRemote(stream); };
  pc.onconnectionstatechange = () => { if (pc.connectionState === 'connected') ui.update({ connecting: false }); if (pc.connectionState === 'failed') { toast('Lost connection to the live'); leave(true); } };
  await pc.setRemoteDescription({ type: 'offer', sdp: p.sdp });
  await pc.setLocalDescription(await pc.createAnswer()); await waitIce(pc);
  if (view?.pc === pc) await sendPayload([from], { type: 'live_answer', live: p.live, sdp: pc.localDescription.sdp }, { ephemeral: true, devices: [{ u: from, d: fd }], self: false });
}

// ============================ comments & hearts (both roles) ============================
export async function comment(text) {
  text = String(text || '').trim().slice(0, 200); if (!text) return;
  if (host) return hostComment({ id: randId(6), from: ME(), text });
  if (!view) return;
  if (Date.now() - view.lastSend < 800) return toast('Slow down a little 🙂');
  view.lastSend = Date.now();
  await sendPayload([view.host], { type: 'live_comment', live: view.id, text }, { ephemeral: true, devices: [{ u: view.host, d: view.dev }], self: false });
}
let heartBuf = 0, heartT;
export function heart() {
  ui.heart();
  if (host) { heartBuf++; clearTimeout(heartT); heartT = setTimeout(flushHearts, 300); return; }
  if (view) sendPayload([view.host], { type: 'live_react', live: view.id, n: 1 }, { ephemeral: true, devices: [{ u: view.host, d: view.dev }], self: false });
}
function flushHearts(except) { if (host && heartBuf) { toViewers({ type: 'live_r', n: Math.min(heartBuf, 10) }, except); heartBuf = 0; } }
function addComment(c, quiet) { ui.comment(c, quiet); }

// ============================ incoming signals ============================
export async function onSignal(from, fd, ts, p) {
  if (from === ME()) return; // my other devices: ignore
  switch (p.type) {
    case 'live_start':
      if (Date.now() - (p.started || ts) > 12 * 3600e3) return;
      lives[from] = { id: p.live, title: String(p.title || '').slice(0, 80), started: p.started || ts, dev: fd };
      ui.listChanged(); ui.notifyLive(from, lives[from]);
      return;
    case 'live_end':
      if (lives[from]?.id === p.live) delete lives[from];
      ui.listChanged();
      if (view?.id === p.live) { leave(true); ui.ended(from); }
      return;
  }
  if (host && p.live === host.id) {
    const id = pid(from, fd);
    switch (p.type) {
      case 'live_join': return hostJoin(from, fd, p);
      case 'live_answer': { const peer = host.peers.get(id); if (peer?.pc) await peer.pc.setRemoteDescription({ type: 'answer', sdp: p.sdp }); return; }
      case 'live_leave': return dropViewer(id);
      case 'live_comment': {
        if (!host.viewers.has(id)) return;
        const last = host.lastComment.get(id) || 0; if (Date.now() - last < 700) return; host.lastComment.set(id, Date.now());
        return hostComment({ id: randId(6), from, text: String(p.text || '').slice(0, 200) });
      }
      case 'live_react': if (host.viewers.has(id)) { ui.heart(); heartBuf += 1; clearTimeout(heartT); heartT = setTimeout(() => flushHearts(), 300); } return;
    }
  }
  if (view && p.live === view.id && from === view.host) {
    switch (p.type) {
      case 'live_offer': return viewerOffer(from, fd, p);
      case 'live_c': return addComment(p.c);
      case 'live_r': for (let i = 0; i < Math.min(p.n || 1, 10); i++) setTimeout(() => ui.heart(), i * 120); return;
      case 'live_stats': return ui.update({ viewers: p.viewers });
      case 'live_full': leave(true); return toast('This live is full right now');
    }
  }
}
let statsCb; export function liveStats() { return new Promise((r) => { statsCb = r; getWorker().onmessage = (e) => e.data.op === 'stats' && statsCb?.(e.data); getWorker().postMessage({ op: 'stats' }); }); }
export function liveInfo() { return { host: !!host, view: !!view }; }
export { isLive, fmtDur, esc, $ };
