// Voice & video calls (1:1 and group mesh, up to 8 people) with post-quantum frame encryption.
// Signalling (ring/join/offer/answer/key/leave) travels inside ratchet-encrypted, ML-DSA-signed envelopes.
import { S, ME, DEV, sendPayload } from './core.js';
import { b64, unb64, rand } from '../shared/crypto.js';
import { $, esc, fmtDur, toast } from './util.js';

const MAX_PARTICIPANTS = 8;
let ui = null; export function setCallUI(x) { ui = x; }
let call = null, worker = null;
const pid = (u, d) => `${u}/${d}`;
const myPid = () => pid(ME(), DEV());
export const inCall = () => !!call;
export const supportsE2EE = () => typeof RTCRtpScriptTransform !== 'undefined' || (window.RTCRtpSender && 'createEncodedStreams' in RTCRtpSender.prototype);
const useScriptTransform = () => typeof RTCRtpScriptTransform !== 'undefined';
function getWorker() { if (!worker) { worker = new Worker('e2ee-worker.js'); worker.onmessage = (e) => { if (e.data.op === 'stats') statsCb?.(e.data); }; } return worker; }
let statsCb; export function frameStats() { return new Promise((r) => { statsCb = r; getWorker().postMessage({ op: 'stats' }); }); }

function signal(p, opts = {}) {
  const payload = { type: 'rtc', call: call.id, ...p };
  if (call.g) payload.g = call.g; else payload.to = call.peerUser;
  return sendPayload(call.users, payload, { ephemeral: true, ...opts });
}
const signalTo = (u, d, p) => signal(p, { devices: [{ u, d }], self: u === ME() });

function newSendKey() {
  const id = call.sendKey ? (call.sendKey.id + 1) % 256 : 0;
  call.sendKey = { id, raw: rand(32) };
  return call.sendKey;
}
const keyMsg = () => ({ key: b64(call.sendKey.raw), keyId: call.sendKey.id });
function setRecvKey(peer, p) { if (p.key) getWorker().postMessage({ op: 'recvKey', peer, id: p.keyId, key: unb64(p.key) }); }

async function getMedia(video) {
  return navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: true, noiseSuppression: true }, video: video ? { width: { ideal: 1280 }, height: { ideal: 720 } } : false });
}
function attach(transceiverSide, op, peer) {
  if (useScriptTransform()) transceiverSide.transform = new RTCRtpScriptTransform(getWorker(), { op, peer });
  else { const { readable, writable } = transceiverSide.createEncodedStreams(); getWorker().postMessage({ op, peer, readable, writable }, [readable, writable]); }
}
async function waitIce(pc) {
  if (pc.iceGatheringState === 'complete') return;
  await new Promise((res) => { const t = setTimeout(res, 2500); pc.addEventListener('icegatheringstatechange', () => { if (pc.iceGatheringState === 'complete') { clearTimeout(t); res(); } }); });
}

function createPeer(u, d) {
  const id = pid(u, d);
  const cfg = { iceServers: S.ice || [] }; if (!useScriptTransform()) cfg.encodedInsertableStreams = true;
  const pc = new RTCPeerConnection(cfg);
  const peer = { id, u, d, pc, stream: null, connected: false };
  call.peers.set(id, peer);
  for (const track of call.local.getTracks()) attach(pc.addTrack(track, call.local), 'encode', id);
  // Attach decryption to receivers *before* negotiation: Chrome ignores receiver transforms set later
  // from ontrack when media flows both ways (frames would then reach the decoder still encrypted).
  for (const tr of pc.getTransceivers()) { attach(tr.receiver, 'decode', id); tr.receiver.__qe2ee = true; }
  // Frame headers must be predictable for encryption: prefer VP8 for video.
  for (const tr of pc.getTransceivers()) {
    if (tr.sender.track?.kind === 'video' && RTCRtpReceiver.getCapabilities) {
      const codecs = RTCRtpReceiver.getCapabilities('video').codecs;
      const vp8 = codecs.filter((c) => /vp8/i.test(c.mimeType)), rest = codecs.filter((c) => /rtx|red|ulpfec/i.test(c.mimeType));
      try { tr.setCodecPreferences([...vp8, ...rest]); } catch {}
    }
  }
  pc.ontrack = (e) => { if (!e.receiver.__qe2ee) { attach(e.receiver, 'decode', id); e.receiver.__qe2ee = true; } peer.stream = e.streams[0] || new MediaStream([e.track]); ui.render(call); };
  pc.onconnectionstatechange = () => {
    if (!call) return;
    if (pc.connectionState === 'connected') { peer.connected = true; call.connectedAt ||= Date.now(); clearTimeout(call.timeout); ui.render(call); }
    if (pc.connectionState === 'failed') closePeer(id, true);
  };
  return peer;
}
function closePeer(id, rotate) {
  const p = call?.peers.get(id); if (!p) return;
  try { p.pc.close(); } catch {}
  call.peers.delete(id); getWorker().postMessage({ op: 'clearPeer', peer: id });
  if (!call.peers.size && (call.connectedAt || !call.g)) return end(call.connectedAt ? null : 'Call ended');
  if (rotate && call.peers.size) rotateKey();
  ui.render(call);
}
// When someone leaves a group call, switch to a new media key they never saw.
function rotateKey() {
  newSendKey();
  for (const p of call.peers.values()) signalTo(p.u, p.d, { kind: 'key', ...keyMsg() });
  const k = call.sendKey; setTimeout(() => call?.sendKey === k && getWorker().postMessage({ op: 'sendKey', id: k.id, key: k.raw }), 800);
}

async function offerTo(u, d) {
  const peer = createPeer(u, d);
  const offer = await peer.pc.createOffer(); await peer.pc.setLocalDescription(offer); await waitIce(peer.pc);
  if (!call) return;
  await signalTo(u, d, { kind: 'offer', sdp: peer.pc.localDescription.sdp, video: call.video, ...keyMsg() });
}

/** Start a call from a chat. chat: {id, type, peer|gid, members} */
export async function startCall(chat, video, users) {
  if (call) return;
  if (!supportsE2EE()) return toast('This browser can\'t do end-to-end encrypted calls. Use a recent Chrome, Edge, Firefox or Safari.');
  if (!navigator.mediaDevices?.getUserMedia) return toast('Calls need HTTPS and microphone access');
  if (users.length + 1 > MAX_PARTICIPANTS) return toast(`Group calls support up to ${MAX_PARTICIPANTS} people`);
  call = { id: b64(rand(9)).replace(/[+/=]/g, ''), chatId: chat.id, g: chat.type === 'group' ? chat.gid : null, peerUser: chat.peer, users, video, role: 'caller', joined: true, peers: new Map(), started: Date.now() };
  try { call.local = await getMedia(video); } catch { call = null; return toast('Could not access microphone/camera'); }
  newSendKey(); getWorker().postMessage({ op: 'sendKey', id: call.sendKey.id, key: call.sendKey.raw });
  ui.show(call, 'Calling…', false);
  await signal({ kind: 'ring', video }, { push: 'call' });
  call.timeout = setTimeout(() => { if (call && !call.connectedAt && !call.peers.size) { signal({ kind: 'leave' }); end('No answer'); } }, 45000);
}

export async function onSignal(from, fd, p, chatId, users) {
  const id = pid(from, fd);
  if (from === ME()) { // my other devices
    if (call?.id === p.call && call.ringing && (p.kind === 'join' || p.kind === 'decline')) end(null, true);
    return;
  }
  if (p.kind === 'ring') {
    if (call) { if (call.id !== p.call) signalToRaw(from, fd, p, { kind: 'busy' }); return; }
    call = { id: p.call, chatId, g: p.g || null, peerUser: p.g ? null : from, users, video: !!p.video, role: 'callee', ringing: true, joined: false, caller: { u: from, d: fd }, peers: new Map(), started: Date.now() };
    ui.show(call, `Incoming ${p.video ? 'video' : 'voice'} call…`, true);
    ui.ringNotify(call, from);
    call.timeout = setTimeout(() => { if (call?.ringing) end('Missed'); }, 45000);
    return;
  }
  if (!call || call.id !== p.call) return;
  switch (p.kind) {
    case 'join':
      if (!call.joined || call.peers.has(id)) return;
      if (call.peers.size + 1 >= MAX_PARTICIPANTS) return;
      if (myPid() < id) await offerTo(from, fd);
      else if (!p.reply) await signalTo(from, fd, { kind: 'join', reply: true });
      return;
    case 'offer': {
      if (!call.joined) return;
      if (call.peers.has(id)) { try { call.peers.get(id).pc.close(); } catch {} call.peers.delete(id); }
      const peer = createPeer(from, fd);
      setRecvKey(id, p);
      await peer.pc.setRemoteDescription({ type: 'offer', sdp: p.sdp });
      const ans = await peer.pc.createAnswer(); await peer.pc.setLocalDescription(ans); await waitIce(peer.pc);
      if (call) await signalTo(from, fd, { kind: 'answer', sdp: peer.pc.localDescription.sdp, ...keyMsg() });
      return;
    }
    case 'answer': { const peer = call.peers.get(id); if (!peer) return; setRecvKey(id, p); await peer.pc.setRemoteDescription({ type: 'answer', sdp: p.sdp }); return; }
    case 'key': setRecvKey(id, p); return;
    case 'leave': if (call.ringing && from === call.caller.u && !call.g) return end('Missed'); closePeer(id, true); return;
    case 'decline': if (!call.g && call.role === 'caller') end('Declined'); return;
    case 'busy': if (!call.g && call.role === 'caller') end('Busy'); return;
  }
}
function signalToRaw(u, d, p, extra) { // reply about a call we're not in
  const payload = { type: 'rtc', call: p.call, ...extra }; if (p.g) payload.g = p.g; else payload.to = u;
  return sendPayload([u], payload, { ephemeral: true, devices: [{ u, d }], self: false });
}

export async function accept() {
  if (!call?.ringing) return;
  call.ringing = false; clearTimeout(call.timeout);
  try { call.local = await getMedia(call.video); } catch { signal({ kind: 'decline' }); return end('Could not access microphone/camera'); }
  newSendKey(); getWorker().postMessage({ op: 'sendKey', id: call.sendKey.id, key: call.sendKey.raw });
  call.joined = true; ui.show(call, 'Connecting…', false);
  await signal({ kind: 'join', video: call.video });
  call.timeout = setTimeout(() => { if (call && !call.connectedAt) end('Could not connect'); }, 30000);
}
export function hangUp() {
  if (!call) return;
  if (call.ringing) { signal({ kind: 'decline' }); return end('Declined'); }
  signal({ kind: 'leave' }); end(null);
}
export function toggle(kind) {
  const t = kind === 'audio' ? call?.local?.getAudioTracks()[0] : call?.local?.getVideoTracks()[0];
  if (!t) return null; t.enabled = !t.enabled; return t.enabled;
}
function end(reason, silent) {
  if (!call) return; const c = call; call = null;
  clearTimeout(c.timeout);
  for (const p of c.peers.values()) try { p.pc.close(); } catch {}
  c.local?.getTracks().forEach((t) => t.stop());
  getWorker().postMessage({ op: 'reset' });
  ui.hide();
  if (!silent) ui.log(c, reason);
}
export function callInfo() { return call; }
