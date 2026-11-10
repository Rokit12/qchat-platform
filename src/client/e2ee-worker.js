// Frame-level end-to-end encryption for calls (runs in a Worker).
// Every encoded audio/video frame is encrypted with AES-256-GCM using a per-participant media key
// that was delivered inside the post-quantum ratchet. DTLS-SRTP still wraps the result, but the
// confidentiality of the media no longer depends on the classical (ECDHE) DTLS handshake.
//
// Frame layout: [codec header (cleartext, authenticated as AAD)] [ciphertext+tag] [IV 12B] [keyId 1B]
const prefixLen = (frame) => (frame.type === 'key' ? 10 : frame.type === 'delta' ? 3 : 1); // VP8 key/delta, audio
let sendKey = null;                 // { id, key: CryptoKey }
const recvKeys = new Map();         // peer -> Map(keyId -> CryptoKey)
const stats = { enc: 0, dec: 0, drop: 0 };

const importKey = (raw) => crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);

async function encodeFrame(frame, ctrl) {
  if (!sendKey) { stats.drop++; return; }                    // never send unencrypted media
  const data = new Uint8Array(frame.data); const p = Math.min(prefixLen(frame), data.length);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: data.subarray(0, p) }, sendKey.key, data.subarray(p)));
  const out = new Uint8Array(p + ct.length + 13);
  out.set(data.subarray(0, p)); out.set(ct, p); out.set(iv, p + ct.length); out[out.length - 1] = sendKey.id;
  frame.data = out.buffer; stats.enc++; ctrl.enqueue(frame);
}
async function decodeFrame(frame, ctrl, peer) {
  const data = new Uint8Array(frame.data); const p = Math.min(prefixLen(frame), data.length);
  if (data.length < p + 29) { stats.drop++; return; }
  const key = recvKeys.get(peer)?.get(data[data.length - 1]);
  if (!key) { stats.drop++; return; }
  try {
    const iv = data.subarray(data.length - 13, data.length - 1);
    const pt = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: data.subarray(0, p) }, key, data.subarray(p, data.length - 13)));
    const out = new Uint8Array(p + pt.length); out.set(data.subarray(0, p)); out.set(pt, p);
    frame.data = out.buffer; stats.dec++; ctrl.enqueue(frame);
  } catch { stats.drop++; }
}
function pipe(readable, writable, op, peer) {
  const transform = op === 'encode' ? encodeFrame : (f, c) => decodeFrame(f, c, peer);
  readable.pipeThrough(new TransformStream({ transform })).pipeTo(writable).catch(() => {});
}
self.onrtctransform = (e) => { const { op, peer } = e.transformer.options; pipe(e.transformer.readable, e.transformer.writable, op, peer); };
self.onmessage = async (e) => {
  const m = e.data;
  if (m.op === 'sendKey') sendKey = { id: m.id, key: await importKey(m.key) };
  else if (m.op === 'recvKey') {
    const map = recvKeys.get(m.peer) || new Map(); map.set(m.id, await importKey(m.key)); recvKeys.set(m.peer, map);
    while (map.size > 3) map.delete(map.keys().next().value);
  } else if (m.op === 'clearPeer') recvKeys.delete(m.peer);
  else if (m.op === 'reset') { sendKey = null; recvKeys.clear(); }
  else if (m.op === 'encode' || m.op === 'decode') pipe(m.readable, m.writable, m.op, m.peer);
  else if (m.op === 'stats') self.postMessage({ op: 'stats', ...stats });
};
