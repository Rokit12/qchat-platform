export const $ = (s, r = document) => r.querySelector(s);
export const $$ = (s, r = document) => [...r.querySelectorAll(s)];
export const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
export const clamp = (n, a, b) => Math.max(a, Math.min(b, n));
export const clip = (s, n) => (typeof s === 'string' ? s.slice(0, n) : '');
export function hashColor(s) { let h = 0; for (const c of String(s)) h = (h * 31 + c.charCodeAt(0)) | 0; return `hsl(${Math.abs(h) % 360} 55% 45%)`; }
export function nameColor(s) { let h = 0; for (const c of String(s)) h = (h * 17 + c.charCodeAt(0)) | 0; return `hsl(${Math.abs(h) % 360} 70% 65%)`; }
export const fmtTime = (t) => new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
export function fmtDay(t) {
  const d = new Date(t), now = new Date(); const y = new Date(now); y.setDate(now.getDate() - 1);
  if (d.toDateString() === now.toDateString()) return 'Today';
  if (d.toDateString() === y.toDateString()) return 'Yesterday';
  return d.toLocaleDateString([], { weekday: now - d < 6 * 864e5 ? 'long' : undefined, day: 'numeric', month: 'short', year: d.getFullYear() !== now.getFullYear() ? 'numeric' : undefined });
}
export const fmtListTime = (t) => (new Date(t).toDateString() === new Date().toDateString() ? fmtTime(t) : fmtDay(t));
export const fmtSize = (n) => (n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(0) + ' KB' : (n / 1048576).toFixed(1) + ' MB');
export function fmtDur(s) { s = Math.round(s || 0); return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`; }
export function fmtAgo(t) { const m = Math.round((Date.now() - t) / 60000); return m < 1 ? 'just now' : m < 60 ? `${m} min ago` : `${fmtDay(t) === 'Today' ? 'today' : fmtDay(t).toLowerCase()} at ${fmtTime(t)}`; }
let toastT;
export function toast(msg, ms = 2600) { const t = $('#toast'); t.textContent = msg; t.classList.remove('hidden'); clearTimeout(toastT); toastT = setTimeout(() => t.classList.add('hidden'), ms); }
export function deviceName() {
  const ua = navigator.userAgent;
  const b = /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : 'Browser';
  const os = /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iOS' : /Mac OS/.test(ua) ? 'macOS' : /Windows/.test(ua) ? 'Windows' : /Linux/.test(ua) ? 'Linux' : '';
  return `${b}${os ? ' on ' + os : ''}`;
}
// Serialize async work (session state must never be mutated concurrently)
export function mutex() { let p = Promise.resolve(); return (fn) => { const r = p.then(fn, fn); p = r.catch(() => {}); return r; }; }
