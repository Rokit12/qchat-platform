// Intrusion-detection dashboard (served only when ADMIN_TOKEN is configured).
(() => {
  const $ = (s) => document.querySelector(s);
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  let token = sessionStorage.getItem('qchat-admin') || '';
  const LABEL = {
    account_takeover_attempt: 'Wrong recovery key for an existing account', account_locked: 'Account locked after repeated takeover attempts',
    device_linked: 'New device linked to an account', bad_device_signature: 'Forged device login signature', auth_failed: 'Failed login',
    ip_banned: 'IP automatically banned', scanner_probe: 'Vulnerability-scanner probe', ws_bad_origin: 'Cross-site WebSocket hijacking attempt',
    mass_registration: 'Mass account creation', reserved_username_attempt: 'Tried to register a reserved/official name', impersonation_attempt: 'Impersonating display name',
    enumeration_suspected: 'Username enumeration', spam_suspected: 'Spam: too many new conversations', user_reported: 'User reported', account_restricted: 'Account restricted (5+ reports)',
    rate_limited: 'Rate limited', send_flood: 'Message flood', admin_auth_failed: 'Failed admin login', queue_full: 'Offline queue full', account_created: 'Account created',
    enroll_while_locked: 'Login attempt on a locked account', admin_unban: 'Admin unbanned an IP',
  };
  async function api(path, opts = {}) {
    const r = await fetch(path, { ...opts, headers: { authorization: 'Bearer ' + token, 'content-type': 'application/json' } });
    if (r.status === 401) throw new Error('Wrong token');
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return r.json();
  }
  async function refresh() {
    try {
      const s = await api('/admin/api/summary');
      const sev = s.last24h.bySeverity;
      $('#admCards').innerHTML = [['Events (24h)', s.last24h.total], ['Critical', sev.critical || 0], ['High', sev.high || 0], ['Active bans', s.bans.length], ['Online devices', s.connections], ['Unauthenticated sockets', s.unauthenticated]]
        .map(([k, v]) => `<div class="adm-card ${k === 'Critical' && v ? 'crit' : k === 'High' && v ? 'high' : ''}"><b>${v}</b><span>${k}</span></div>`).join('');
      $('#admTypes').innerHTML = Object.entries(s.last24h.byType).sort((a, b) => b[1] - a[1]).map(([t, n]) => `<tr><td>${esc(LABEL[t] || t)}</td><td class="num">${n}</td></tr>`).join('') || '<tr><td class="muted">Nothing yet</td></tr>';
      $('#admBans').innerHTML = s.bans.map((b) => `<tr><td><code>${esc(b.ip)}</code></td><td class="muted">${esc(b.reason || '')}</td><td>${Math.round(b.ttl / 60)} min</td><td><button class="btn" data-unban="${esc(b.ip)}">Unban</button></td></tr>`).join('') || '<tr><td class="muted">No active bans</td></tr>';
      const q = new URLSearchParams({ limit: 300 }); if ($('#admSev').value) q.set('minSeverity', $('#admSev').value); if ($('#admUser').value.trim()) q.set('user', $('#admUser').value.trim().toLowerCase());
      const ev = await api('/admin/api/events?' + q);
      $('#admEvents').innerHTML = '<tr><th>Time</th><th>Severity</th><th>Event</th><th>User</th><th>IP (hashed)</th><th>Details</th></tr>' + ev.map((e) => `<tr class="sev-${e.severity}"><td>${new Date(e.ts).toLocaleString()}</td><td><span class="sev">${e.severity}</span></td><td>${esc(LABEL[e.type] || e.type)}</td><td>${esc(e.username || '')}</td><td><code>${esc(e.ipHash || '')}</code></td><td class="muted">${esc(JSON.stringify(e.detail))}</td></tr>`).join('');
      $('#admStatus').textContent = `store: ${s.store} · bus: ${s.bus} · updated ${new Date().toLocaleTimeString()}`;
    } catch (e) { if (e.message === 'Wrong token') { sessionStorage.removeItem('qchat-admin'); location.reload(); } else $('#admStatus').textContent = e.message; }
  }
  async function start() {
    try { await api('/admin/api/summary'); } catch (e) { $('#admErr').textContent = e.message; return; }
    sessionStorage.setItem('qchat-admin', token);
    $('#admLogin').classList.add('hidden'); $('#admBody').classList.remove('hidden');
    refresh(); setInterval(refresh, 10000);
  }
  $('#admLogin').onsubmit = (e) => { e.preventDefault(); token = $('#admToken').value.trim(); start(); };
  $('#admSev').onchange = refresh; $('#admUser').oninput = () => { clearTimeout(window.__t); window.__t = setTimeout(refresh, 400); };
  document.addEventListener('click', async (e) => { const b = e.target.closest('[data-unban]'); if (b) { await api('/admin/api/unban', { method: 'POST', body: JSON.stringify({ ip: b.dataset.unban }) }); refresh(); } });
  $('#admBanForm').onsubmit = async (e) => { e.preventDefault(); const ip = $('#admBanIp').value.trim(); if (!ip) return; await api('/admin/api/ban', { method: 'POST', body: JSON.stringify({ ip, seconds: 3600 }) }); $('#admBanIp').value = ''; refresh(); };
  if (token) start();
})();
