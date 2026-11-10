// QChat admin dashboard (bundled to public/admin.js). Talks only to /admin/api/* with an HttpOnly
// session cookie + CSRF header. All server data is escaped before it touches the DOM.
import qrcode from 'qrcode-generator';

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmtN = (n) => (n == null ? '—' : Number(n).toLocaleString());
const fmtDate = (t) => (t ? new Date(t).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }) : '—');
function ago(t) { if (!t) return 'never'; const s = (Date.now() - t) / 1000; if (s < 60) return 'just now'; if (s < 3600) return Math.floor(s / 60) + ' min ago'; if (s < 86400) return Math.floor(s / 3600) + ' h ago'; return Math.floor(s / 86400) + ' d ago'; }
let toastT; function toast(m) { const t = $('#toast'); t.textContent = m; t.classList.remove('hidden'); clearTimeout(toastT); toastT = setTimeout(() => t.classList.add('hidden'), 3500); }
let ME = null, view = 'overview', refreshT = null;

async function api(path, opts = {}) {
  const r = await fetch('/admin/api/' + path, { method: opts.method || 'GET', credentials: 'same-origin', headers: { 'x-qchat-admin': '1', 'content-type': 'application/json' }, body: opts.body ? JSON.stringify(opts.body) : undefined });
  const data = await r.json().catch(() => ({}));
  if (r.status === 401 && path !== 'login') { showLogin('Your session ended — please sign in again.'); throw new Error('signed out'); }
  if (!r.ok) throw new Error(data.error || 'HTTP ' + r.status);
  return data;
}
function openModal(html, mount) { $('#modalCard').innerHTML = html; $('#modal').classList.remove('hidden'); mount?.($('#modalCard')); }
function closeModal() { $('#modal').classList.add('hidden'); $('#modalCard').innerHTML = ''; }
$('#modal').addEventListener('mousedown', (e) => { if (e.target.id === 'modal') closeModal(); });
$('#modal').addEventListener('click', (e) => { if (e.target.closest('[data-close]')) closeModal(); });
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeModal(); });

// ---------- tiny SVG charts ----------
function barChart(values, labels, { color = 'var(--accent)', height = 140, unit = '' } = {}) {
  const max = Math.max(1, ...values), w = 100 / values.length;
  return `<svg class="chart" viewBox="0 0 100 ${height / 3}" preserveAspectRatio="none" role="img">${values.map((v, i) => { const h = (v / max) * (height / 3 - 2); return `<rect x="${i * w + w * 0.12}" y="${height / 3 - h}" width="${w * 0.76}" height="${Math.max(h, 0.3)}" fill="${color}" rx="0.4"><title>${esc(labels[i])}: ${fmtN(v)}${unit}</title></rect>`; }).join('')}</svg>
    <div class="chart-axis"><span>${esc(labels[0]?.slice(5))}</span><span>${esc(labels[labels.length - 1]?.slice(5))}</span></div>`;
}
function lineChart(values, labels, color = '#53bdeb') {
  const max = Math.max(1, ...values), H = 40, step = 100 / Math.max(values.length - 1, 1);
  const pts = values.map((v, i) => `${(i * step).toFixed(2)},${(H - (v / max) * (H - 3) - 1).toFixed(2)}`).join(' ');
  return `<svg class="chart" viewBox="0 0 100 ${H}" preserveAspectRatio="none"><polyline points="${pts}" fill="none" stroke="${color}" stroke-width="0.8" vector-effect="non-scaling-stroke"/>${values.map((v, i) => `<circle cx="${i * step}" cy="${H - (v / max) * (H - 3) - 1}" r="0.9" fill="${color}"><title>${esc(labels[i])}: ${fmtN(v)}</title></circle>`).join('')}</svg>
    <div class="chart-axis"><span>${esc(labels[0]?.slice(5))}</span><span>${esc(labels[labels.length - 1]?.slice(5))}</span></div>`;
}
const STATE = { up: ['Operational', 'up'], down: ['Down', 'down'], unknown: ['Checking…', 'unknown'], not_configured: ['Not configured', 'na'] };
const OVERALL = { operational: ['All systems operational', 'up'], degraded: ['Partial degradation', 'partial'], major_outage: ['Major outage', 'down'] };
const statusBars = (bars, cls = '') => `<div class="ubars ${cls}">${bars.map((b) => `<i class="b-${b}"></i>`).join('')}</div>`;

// ---------- views ----------
const views = {
  async overview(main) {
    const o = await api('overview');
    const t = o.totals, c = o.charts, today = o.days.length - 1;
    const sev = {}; for (const e of o.security7d) sev[e.severity] = (sev[e.severity] || 0) + e.n;
    const ov = OVERALL[o.status.overall];
    main.innerHTML = `
      <div class="adm-title"><h2>Overview</h2><span class="muted small">auto-refreshes every 30 s</span></div>
      <div class="status-strip st-${ov[1]}" data-goto="status"><b>● ${ov[0]}</b><span>${o.status.services.filter((s) => s.state !== 'not_configured').map((s) => `<span class="pill p-${STATE[s.state][1]}" title="${esc(s.name)}: ${STATE[s.state][0]}">${esc(s.name)}</span>`).join('')}</span></div>
      <div class="adm-cards">
        ${[['Registered users', t.users], ['Online now', t.onlineUsers], ['New (24 h)', t.new24h], ['Active today', c.dau[today]], ['Messages today', c.messages[today]], ['Linked devices', t.devices], ['PIN login adoption', t.pinAdoption + '%'], ['Suspended', t.suspended]].map(([k, v]) => `<div class="adm-card"><b>${typeof v === 'number' ? fmtN(v) : esc(v)}</b><span>${k}</span></div>`).join('')}
      </div>
      <div class="adm-grid">
        <div class="adm-panel"><h3>New users · 30 days</h3>${barChart(c.newUsers, o.days)}</div>
        <div class="adm-panel"><h3>Daily active users · 30 days</h3>${lineChart(c.dau, o.days)}</div>
        <div class="adm-panel"><h3>Encrypted messages per day</h3>${barChart(c.messages, o.days, { color: '#8e7dbe' })}<p class="muted small">Counts only — message content is end-to-end encrypted and never visible to the server.</p></div>
        <div class="adm-panel"><h3>Logins per day</h3>${barChart(c.logins, o.days, { color: '#e9c46a' })}</div>
        <div class="adm-panel"><h3>Traffic relayed (MB/day)</h3>${barChart(c.mb, o.days, { color: '#3a86ff', unit: ' MB' })}</div>
        <div class="adm-panel"><h3>Devices by platform</h3><table>${Object.entries(o.platforms).sort((a, b) => Object.values(b[1]).reduce((x, y) => x + y, 0) - Object.values(a[1]).reduce((x, y) => x + y, 0)).map(([os, brs]) => `<tr><td>${esc(os)}</td><td class="muted">${Object.entries(brs).map(([b, n]) => `${esc(b)} ${n}`).join(' · ')}</td><td class="num">${Object.values(brs).reduce((a, b) => a + b, 0)}</td></tr>`).join('') || '<tr><td class="muted">No devices yet</td></tr>'}</table></div>
        <div class="adm-panel"><h3>Most active senders · 30 days</h3><table>${o.topSenders.map((s) => `<tr data-user="${esc(s.username)}" class="click"><td>@${esc(s.username)}</td><td class="num">${fmtN(s.n)}</td></tr>`).join('') || '<tr><td class="muted">No messages yet</td></tr>'}</table></div>
        <div class="adm-panel"><h3>Security · 7 days</h3><div class="sev-row">${['critical', 'high', 'medium', 'low', 'info'].map((s) => `<span class="sevbox sev-${s}"><b>${sev[s] || 0}</b>${s}</span>`).join('')}</div>
          <table>${o.security7d.sort((a, b) => b.n - a.n).slice(0, 8).map((e) => `<tr class="sev-${e.severity}"><td>${esc(EV[e.type] || e.type)}</td><td class="num">${e.n}</td></tr>`).join('')}</table></div>
      </div>`;
  },

  async users(main, st = { q: '', status: '', sort: 'created', page: 0 }) {
    const qs = new URLSearchParams({ q: st.q, status: st.status, sort: st.sort, page: st.page });
    const d = await api('users?' + qs);
    const pages = Math.max(1, Math.ceil(d.total / d.pageSize));
    main.innerHTML = `
      <div class="adm-title"><h2>Users <span class="muted">(${fmtN(d.total)})</span></h2></div>
      <form class="row adm-filters" id="uf"><input id="uq" placeholder="Search username or display name" value="${esc(st.q)}"/>
        <select id="us"><option value="">All</option><option value="active" ${st.status === 'active' ? 'selected' : ''}>Active</option><option value="suspended" ${st.status === 'suspended' ? 'selected' : ''}>Suspended</option></select>
        <select id="uo"><option value="created">Newest</option><option value="created_asc" ${st.sort === 'created_asc' ? 'selected' : ''}>Oldest</option><option value="seen" ${st.sort === 'seen' ? 'selected' : ''}>Recently seen</option><option value="name" ${st.sort === 'name' ? 'selected' : ''}>Username A–Z</option></select>
        <button class="btn primary">Search</button></form>
      <div class="adm-panel"><table class="adm-users"><tr><th>User</th><th>Joined</th><th>Last seen</th><th>Devices</th><th>PIN</th><th>Reports</th><th>Status</th></tr>
        ${d.users.map((u) => `<tr class="click" data-user="${esc(u.username)}"><td><span class="dot ${u.online ? 'on' : ''}"></span><b>@${esc(u.username)}</b><small class="muted block">${esc(u.displayName)}</small></td>
          <td>${fmtDate(u.createdAt)}</td><td>${u.online ? '<span class="tag on">online</span>' : esc(ago(u.lastSeen))}</td><td class="num">${u.devices}</td><td>${u.pin ? '✅' : '—'}</td>
          <td class="num">${u.reports ? `<span class="tag warn">${u.reports}</span>` : '0'}</td><td>${u.suspendedUntil ? '<span class="tag bad">suspended</span>' : '<span class="tag ok">active</span>'}</td></tr>`).join('') || '<tr><td colspan="7" class="muted">No users match.</td></tr>'}
      </table>
      <div class="row pager"><button class="btn" id="pp" ${st.page <= 0 ? 'disabled' : ''}>← Prev</button><span class="muted">Page ${st.page + 1} of ${pages}</span><button class="btn" id="pn" ${st.page + 1 >= pages ? 'disabled' : ''}>Next →</button></div></div>`;
    $('#uf').onsubmit = (e) => { e.preventDefault(); views.users(main, { q: $('#uq').value.trim(), status: $('#us').value, sort: $('#uo').value, page: 0 }); };
    $('#pp').onclick = () => views.users(main, { ...st, page: st.page - 1 });
    $('#pn').onclick = () => views.users(main, { ...st, page: st.page + 1 });
    views.users.state = st;
  },

  async activity(main) {
    const a = await api('activity?limit=300');
    main.innerHTML = `<div class="adm-title"><h2>Recent activity</h2><span class="muted small">Account metadata only — never message content</span></div>
      <div class="adm-panel"><table>${a.map((x) => `<tr><td class="nowrap">${fmtDate(x.ts)}</td><td><a href="#" data-user="${esc(x.username)}">@${esc(x.username)}</a></td><td>${esc(ACT[x.type] || x.type)}</td><td class="muted">${esc(detailText(x.detail))}</td></tr>`).join('') || '<tr><td class="muted">No activity yet</td></tr>'}</table></div>`;
  },

  async security(main, sev = 'medium') {
    const [ev, bans] = await Promise.all([api('events?limit=300&minSeverity=' + sev), api('bans')]);
    main.innerHTML = `<div class="adm-title"><h2>Security</h2></div>
      <div class="adm-grid"><div class="adm-panel"><h3>Active IP bans</h3><table>${bans.map((b) => `<tr><td><code>${esc(b.ip)}</code></td><td class="muted">${esc(b.reason || '')}</td><td>${Math.ceil((b.ttl || 0) / 60)} min</td><td>${ME.role !== 'viewer' ? `<button class="btn" data-unban="${esc(b.ip)}">Unban</button>` : ''}</td></tr>`).join('') || '<tr><td class="muted">No active bans</td></tr>'}</table>
        ${ME.role !== 'viewer' ? '<form class="row" id="banF"><input id="banIp" placeholder="IP address"/><button class="btn danger">Ban for 1 hour</button></form>' : ''}</div>
      <div class="adm-panel"><h3>How detection works</h3><p class="muted small">Suspicious actions add strike points to an IP; enough points within 10 minutes trigger an automatic, escalating ban. Account-takeover attempts, wrong PINs and new devices also alert the account owner's devices instantly.</p></div></div>
      <div class="adm-panel"><div class="row"><h3 class="grow">Security events</h3><select id="sevSel">${['info', 'low', 'medium', 'high', 'critical'].map((s) => `<option value="${s}" ${s === sev ? 'selected' : ''}>${s}+</option>`).join('')}</select></div>
      <table class="adm-events"><tr><th>Time</th><th>Severity</th><th>Event</th><th>User</th><th>IP (hashed)</th><th>Details</th></tr>${ev.map((e) => `<tr class="sev-${e.severity}"><td class="nowrap">${fmtDate(e.ts)}</td><td><span class="sev">${e.severity}</span></td><td>${esc(EV[e.type] || e.type)}</td><td>${e.username ? `<a href="#" data-user="${esc(e.username)}">@${esc(e.username)}</a>` : ''}</td><td><code>${esc(e.ipHash || '')}</code></td><td class="muted">${esc(detailText(e.detail))}</td></tr>`).join('')}</table></div>`;
    $('#sevSel').onchange = (e) => views.security(main, e.target.value);
    $('#banF') && ($('#banF').onsubmit = async (e) => { e.preventDefault(); await api('ban', { method: 'POST', body: { ip: $('#banIp').value.trim(), seconds: 3600 } }); toast('IP banned'); views.security(main, sev); });
  },

  async status(main) {
    const s = await api('status');
    const ov = OVERALL[s.overall];
    main.innerHTML = `<div class="adm-title"><h2>Service status</h2><span class="muted small">checked every ${Math.round(s.intervalMs / 1000)} s · <a href="/status" target="_blank" rel="noopener">public status page ↗</a></span></div>
      <div class="status-strip st-${ov[1]}"><b>● ${ov[0]}</b><span class="muted small">last check ${esc(ago(s.checkedAt))}</span></div>
      <div class="adm-panel">${s.services.map((x) => `
        <div class="svc"><div class="svc-head"><span class="pill p-${STATE[x.state][1]}">${STATE[x.state][0]}</span><b>${esc(x.name)}</b><span class="grow"></span>
          ${x.state === 'not_configured' ? '' : `<span class="muted small">${x.latency != null ? x.latency + ' ms · ' : ''}${x.uptime24h != null ? x.uptime24h + '% (24 h)' : ''} · ${x.uptime30d != null ? x.uptime30d + '% (30 d)' : ''}</span>`}</div>
          ${x.state === 'not_configured' ? '<p class="muted small">Not configured on this deployment.</p>' : `<div class="muted small">Last 24 hours (30-min blocks)</div>${statusBars(x.bars24h)}<div class="muted small">Last 30 days</div>${statusBars(x.bars30d, 'wide')}${x.state === 'down' && x.detail ? `<p class="error small">${esc(x.detail)}</p>` : x.detail ? `<p class="muted small">${esc(x.detail)}</p>` : ''}`}</div>`).join('')}</div>
      <div class="adm-grid"><div class="adm-panel"><h3>App server instances</h3><table><tr><th>Instance</th><th>Host</th><th>Up since</th><th>Connections</th><th>Users</th></tr>${s.instances.map((i) => `<tr><td><code>${esc(i.id)}</code></td><td>${esc(i.host)}</td><td>${fmtDate(i.started)}</td><td class="num">${i.connections}</td><td class="num">${i.users}</td></tr>`).join('')}</table></div>
      <div class="adm-panel"><h3>Incidents · 30 days</h3><table>${s.incidents.map((i) => `<tr><td>${esc(s.services.find((x) => x.id === i.service)?.name || i.service)}</td><td>${fmtDate(i.started)}</td><td>${i.ended ? 'resolved after ' + Math.max(1, Math.round((i.ended - i.started) / 60000)) + ' min' : '<span class="tag bad">ongoing</span>'}</td><td class="muted">${esc(i.detail || '')}</td></tr>`).join('') || '<tr><td class="muted">No incidents 🎉</td></tr>'}</table></div></div>`;
  },

  async audit(main) {
    const a = await api('audit');
    main.innerHTML = `<div class="adm-title"><h2>Audit log</h2><span class="muted small">Every admin action is recorded here</span></div>
      <div class="adm-panel"><table><tr><th>Time</th><th>Admin</th><th>Action</th><th>Target</th><th>Details</th></tr>${a.map((x) => `<tr><td class="nowrap">${fmtDate(x.ts)}</td><td>${esc(x.admin)}</td><td>${esc(x.action)}</td><td>${esc(x.target || '')}</td><td class="muted">${esc(detailText(x.detail))}</td></tr>`).join('')}</table></div>`;
  },

  async admins(main) {
    const list = await api('admins');
    main.innerHTML = `<div class="adm-title"><h2>Admin accounts</h2></div>
      <div class="adm-grid"><div class="adm-panel"><table><tr><th>Admin</th><th>Role</th><th>Last sign-in</th><th></th></tr>${list.map((a) => `<tr><td>${esc(a.username)}</td><td>${esc(a.role)}</td><td>${esc(ago(a.last_login))}</td><td>${a.username === ME.username ? '<span class="muted">you</span>' : `<button class="btn ${Number(a.disabled) ? '' : 'danger'}" data-admin="${a.id}" data-act="${Number(a.disabled) ? 'enable' : 'disable'}">${Number(a.disabled) ? 'Enable' : 'Disable'}</button>`}</td></tr>`).join('')}</table></div>
      <form class="adm-panel" id="newAdmin"><h3>Add an admin</h3>
        <label class="field"><span>Username</span><input id="naU" required/></label><label class="field"><span>Temporary password (12+ chars)</span><input id="naP" type="password" autocomplete="new-password" required/></label>
        <label class="field"><span>Role</span><select id="naR"><option value="viewer">Viewer — read-only</option><option value="admin" selected>Admin — manage users</option><option value="owner">Owner — everything</option></select></label>
        <button class="btn primary">Create admin</button></form></div>`;
    $('#newAdmin').onsubmit = async (e) => {
      e.preventDefault();
      try {
        const r = await api('admins', { method: 'POST', body: { username: $('#naU').value.trim(), password: $('#naP').value, role: $('#naR').value } });
        const q = qrcode(0, 'M'); q.addData(r.otpauth); q.make();
        openModal(`<h3>Admin "${esc(r.username)}" created</h3><p class="muted small">Have them scan this in an authenticator app now. It will not be shown again.</p><div class="qr">${q.createSvgTag({ cellSize: 5, margin: 2, scalable: true })}</div><p class="small">Secret: <code>${esc(r.totpSecret.match(/.{1,4}/g).join(' '))}</code></p><div class="modal-actions"><button class="btn primary" data-close>Done</button></div>`);
        views.admins(main);
      } catch (err) { toast(err.message); }
    };
  },
};
const EV = {
  account_takeover_attempt: 'Wrong recovery key for an account', account_locked: 'Account locked (takeover attempts)', device_linked: 'Device linked', bad_device_signature: 'Forged device signature',
  auth_failed: 'Failed login', ip_banned: 'IP auto-banned', scanner_probe: 'Vulnerability-scanner probe', ws_bad_origin: 'Cross-site WebSocket hijacking attempt', mass_registration: 'Mass account creation',
  reserved_username_attempt: 'Reserved-name sign-up attempt', impersonation_attempt: 'Impersonating display name', enumeration_suspected: 'Username enumeration', spam_suspected: 'Spam (too many new chats)',
  user_reported: 'User reported', account_restricted: 'Account restricted (5+ reports)', rate_limited: 'Rate limited', send_flood: 'Message flood', admin_auth_failed: 'Failed admin sign-in',
  admin_login_locked: 'Admin sign-in while locked', admin_csrf_blocked: 'Blocked cross-site admin request', queue_full: 'Offline queue full', account_created: 'Account created', account_deleted: 'Account deleted',
  pin_failed: 'Wrong login PIN', pin_wiped: 'PIN login wiped (too many wrong PINs)', pin_changed: 'Login PIN changed', pin_removed: 'Login PIN removed', pin_set: 'Login PIN set', pin_unlock: 'Logged in with PIN',
  pin_bruteforce: 'PIN brute force from one network', admin_2fa_setup_started: 'Admin started 2FA setup', pin_while_locked: 'PIN attempt during lockout', enroll_while_locked: 'Login attempt on locked account', service_down: 'Service down', service_recovered: 'Service recovered',
};
const ACT = {
  account_created: 'Created account', login: 'Logged in', device_linked: 'Linked a new device', device_removed: 'Removed a device', profile_updated: 'Updated profile', pin_set: 'Set login PIN', pin_changed: 'Changed login PIN',
  reported_user: 'Reported a user', push_enabled: 'Turned on push notifications', push_disabled: 'Turned off push notifications', suspended_by_admin: 'Suspended by an admin', unsuspended_by_admin: 'Unsuspended by an admin',
  signed_out_by_admin: 'Signed out by an admin', device_removed_by_admin: 'Device removed by an admin', pin_reset_by_admin: 'PIN login reset by an admin',
};
const detailText = (d) => Object.entries(d || {}).filter(([, v]) => v !== '' && v != null && !(Array.isArray(v) && !v.length)).map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(', ') : typeof v === 'number' && v > 1e12 ? new Date(v).toLocaleString() : v}`).join(' · ');

// ---------- user detail & management ----------
async function userDetail(u) {
  const d = await api('users/' + encodeURIComponent(u));
  const canManage = ME.role !== 'viewer', isOwner = ME.role === 'owner';
  const days = Array.from({ length: 30 }, (_, i) => new Date(Date.now() - (29 - i) * 864e5).toISOString().slice(0, 10));
  const sent = days.map((x) => d.messagesPerDay.find((m) => m.day === x)?.sent || 0);
  openModal(`
    <div class="row"><h3 class="grow">@${esc(d.username)} <span class="muted">${esc(d.profile.displayName || '')}</span></h3><button class="icon-btn" data-close>✕</button></div>
    <p class="muted small">${esc(d.profile.about || '')}</p>
    <div class="adm-cards mini">${[['Joined', fmtDate(d.createdAt)], ['Last seen', d.hideLastSeen ? 'hidden by user' : ago(d.lastSeen)], ['Days active', d.activeDays], ['Devices', d.devices.length], ['Reports', d.reports.length], ['Status', d.suspendedUntil ? 'Suspended until ' + fmtDate(d.suspendedUntil) : 'Active']].map(([k, v]) => `<div class="adm-card"><b>${esc(v)}</b><span>${k}</span></div>`).join('')}</div>
    ${d.suspendedUntil && d.suspendReason ? `<p class="error small">Suspension reason: ${esc(d.suspendReason)}</p>` : ''}
    ${canManage ? `<div class="row adm-actions">${d.suspendedUntil ? '<button class="btn" data-a="unsuspend">Unsuspend</button>' : '<button class="btn danger" data-a="suspend">Suspend…</button>'}
      <button class="btn" data-a="logout">Force sign-out</button>${d.pin.enabled ? '<button class="btn" data-a="reset_pin">Reset PIN login</button>' : ''}${d.reports.length ? '<button class="btn" data-a="clear_reports">Clear reports</button>' : ''}${isOwner ? '<button class="btn danger" data-a="delete">Delete account…</button>' : ''}</div>` : ''}
    <div class="section-title">Messages sent · 30 days (counts only)</div>${barChart(sent, days, { color: '#8e7dbe' })}
    <div class="section-title">Devices</div><table>${d.devices.map((v) => `<tr><td><span class="dot ${v.online ? 'on' : ''}"></span>${esc(v.name || 'Device')}</td><td class="muted">added ${fmtDate(v.created)}</td><td>${v.push ? '🔔' : ''}</td><td>${canManage ? `<button class="btn danger" data-a="remove_device" data-dev="${esc(v.device)}">Remove</button>` : ''}</td></tr>`).join('') || '<tr><td class="muted">No devices</td></tr>'}</table>
    <div class="section-title">Login PIN</div><p class="small">${d.pin.enabled ? `Enabled · ${d.pin.failedAttempts} recent wrong attempt(s)${d.pin.lockedUntil > Date.now() ? ' · locked until ' + fmtDate(d.pin.lockedUntil) : ''}` : 'Not set'}</p>
    ${d.reports.length ? `<div class="section-title">Reports</div><table>${d.reports.map((r) => `<tr><td>@${esc(r.reporter)}</td><td>${esc(r.reason || '')}</td><td class="muted">${fmtDate(r.ts)}</td></tr>`).join('')}</table>` : ''}
    <div class="section-title">Activity & security timeline</div>
    <table class="timeline">${d.timeline.map((x) => `<tr class="${x.kind === 'security' ? 'sev-' + x.severity : ''}"><td class="nowrap">${fmtDate(x.ts)}</td><td>${x.kind === 'security' ? `<span class="sev">${x.severity}</span> ` : ''}${esc((x.kind === 'security' ? EV : ACT)[x.type] || x.type)}</td><td class="muted">${esc(detailText(x.detail))}</td></tr>`).join('') || '<tr><td class="muted">No activity recorded</td></tr>'}</table>
    <p class="muted small">Message content, contacts and group membership are end-to-end encrypted and never stored on the server, so they can't appear here.</p>`, (card) => {
    card.onclick = async (e) => {
      const b = e.target.closest('[data-a]'); if (!b) return;
      const a = b.dataset.a; let body = {};
      if (a === 'suspend') {
        const hours = prompt2('Suspend for how many hours? (0 = indefinitely)', '24'); if (hours === null) return;
        const reason = prompt2('Reason (shown in the audit log)', 'Spam / phishing'); if (reason === null) return; body = { hours: Number(hours), reason };
      } else if (a === 'delete') {
        const c = prompt2(`Type ${d.username} to permanently delete this account`, ''); if (c !== d.username) return toast('Not deleted'); body = { confirm: c };
      } else if (!confirm2(`Confirm: ${b.textContent.trim()} for @${d.username}?`)) return;
      try { await api(`users/${encodeURIComponent(d.username)}/${a}${b.dataset.dev ? '/' + b.dataset.dev : ''}`, { method: 'POST', body }); toast('Done'); if (a === 'delete') { closeModal(); render(); } else userDetail(d.username); }
      catch (err) { toast(err.message); }
    };
  });
}
// inline prompt/confirm (window.prompt/confirm are blocked in some embeds)
function prompt2(q, def) { return window.prompt ? window.prompt(q, def) : def; }
function confirm2(q) { return window.confirm ? window.confirm(q) : true; }

// ---------- shell ----------
async function render() {
  clearTimeout(refreshT);
  $$('.adm-nav [data-view]').forEach((b) => b.classList.toggle('active', b.dataset.view === view));
  const main = $('#main');
  try { if (view === 'users') await views.users(main, views.users.state); else await views[view](main); }
  catch (e) { if (e.message !== 'signed out') main.innerHTML = `<p class="error">${esc(e.message)}</p>`; }
  if (view === 'overview' || view === 'status') refreshT = setTimeout(render, 30000);
}
document.addEventListener('click', async (e) => {
  const nav = e.target.closest('.adm-nav [data-view]'); if (nav) { view = nav.dataset.view; location.hash = view; return render(); }
  const go = e.target.closest('[data-goto]'); if (go) { view = go.dataset.goto; location.hash = view; return render(); }
  const u = e.target.closest('[data-user]'); if (u && !e.target.closest('#modalCard')) { e.preventDefault(); return userDetail(u.dataset.user); }
  const ub = e.target.closest('[data-unban]'); if (ub) { await api('unban', { method: 'POST', body: { ip: ub.dataset.unban } }); toast('Unbanned'); return render(); }
  const ad = e.target.closest('[data-admin]'); if (ad) { await api(`admins/${ad.dataset.admin}/${ad.dataset.act}`, { method: 'POST' }).catch((err) => toast(err.message)); return render(); }
});
function showLogin(msg) { $('#appView').classList.add('hidden'); $('#loginView').classList.remove('hidden'); $('#lgErr').textContent = msg || ''; }
function showApp() {
  $('#loginView').classList.add('hidden'); $('#appView').classList.remove('hidden');
  $('#meName').textContent = ME.username; $('#meRole').textContent = ME.role;
  $$('.owner-only').forEach((b) => b.classList.toggle('hidden', ME.role !== 'owner'));
  view = (location.hash.slice(1) in views && (ME.role === 'owner' || !['audit', 'admins'].includes(location.hash.slice(1)))) ? location.hash.slice(1) : 'overview';
  render();
}
$('#loginForm').onsubmit = async (e) => {
  e.preventDefault(); $('#lgErr').textContent = 'Signing in…';
  try {
    const r = await api('login', { method: 'POST', body: { username: $('#lgUser').value.trim(), password: $('#lgPass').value, code: $('#lgCode').value.trim() } });
    if (r.setup2fa) { // first sign-in: enrol an authenticator app
      const q = qrcode(0, 'M'); q.addData(r.otpauth); q.make();
      $('#lgSetup').innerHTML = `<div class="section-title">Set up two-factor authentication</div><p class="small">Scan this QR code with Google Authenticator, Microsoft Authenticator, Authy or 1Password, then enter the 6-digit code it shows and press <b>Sign in</b>.</p><div class="qr">${q.createSvgTag({ cellSize: 5, margin: 2, scalable: true })}</div><p class="small muted">Can't scan? Enter this key: <code>${esc(r.secret.match(/.{1,4}/g).join(' '))}</code></p>`;
      $('#lgSetup').classList.remove('hidden'); $('#lgCodeField').classList.remove('hidden'); $('#lgErr').textContent = ''; $('#lgCode').focus(); return;
    }
    ME = { username: r.username, role: r.role }; $('#lgPass').value = ''; $('#lgCode').value = ''; $('#lgSetup').classList.add('hidden'); showApp();
  } catch (err) { $('#lgErr').textContent = err.message; $('#lgCode').value = ''; }
};
$('#pwBtn').onclick = () => openModal(`<h3>Change password</h3>
  <p class="muted small">You'll be signed out everywhere afterwards. Use 12+ characters mixing letters with numbers or symbols.</p>
  <label class="field"><span>Current password</span><input id="cpCur" type="password" autocomplete="current-password"/></label>
  <label class="field"><span>New password</span><input id="cpNew" type="password" autocomplete="new-password"/></label>
  <label class="field"><span>Repeat new password</span><input id="cpNew2" type="password" autocomplete="new-password"/></label>
  <label class="field"><span>Authenticator code</span><input id="cpCode" class="pin-input" inputmode="numeric" maxlength="6" autocomplete="one-time-code"/></label>
  <p class="error" id="cpErr"></p>
  <div class="modal-actions"><button class="btn" data-close>Cancel</button><button class="btn primary" id="cpGo">Change password</button></div>`, (card) => {
  $('#cpGo', card).onclick = async () => {
    if ($('#cpNew', card).value !== $('#cpNew2', card).value) return ($('#cpErr', card).textContent = "New passwords don't match");
    try { await api('password', { method: 'POST', body: { current: $('#cpCur', card).value, password: $('#cpNew', card).value, code: $('#cpCode', card).value.trim() } }); closeModal(); ME = null; showLogin('Password changed — please sign in with your new password.'); }
    catch (e) { $('#cpErr', card).textContent = e.message; }
  };
});
$('#logoutBtn').onclick = async () => { await api('logout', { method: 'POST' }).catch(() => {}); ME = null; showLogin('Signed out.'); };
(async () => { try { ME = await api('me'); showApp(); } catch { showLogin(); } })();
