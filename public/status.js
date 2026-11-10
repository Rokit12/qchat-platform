// Public service status page (no internals are exposed by /api/status).
(() => {
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const OV = { operational: ['All systems operational', 'up'], degraded: ['Some services are degraded', 'partial'], major_outage: ['Major outage — we are working on it', 'down'] };
  const ST = { up: ['Operational', 'up'], down: ['Outage', 'down'], unknown: ['Checking…', 'unknown'] };
  async function load() {
    try {
      const s = await (await fetch('/api/status', { cache: 'no-store' })).json();
      const o = OV[s.overall] || OV.operational;
      const el = document.getElementById('overall'); el.className = 'status-strip st-' + o[1]; el.innerHTML = `<b>● ${o[0]}</b><span class="muted small">checked ${new Date(s.checkedAt).toLocaleTimeString()}</span>`;
      document.getElementById('services').innerHTML = s.services.map((x) => `<div class="svc"><div class="svc-head"><span class="pill p-${(ST[x.state] || ST.unknown)[1]}">${(ST[x.state] || ST.unknown)[0]}</span><b>${esc(x.name)}</b><span class="grow"></span><span class="muted small">${x.uptime30d != null ? x.uptime30d + '% uptime (30 days)' : ''}</span></div><div class="ubars wide">${x.bars30d.map((b) => `<i class="b-${b}"></i>`).join('')}</div></div>`).join('');
      document.getElementById('incidents').innerHTML = s.incidents.length ? s.incidents.map((i) => `<div class="small">${esc(i.service)} — ${new Date(i.started).toLocaleString()} ${i.ended ? '· resolved after ' + Math.max(1, Math.round((i.ended - i.started) / 60000)) + ' min' : '· <b class="error">ongoing</b>'}</div>`).join('') : 'No incidents in the last 30 days 🎉';
    } catch { document.getElementById('overall').innerHTML = '<b>● Status unavailable — the QChat server may be unreachable</b>'; document.getElementById('overall').className = 'status-strip st-down'; }
  }
  load(); setInterval(load, 60000);
})();
