/* Marsad SPA controller — login, routing, and the four views. Vanilla JS. */
(function () {
  const $ = s => document.querySelector(s);
  const $$ = s => document.querySelectorAll(s);
  const el = (t, c, h) => { const e = document.createElement(t); if (c) e.className = c; if (h != null) e.innerHTML = h; return e; };
  const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const fmtDate = s => s ? new Date(s).toISOString().slice(0, 10) : '—';
  const riskColor = r => r >= 80 ? 'var(--crit)' : r >= 55 ? 'var(--high)' : r >= 30 ? 'var(--med)' : 'var(--low)';
  const STATUSES = ['open', 'triaged', 'in_progress', 'remediated', 'accepted', 'false_positive'];
  function toast(m) { const t = $('#toast'); t.textContent = m; t.classList.add('show'); setTimeout(() => t.classList.remove('show'), 1600); }

  /* ── login ── */
  $('#loginForm').addEventListener('submit', async e => {
    e.preventDefault();
    $('#loginErr').textContent = '';
    try {
      const { demo } = await API.login($('#email').value.trim(), $('#password').value);
      $('#login').style.display = 'none';
      $('#app').classList.add('on');
      $('#whoName').textContent = API.name;
      $('#whoRole').textContent = API.role;
      $('#demoBanner').style.display = demo ? 'block' : 'none';
      go('dashboard');
    } catch (err) {
      $('#loginErr').textContent = err.status === 401 ? 'Incorrect email or password.' : 'Could not sign in. ' + err.message;
    }
  });
  $('#logout').addEventListener('click', () => location.reload());

  /* ── router ── */
  const views = { dashboard: renderDashboard, findings: renderFindings, assets: renderAssets, import: renderImport };
  function go(v) {
    $$('.nav-btn').forEach(b => b.classList.toggle('on', b.dataset.view === v));
    $$('.view').forEach(x => x.classList.toggle('on', x.id === 'v-' + v));
    views[v]();
  }
  $$('.nav-btn').forEach(b => b.addEventListener('click', () => go(b.dataset.view)));

  /* ── dashboard ── */
  async function renderDashboard() {
    const d = await API.dashboard();
    const t = d.totals;
    $('#kpis').innerHTML = `
      <div class="kpi"><h4>Open findings</h4><div class="n amber">${t.open_findings}</div><div class="d">across ${t.assets} assets</div></div>
      <div class="kpi"><h4>Overdue (SLA breached)</h4><div class="n crit">${t.overdue}</div><div class="d">need immediate action</div></div>
      <div class="kpi"><h4>Mean time to remediate</h4><div class="n cyan">${t.mttr_days ?? '—'}${t.mttr_days != null ? '<span style="font-size:15px"> d</span>' : ''}</div><div class="d">rolling average</div></div>
      <div class="kpi"><h4>Vulnerabilities tracked</h4><div class="n">${t.vulnerabilities}</div><div class="d">in catalog</div></div>`;

    const sev = d.by_severity; const max = Math.max(1, ...Object.values(sev));
    $('#sevBars').innerHTML = ['Critical', 'High', 'Medium', 'Low', 'Info'].map(s => `
      <div class="sevbar"><span class="lbl">${s}</span>
        <span class="track"><i class="c-${s.toLowerCase()}" style="width:${sev[s] / max * 100}%"></i></span>
        <span class="val">${sev[s] || 0}</span></div>`).join('');

    $('#topRisks').innerHTML = d.top_risks.length ? `<table><thead><tr>
        <th>Risk</th><th>Finding</th><th>Asset</th><th>Sev</th><th>Status</th></tr></thead><tbody>${
      d.top_risks.map(r => `<tr>
        <td><span class="riskpip" style="background:${riskColor(r.risk_score)}">${r.risk_score}</span></td>
        <td>${esc(r.title)}${r.cve ? `<span class="t2">${esc(r.cve)}</span>` : ''}</td>
        <td>${esc(r.asset)}${r.overdue ? ' <span class="overdue">⚠ overdue</span>' : ''}</td>
        <td><span class="sev ${r.severity}">${r.severity}</span></td>
        <td><span class="status ${r.status}">${r.status.replace('_', ' ')}</span></td></tr>`).join('')
      }</tbody></table>` : '<div class="empty"><b>No open findings</b>Import a scan to populate the board.</div>';
  }

  /* ── findings ── */
  let findingCache = [];
  async function renderFindings() {
    findingCache = await API.findings();
    drawFindings();
  }
  function drawFindings() {
    const q = $('#fQ').value.toLowerCase();
    const sev = $('#fSev').value, st = $('#fStatus').value, od = $('#fOverdue').checked;
    let list = findingCache.filter(f => {
      if (sev && f._sev !== sev) return false;
      if (st && f.status !== st) return false;
      if (od && !f.overdue) return false;
      if (q && !((f._title || '') + (f._cve || '') + (f._asset || '')).toLowerCase().includes(q)) return false;
      return true;
    });
    $('#fCount').textContent = `${list.length} finding${list.length === 1 ? '' : 's'}`;
    const canWrite = API.canWrite();
    $('#findingsTable').innerHTML = list.length ? `<table><thead><tr>
        <th>Risk</th><th>Finding</th><th>Asset</th><th>Severity</th><th>Due</th><th>Owner</th><th>Status</th></tr></thead><tbody>${
      list.map(f => `<tr>
        <td><span class="riskpip" style="background:${riskColor(f.risk_score)}">${f.risk_score}</span></td>
        <td>${esc(f._title)}${f._cve ? `<span class="t2">${esc(f._cve)}</span>` : ''}</td>
        <td>${esc(f._asset)}</td>
        <td><span class="sev ${f._sev}">${f._sev}</span></td>
        <td>${f.overdue ? `<span class="overdue">${fmtDate(f.due_date)} ⚠</span>` : `<span class="due-ok">${fmtDate(f.due_date)}</span>`}</td>
        <td>${esc(f.assigned_to || '—')}</td>
        <td><select class="row-status" data-id="${f.id}" ${canWrite ? '' : 'disabled title="Read-only role"'}>${
          STATUSES.map(s => `<option value="${s}" ${f.status === s ? 'selected' : ''}>${s.replace('_', ' ')}</option>`).join('')
        }</select></td></tr>`).join('')
      }</tbody></table>` : '<div class="empty"><b>Nothing matches these filters</b>Try clearing them.</div>';

    $$('.row-status').forEach(sel => sel.addEventListener('change', async e => {
      const id = +e.target.dataset.id, status = e.target.value;
      try {
        await API.setStatus(id, status);
        const f = findingCache.find(x => x.id === id);
        if (f) { f.status = status; f.overdue = ['open', 'triaged', 'in_progress'].includes(status) && new Date(f.due_date) < new Date(); }
        toast(`Status set to ${status.replace('_', ' ')}`);
        drawFindings();
      } catch (err) { toast('Update failed: ' + err.message); }
    }));
  }
  ['fQ', 'fSev', 'fStatus'].forEach(id => $('#' + id).addEventListener('input', drawFindings));
  $('#fOverdue').addEventListener('change', drawFindings);

  /* ── assets ── */
  async function renderAssets() {
    const assets = await API.assets();
    const critLabel = { 4: 'Critical', 3: 'High', 2: 'Medium', 1: 'Low' };
    const critClass = { 4: 'Critical', 3: 'High', 2: 'Medium', 1: 'Low' };
    $('#assetsTable').innerHTML = `<table><thead><tr>
        <th>Asset</th><th>Type</th><th>Environment</th><th>Business unit</th><th>Exposure</th><th>Criticality</th></tr></thead><tbody>${
      assets.map(a => `<tr>
        <td>${esc(a.name)}<span class="t2">${esc(a.ip_address || '')}</span></td>
        <td>${esc(a.asset_type)}</td>
        <td>${esc(a.environment)}</td>
        <td>${esc(a.business_unit || '—')}</td>
        <td>${a.internet_facing ? '<span class="sev High">Internet-facing</span>' : '<span class="status">Internal</span>'}</td>
        <td><span class="sev ${critClass[a.criticality]}">${critLabel[a.criticality] || a.criticality}</span></td></tr>`).join('')
      }</tbody></table>`;
  }

  /* ── import ── */
  function renderImport() {
    $('#importResult').style.display = 'none';
    if (API.isDemo) $('#importNote').textContent = 'Demo mode: import is disabled. Run the backend to ingest real Nessus / CSV scans.';
  }
  const drop = $('#drop'), fileInput = $('#scanFile');
  drop.addEventListener('click', () => fileInput.click());
  drop.addEventListener('dragover', e => { e.preventDefault(); drop.classList.add('drag'); });
  drop.addEventListener('dragleave', () => drop.classList.remove('drag'));
  drop.addEventListener('drop', e => { e.preventDefault(); drop.classList.remove('drag'); if (e.dataTransfer.files[0]) doImport(e.dataTransfer.files[0]); });
  fileInput.addEventListener('change', e => { if (e.target.files[0]) doImport(e.target.files[0]); });
  async function doImport(file) {
    try {
      const r = await API.importScan(file);
      const box = $('#importResult');
      box.style.display = 'block';
      box.textContent = r._demo
        ? 'Demo mode — import is disabled here. With the backend running, this would parse the file and create findings.'
        : `Imported from ${r.source}: ${r.findings_created} new finding(s), ${r.findings_updated} updated.`;
      if (!r._demo) toast('Scan imported');
    } catch (err) { toast('Import failed: ' + err.message); }
  }
})();
