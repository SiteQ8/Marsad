/* API client. Talks to the FastAPI backend when reachable; otherwise (e.g. the
   GitHub Pages build) transparently serves the bundled demo dataset so the UI is
   fully explorable offline. Override the backend with ?api=https://host:port. */
window.API = (function () {
  const qs = new URLSearchParams(location.search);
  const BASE = qs.get('api') || window.MARSAD_API || (location.protocol === 'file:' ? null : location.origin);
  const state = { token: null, demo: false, role: 'viewer', name: '' };

  async function real(path, { method = 'GET', body, form, auth = true } = {}) {
    const headers = {};
    if (auth && state.token) headers['Authorization'] = `Bearer ${state.token}`;
    let payload;
    if (form) { payload = form; }
    else if (body) { headers['Content-Type'] = 'application/json'; payload = JSON.stringify(body); }
    const res = await fetch(BASE + path, { method, headers, body: payload });
    if (!res.ok) {
      let detail = res.statusText;
      try { detail = (await res.json()).detail || detail; } catch {}
      const err = new Error(detail); err.status = res.status; throw err;
    }
    return res.status === 204 ? null : res.json();
  }

  return {
    get isDemo() { return state.demo; },
    get role() { return state.role; },
    get name() { return state.name; },
    canWrite() { return !state.demo && (state.role === 'analyst' || state.role === 'admin'); },

    async login(email, password) {
      // Try the real backend first; fall back to demo if unreachable.
      if (BASE) {
        try {
          const form = new URLSearchParams({ username: email, password });
          const data = await real('/api/auth/login', { method: 'POST', form, auth: false });
          Object.assign(state, { token: data.access_token, role: data.role, name: data.full_name, demo: false });
          return { demo: false };
        } catch (e) {
          if (e.status === 401) throw e;           // real server, wrong creds
          /* network/CORS error → fall through to demo */
        }
      }
      const d = window.DEMO.login();
      Object.assign(state, { token: d.access_token, role: d.role, name: d.full_name, demo: true });
      return { demo: true };
    },

    async dashboard() { return state.demo ? window.DEMO.dashboard() : real('/api/dashboard'); },

    async findings(params = {}) {
      if (state.demo) return window.DEMO.listFindings(params);
      const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v)).toString();
      return real('/api/findings' + (q ? '?' + q : ''));
    },

    async setStatus(id, status) {
      if (state.demo) return window.DEMO.setStatus(id, status);
      return real(`/api/findings/${id}/status`, { method: 'PATCH', body: { status } });
    },

    async assets() { return state.demo ? window.DEMO.assets() : real('/api/assets'); },

    async importScan(file) {
      if (state.demo) return { source: 'demo', findings_created: 0, findings_updated: 0, _demo: true };
      const fd = new FormData(); fd.append('file', file);
      return real('/api/findings/import', { method: 'POST', form: fd });
    },
  };
})();
