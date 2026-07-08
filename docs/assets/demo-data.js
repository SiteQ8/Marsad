/* Demo mode: a self-contained dataset + an in-memory API that mirrors the real
   backend's responses, so the GitHub Pages build is fully explorable with no
   server. The live app uses the real FastAPI backend (see api.js). */
window.DEMO = (function () {
  const rnd = (seed => () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff)(7);
  const pick = a => a[Math.floor(rnd() * a.length)];
  const daysAgo = n => { const d = new Date(); d.setDate(d.getDate() - n); return d.toISOString(); };

  const assets = [
    ['web-prod-01','203.0.113.10','Server','production','Digital',4,true],
    ['web-prod-02','203.0.113.11','Server','production','Digital',4,true],
    ['api-gateway','203.0.113.20','Application','production','Platform',4,true],
    ['db-core-01','10.0.5.10','Database','production','Platform',4,false],
    ['erp-sap','10.0.5.30','Application','production','Finance',4,false],
    ['mail-relay','10.0.6.5','Server','production','IT',3,true],
    ['vpn-concentrator','203.0.113.40','Network device','production','IT',3,true],
    ['build-ci','10.0.9.12','Server','staging','Engineering',2,false],
    ['dev-sandbox','10.0.9.50','Server','dev','Engineering',1,false],
    ['fileshare-01','10.0.7.20','Server','production','Corporate',3,false],
    ['k8s-worker-03','10.0.8.33','Server','production','Platform',3,false],
    ['hr-portal','203.0.113.60','Application','production','HR',3,true],
  ].map((a, i) => ({ id: i+1, name:a[0], ip_address:a[1], asset_type:a[2], environment:a[3],
    business_unit:a[4], criticality:a[5], internet_facing:a[6], owner:'IT Ops' }));

  const vulns = [
    ['OpenSSL 3.0 X.509 buffer overflow','CVE-2022-3602',7.5,'High'],
    ['Apache Log4j2 RCE (Log4Shell)','CVE-2021-44228',10.0,'Critical'],
    ['PAN-OS GlobalProtect command injection','CVE-2024-3400',10.0,'Critical'],
    ['Exposed database with no authentication',null,9.8,'Critical'],
    ['TLS 1.0/1.1 enabled',null,3.7,'Low'],
    ['SMBv1 protocol enabled','CVE-2017-0144',8.1,'High'],
    ['Outdated jQuery with known XSS','CVE-2020-11022',6.1,'Medium'],
    ['SSH weak ciphers permitted',null,5.3,'Medium'],
    ['Missing OS security patches (multiple)',null,7.8,'High'],
    ['Default admin credentials on appliance',null,9.8,'Critical'],
    ['Publicly accessible .git directory',null,7.5,'High'],
    ['Verbose error messages leak stack traces',null,5.3,'Medium'],
  ].map((v, i) => ({ id:i+1, title:v[0], cve_id:v[1], cvss_score:v[2], severity:v[3],
    remediation:'Apply vendor patch / harden configuration per baseline.' }));

  const critW = {1:0.7,2:1.0,3:1.3,4:1.6};
  const sla = {Critical:7,High:30,Medium:90,Low:180,Info:365};
  const statuses = ['open','open','open','open','open','open','triaged','triaged','in_progress','in_progress','remediated','remediated','accepted'];

  let fid = 0; const findings = [];
  for (const asset of assets) {
    const n = 3 + Math.floor(rnd() * 5);
    const shuffled = vulns.slice().sort(() => rnd() - 0.5).slice(0, n);
    for (const v of shuffled) {
      const age = 1 + Math.floor(rnd() * 200);
      const status = pick(statuses);
      let risk = (v.cvss_score / 10) * 100 * (critW[asset.criticality] || 1);
      if (asset.internet_facing) risk *= 1.25;
      risk = Math.round(Math.min(risk, 100) * 10) / 10;
      const first = new Date(); first.setDate(first.getDate() - age);
      const due = new Date(first); due.setDate(due.getDate() + (sla[v.severity] || 90));
      const resolved = (status === 'remediated' || status === 'accepted');
      findings.push({ id:++fid, asset_id:asset.id, vulnerability_id:v.id, status,
        port:String(pick([22,80,443,445,3389,8080])), risk_score:risk,
        first_seen:first.toISOString(), due_date:due.toISOString(),
        resolved_at: resolved ? daysAgo(age-10) : null,
        assigned_to: pick(['','IT Ops','AppSec','Platform']),
        _sev:v.severity, _title:v.title, _cve:v.cve_id, _asset:asset.name });
    }
  }

  const OPEN = ['open','triaged','in_progress'];
  const isOverdue = f => OPEN.includes(f.status) && new Date(f.due_date) < new Date();

  function dashboard() {
    const open = findings.filter(f => OPEN.includes(f.status));
    const by = {Critical:0,High:0,Medium:0,Low:0,Info:0};
    open.forEach(f => by[f._sev]++);
    const resolved = findings.filter(f => f.resolved_at);
    const mttr = resolved.length
      ? Math.round(resolved.reduce((s,f)=>s+((new Date(f.resolved_at)-new Date(f.first_seen))/864e5),0)/resolved.length*10)/10
      : null;
    const byStatus = {};
    findings.forEach(f => byStatus[f.status]=(byStatus[f.status]||0)+1);
    const top = open.slice().sort((a,b)=>b.risk_score-a.risk_score).slice(0,10).map(f=>({
      id:f.id, risk_score:f.risk_score, title:f._title, cve:f._cve, severity:f._sev,
      asset:f._asset, status:f.status, overdue:isOverdue(f) }));
    return { totals:{ assets:assets.length, vulnerabilities:vulns.length,
      open_findings:open.length, overdue:open.filter(isOverdue).length, mttr_days:mttr },
      by_severity:by, by_status:byStatus, top_risks:top };
  }

  function listFindings(params={}) {
    let list = findings.slice();
    if (params.status) list = list.filter(f=>f.status===params.status);
    if (params.severity) list = list.filter(f=>f._sev===params.severity);
    if (params.overdue) list = list.filter(isOverdue);
    list.sort((a,b)=>b.risk_score-a.risk_score);
    return list.map(f=>({...f, overdue:isOverdue(f)}));
  }

  function setStatus(id, status) {
    const f = findings.find(x=>x.id===id);
    if (f){ f.status=status; f.resolved_at = ['remediated','accepted','false_positive'].includes(status)?new Date().toISOString():null; }
    return f;
  }

  return {
    login: () => ({ access_token:'demo', role:'analyst', full_name:'Ali AlEnezi (demo)' }),
    dashboard, listFindings, setStatus,
    assets: () => assets,
    findingsRaw: findings,
  };
})();
