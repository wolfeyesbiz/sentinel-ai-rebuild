import React, { useEffect, useState } from 'react';
import { Activity, Copy, Plus, RefreshCw, ScanLine, Trash2, X, Zap } from 'lucide-react';
import { apiFetch, apiUrl } from '../api';

type Site = {
  id: string; name: string; url: string; status: string; checked_at?: string;
  http_status?: number; latency_ms?: number; event_count: number; threat_count: number;
  last_event_at?: string; last_scan_at?: string; last_scan_findings?: number | null;
  verified?: boolean; verified_method?: string | null;
  verification?: { token: string; methods: Array<{ id: string; title: string; how: string }> };
};
type Probe = { probe: string; status_code?: number | null; latency_ms?: number; result: string; severity: string; details: string };
type Assessment = {
  summary?: string; finding_count?: number; checks?: Array<{ title: string; result: string; severity: string; details: string; recommendation?: string; fix?: string }>;
  probes?: Probe[]; requests_sent?: number; scope: string;
  redirects?: string[];
  source?: string; scanned_files?: number;
  findings?: Array<{ severity: string; title: string; file: string; line: number; evidence: string; recommendation: string }>;
};

const apiRequest = async (path: string, init?: RequestInit) => {
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), 90_000);
  try {
    const response = await apiFetch(apiUrl(path), { ...init, signal: controller.signal });
    const text = await response.text();
    let data: any = {};
    try { data = text ? JSON.parse(text) : {}; } catch { data = {}; }
    if (!response.ok) throw new Error(data.detail || `Server returned ${response.status}.`);
    return data;
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') throw new Error('This request took too long. The free Render service may be waking up, or the website may not be responding. Wait a moment and try again.');
    if (error instanceof TypeError) throw new Error('Could not reach Sentinel. Its Render service may be starting up; wait a few seconds and try again.');
    throw error;
  } finally { window.clearTimeout(timer); }
};

export const IntegrationsModal: React.FC<{ isOpen: boolean; onClose: () => void }> = ({ isOpen, onClose }) => {
  const [sites, setSites] = useState<Site[]>([]);
  const [name, setName] = useState('');
  const [url, setUrl] = useState('https://');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [credential, setCredential] = useState<{ id: string; key: string } | null>(null);
  const [assessments, setAssessments] = useState<Record<string, Assessment>>({});
  const [activeAction, setActiveAction] = useState<string | null>(null);
  const [loadingMessage, setLoadingMessage] = useState('');
  const [sourceArchives, setSourceArchives] = useState<Record<string, File | undefined>>({});
  const [assessmentCooldowns, setAssessmentCooldowns] = useState<Record<string, number>>({});
  const [clockNow, setClockNow] = useState(Date.now());

  useEffect(() => {
    const timer = window.setInterval(() => setClockNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  const cooldownKey = (site: Site) => {
    try { return new URL(site.url).hostname; } catch { return site.id; }
  };
  const assessmentWait = (site: Site) => Math.max(0, Math.ceil(((assessmentCooldowns[cooldownKey(site)] || 0) - clockNow) / 1000));

  const refresh = async () => {
    setSites(await apiRequest('/api/integrations'));
  };
  useEffect(() => {
    if (!isOpen) return;
    setLoadingMessage('Loading connected websites…');
    refresh().catch(e => setError(e instanceof Error ? e.message : 'Could not load integrations.')).finally(() => setLoadingMessage(''));
  }, [isOpen]);
  if (!isOpen) return null;

  const add = async (event: React.FormEvent) => {
    event.preventDefault(); setBusy(true); setError(''); setCredential(null);
    try {
      setLoadingMessage('Connecting to Sentinel…');
      let siteName = name.trim();
      if (!siteName) { try { siteName = new URL(url).hostname; } catch { siteName = url; } }
      const result = await apiRequest('/api/integrations', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: siteName, url }) });
      setCredential({ id: result.id, key: result.integration_key }); setName(''); setUrl('https://'); await refresh();
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not add site.'); }
    finally { setBusy(false); setLoadingMessage(''); }
  };
  const check = async (site: Site) => {
    setActiveAction(`${site.id}:check`); setError(''); setLoadingMessage(`Checking ${site.name}…`);
    try { await apiRequest(`/api/integrations/${site.id}/check`, { method: 'POST' }); }
    finally { setActiveAction(null); setLoadingMessage(''); }
    await refresh();
  };
  const verify = async (site: Site) => {
    setActiveAction(`${site.id}:verify`); setError(''); setLoadingMessage(`Looking for the verification token on ${site.name}…`);
    try { await apiRequest(`/api/integrations/${site.id}/verify`, { method: 'POST' }); await refresh(); }
    catch (e) { setError(e instanceof Error ? e.message : 'Verification failed.'); }
    finally { setActiveAction(null); setLoadingMessage(''); }
  };
  const assess = async (site: Site, mode: 'scan' | 'simulate') => {
    setActiveAction(`${site.id}:${mode}`); setError(''); setLoadingMessage(`${mode === 'scan' ? 'Running security checks on' : 'Sending safe probes to'} ${site.name}…`);
    try {
      const result = await apiRequest(`/api/integrations/${site.id}/${mode}`, { method: 'POST' });
      setAssessments(current => ({ ...current, [site.id]: result }));
      const until = Date.now() + 30_000;
      setAssessmentCooldowns(current => ({ ...current, [cooldownKey(site)]: until }));
      if (mode === 'simulate') await refresh();
      const sample = mode === 'scan' ? result : result.probes?.find((probe: Probe) => probe.status_code != null);
      const statusCode = mode === 'scan' ? result.http_status : sample?.status_code;
      const latency = mode === 'scan' ? result.latency_ms : sample?.latency_ms;
      if (statusCode != null) {
        setSites(current => current.map(entry => entry.id === site.id ? {
          ...entry,
          status: statusCode < 500 ? 'online' : 'degraded',
          http_status: statusCode,
          latency_ms: latency ?? entry.latency_ms,
          checked_at: mode === 'scan' ? result.checked_at : result.simulated_at,
          ...(mode === 'scan' ? { last_scan_at: result.checked_at, last_scan_findings: result.finding_count } : {}),
        } : entry));
      }
    } catch (e) {
      const message = e instanceof Error ? e.message : 'Assessment failed.';
      if (message.includes('assessed recently')) setAssessmentCooldowns(current => ({ ...current, [cooldownKey(site)]: Date.now() + 30_000 }));
      setError(message);
    }
    finally { setActiveAction(null); setLoadingMessage(''); }
  };
  const scanSource = async (site: Site) => {
    setActiveAction(`${site.id}:source`); setError(''); setLoadingMessage(`Reviewing source code for ${site.name}…`);
    try {
      const data = new FormData();
      const file = sourceArchives[site.id];
      if (file) data.append('file', file);
      const options: RequestInit = { method: 'POST', body: data };
      const result = await apiRequest(`/api/integrations/${site.id}/source/upload`, options);
      setAssessments(current => ({ ...current, [`${site.id}:source`]: result }));
      setSourceArchives(current => ({ ...current, [site.id]: undefined }));
    } catch (e) { setError(e instanceof Error ? e.message : 'Source review failed.'); }
    finally { setActiveAction(null); setLoadingMessage(''); }
  };
  const remove = async (site: Site) => {
    const response = await apiFetch(apiUrl(`/api/integrations/${site.id}`), { method: 'DELETE' });
    if (!response.ok) throw new Error('Could not remove site.');
    setAssessments(current => { const next = { ...current }; delete next[site.id]; return next; });
    await refresh();
  };

  return <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 bg-black/80 backdrop-blur-sm">
    <section className="bg-[var(--color-paper-2)] border border-[var(--color-rule)] w-full max-w-3xl rounded-xl shadow-2xl max-h-[92vh] overflow-y-auto">
      <header className="sticky top-0 bg-[var(--color-sidebar)] border-b border-[var(--color-rule)] p-5 flex justify-between items-center z-10">
        <div><h2 className="text-lg font-bold text-white">Website integrations</h2><p className="text-xs text-slate-400 mt-1">Security checks and attack telemetry for websites you own</p></div>
        <button onClick={onClose} aria-label="Close" className="text-slate-400 hover:text-white"><X /></button>
      </header>
      <div className="p-5 space-y-5">
        <form onSubmit={add} className="rounded-lg border border-[var(--color-rule)] bg-[var(--color-paper-3)] p-4 space-y-3">
          <h3 className="text-xs font-bold tracking-wider text-cyan-300 uppercase">Connect a website</h3>
          <p className="text-xs text-slate-400">Sentinel only ever runs checks against a website after you prove you own it (a meta tag, a small file, or a DNS record). Until then nothing is sent to the site. Sentinel never logs in, never reads your data, and its integration key can only send request telemetry in, not read anything out.</p>
          <div className="grid sm:grid-cols-2 gap-3"><input maxLength={80} placeholder="Store name (optional)" value={name} onChange={e => setName(e.target.value)} className="rounded bg-[var(--color-paper-2)] border border-[var(--color-rule)] px-3 py-2 text-sm text-white"/><input required type="url" placeholder="https://shop.example.com" value={url} onChange={e => setUrl(e.target.value)} className="rounded bg-[var(--color-paper-2)] border border-[var(--color-rule)] px-3 py-2 text-sm text-white"/></div>
          {loadingMessage && busy && <p role="status" className="text-xs text-cyan-200">{loadingMessage} The first request can take longer while a free Render service starts.</p>}
          <button disabled={busy} className="inline-flex items-center gap-2 rounded bg-cyan-700 hover:bg-cyan-600 px-3 py-2 text-xs font-semibold disabled:opacity-50"><Plus size={15}/>{busy ? 'Connecting…' : 'Add website'}</button>
        </form>
        {credential && <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-4 space-y-3 text-xs">
          <p className="font-bold text-amber-200">Save this integration key now. It is shown only once.</p>
          <div className="rounded bg-[var(--color-paper-3)] p-3 space-y-2"><p className="text-slate-400">Integration key</p><code className="block break-all text-slate-100">{credential.key}</code></div>
          <div className="rounded bg-[var(--color-paper-3)] p-3 space-y-1"><p className="text-slate-400">Telemetry endpoint</p><code className="block break-all text-slate-300">POST /api/integrations/{credential.id}/events</code><code className="block break-all text-slate-300">Authorization: Bearer &lt;key&gt;</code></div>
          <p className="text-slate-300">Forward only method, path, source IP, user agent, and sanitized query/body data. Never forward passwords, cookies, tokens, or payment data.</p>
          <pre className="overflow-x-auto rounded bg-[var(--color-paper-3)] p-2 text-[10px] text-slate-300">{`await fetch("${apiUrl(`/api/integrations/${credential.id}/events`)}", {
  method: "POST",
  headers: { "Content-Type": "application/json", "Authorization": "Bearer " + process.env.SENTINEL_KEY },
  body: JSON.stringify({ method: "GET", path: "/", client_ip: request.ip, user_agent: request.headers["user-agent"] })
});`}</pre>
          <button onClick={() => navigator.clipboard?.writeText(credential.key)} className="inline-flex items-center gap-1 text-cyan-300"><Copy size={13}/>Copy key</button>
        </div>}
        {error && <p role="alert" className="rounded border border-red-900/70 bg-red-950/30 p-3 text-sm text-red-200">{error}</p>}
        {loadingMessage && !busy && <p role="status" className="rounded border border-[var(--color-rule-2)] bg-[var(--color-paper-2)] p-3 text-xs text-zinc-300">{loadingMessage} The first request can take longer while a free Render service starts.</p>}
        <div className="space-y-2">{sites.length === 0 ? <div className="text-center text-sm text-slate-500 py-8">No websites connected yet.</div> : sites.map(site => <article key={site.id} className="rounded-lg border border-[var(--color-rule)] bg-[var(--color-sidebar)]/60 p-4">
          <div className="flex flex-wrap items-start justify-between gap-3"><div className="min-w-0"><h3 className="font-semibold text-white">{site.name}{site.verified && <span className="ml-2 rounded bg-emerald-500/20 px-1.5 py-0.5 text-[10px] font-bold uppercase text-emerald-300">Verified · {site.verified_method}</span>}</h3><a href={site.url} target="_blank" rel="noreferrer" className="text-xs text-cyan-300 break-all">{site.url}</a></div><div className="flex flex-wrap gap-2">
            {site.verified && <>
            <button disabled={activeAction !== null} onClick={() => check(site).catch(e => setError(e instanceof Error ? e.message : 'Availability check failed.'))} className="inline-flex items-center gap-1 rounded border border-[var(--color-rule)] px-2 py-1 text-xs text-slate-200 disabled:opacity-50"><RefreshCw size={13}/>{activeAction === `${site.id}:check` ? 'Checking…' : 'Check'}</button>
            <button disabled={activeAction !== null || assessmentWait(site) > 0} onClick={() => assess(site, 'scan')} className="inline-flex items-center gap-1 rounded border border-cyan-700 px-2 py-1 text-xs text-cyan-200 disabled:opacity-50"><ScanLine size={13}/>{activeAction === `${site.id}:scan` ? 'Scanning…' : assessmentWait(site) > 0 ? `Wait ${assessmentWait(site)}s` : 'Website review'}</button>
            <button disabled={activeAction !== null || assessmentWait(site) > 0} onClick={() => assess(site, 'simulate')} className="inline-flex items-center gap-1 rounded border border-amber-700 px-2 py-1 text-xs text-amber-200 disabled:opacity-50"><Zap size={13}/>{activeAction === `${site.id}:simulate` ? 'Probing…' : assessmentWait(site) > 0 ? `Wait ${assessmentWait(site)}s` : 'Simulate safe probes'}</button>
            </>}
            <button onClick={() => remove(site).catch(e => setError(e instanceof Error ? e.message : 'Could not remove site.'))} aria-label={`Remove ${site.name}`} className="rounded border border-red-900 px-2 py-1 text-red-300"><Trash2 size={13}/></button>
          </div></div>
          {!site.verified && site.verification && <div className="mt-4 space-y-2 rounded border border-amber-500/40 bg-amber-500/10 p-3 text-xs">
            <p className="font-semibold text-amber-200">Verify ownership to unlock checks</p>
            <p className="text-slate-300">Use any one method, then press Verify. Remove it afterwards only if you want to re-verify later (ownership is re-checked every 30 days).</p>
            {site.verification.methods.map(method => <div key={method.id} className="rounded bg-[var(--color-paper-3)] p-2"><p className="font-medium text-slate-200">{method.title}</p><code className="block break-all text-[11px] text-slate-300">{method.how}</code></div>)}
            <button disabled={activeAction !== null} onClick={() => verify(site)} className="rounded bg-cyan-700 hover:bg-cyan-600 px-3 py-2 text-xs font-semibold disabled:opacity-50">{activeAction === `${site.id}:verify` ? 'Checking…' : 'Verify ownership'}</button>
          </div>}
          {site.verified && <div className="mt-4 rounded border border-[var(--color-rule-2)] bg-black/20 p-3">
            <div className="mb-2 text-xs font-medium text-zinc-200">Source code review <span className="font-normal text-zinc-500">· upload code you own</span></div>
            <div className="mt-2 flex flex-wrap items-center gap-2"><input type="file" accept=".zip,application/zip" onChange={e => setSourceArchives(current => ({ ...current, [site.id]: e.target.files?.[0] }))} className="min-w-0 flex-1 text-xs text-zinc-400 file:mr-2 file:rounded file:border-0 file:bg-[var(--color-rule)] file:px-2 file:py-1.5 file:text-xs file:text-zinc-300"/><button disabled={activeAction !== null || !sourceArchives[site.id]} onClick={() => scanSource(site)} className="rounded border border-[var(--color-rule-2)] px-3 py-2 text-xs text-zinc-200 disabled:opacity-40">Review ZIP</button></div>
            <p className="mt-2 text-[10px] leading-4 text-zinc-600">ZIP limit 12 MB; source review reads up to 250 files / 5 MB, skips dependencies/build output, and never executes code. Pattern matches need manual review.</p>
          </div>}
          <div className="mt-3 flex flex-wrap gap-x-5 gap-y-1 text-xs text-slate-400"><span>Status: <b className={site.status === 'online' ? 'text-emerald-300' : site.status === 'unreachable' ? 'text-red-300' : 'text-slate-200'}>{site.status.replace('_', ' ')}</b></span><span>HTTP: {site.http_status ?? '—'}</span><span>Latency: {site.latency_ms != null ? `${site.latency_ms} ms` : '—'}</span><span><Activity className="inline" size={13}/> Events {site.event_count} · Threats {site.threat_count}</span></div>
          <p className="mt-2 text-[11px] text-slate-500">{site.last_event_at ? `Last telemetry: ${new Date(site.last_event_at).toLocaleString()}` : 'No telemetry received yet'}{site.checked_at ? ` · Checked ${new Date(site.checked_at).toLocaleString()}` : ''}{site.last_scan_at ? ` · Last scan: ${new Date(site.last_scan_at).toLocaleString()} (${site.last_scan_findings ?? 0} potential findings)` : ''}</p>
          {assessments[site.id] && <div className="mt-3 rounded border border-[var(--color-rule)] bg-[var(--color-paper-3)] p-3 space-y-2">
            <p className="text-xs font-semibold text-white">{assessments[site.id].summary ? `Website review: ${assessments[site.id].summary} (${assessments[site.id].finding_count} potential findings)` : `Simulation: ${assessments[site.id].requests_sent} safe GET probes sent`}</p>
            {assessments[site.id].checks?.filter(check => check.severity !== 'info').map((check, index) => <div key={`check-${index}`} className="space-y-1 rounded border border-[var(--color-rule)] bg-black/20 p-2 text-[11px]">
              <div className="flex items-center gap-2"><span className={`rounded px-1.5 py-0.5 text-[10px] font-bold uppercase ${check.severity === 'high' ? 'bg-rose-500/20 text-rose-300' : check.severity === 'medium' ? 'bg-amber-500/20 text-amber-300' : 'bg-slate-500/20 text-slate-300'}`}>{check.severity}</span><b className="text-slate-100">{check.title}</b></div>
              <p className="text-slate-400">{check.details}</p>
              {check.recommendation && <p className="text-emerald-300"><b>How to fix:</b> {check.recommendation}</p>}
              {check.fix && <div className="flex items-start gap-2"><pre className="min-w-0 flex-1 overflow-x-auto rounded bg-[var(--color-paper-3)] p-2 text-[10px] text-cyan-200">{check.fix}</pre><button onClick={() => navigator.clipboard?.writeText(check.fix || '')} className="inline-flex shrink-0 items-center gap-1 rounded border border-[var(--color-rule-2)] px-2 py-1 text-[10px] text-zinc-400 hover:text-white"><Copy size={12}/>Copy</button></div>}
            </div>)}
            {assessments[site.id].checks && <p className="text-[11px] text-emerald-300">{assessments[site.id].checks!.filter(check => check.severity === 'info').length} informational observations hidden</p>}
            {assessments[site.id].redirects && assessments[site.id].redirects!.length > 0 && <p className="text-[10px] text-zinc-500">Redirect path: {assessments[site.id].redirects!.join(' → ')}</p>}
            {assessments[site.id].probes?.map((probe, index) => <div key={`probe-${index}`} className="text-[11px] text-slate-300"><b className={probe.severity === 'info' ? 'text-emerald-300' : 'text-amber-300'}>{probe.probe}: {probe.result}</b><span className="block text-slate-400">HTTP {probe.status_code ?? '—'} · {probe.details}</span></div>)}
            <p className="text-[10px] text-slate-500">{assessments[site.id].scope}</p>
          </div>}
          {assessments[`${site.id}:source`] && <div className="mt-3 space-y-2 rounded border border-emerald-900/60 bg-emerald-950/10 p-3">
            <p className="text-xs font-semibold text-zinc-100">Code review: {assessments[`${site.id}:source`].summary} · {assessments[`${site.id}:source`].finding_count} potential issues · {assessments[`${site.id}:source`].scanned_files} files</p>
            <p className="text-[10px] text-zinc-500">Source: {assessments[`${site.id}:source`].source}</p>
            {assessments[`${site.id}:source`].findings?.map((finding, index) => <div key={`finding-${index}`} className="rounded border border-[var(--color-rule)] bg-black/20 p-2 text-[11px]"><div className="flex flex-wrap justify-between gap-1"><b className={finding.severity === 'high' ? 'text-rose-300' : finding.severity === 'medium' ? 'text-amber-300' : 'text-zinc-300'}>{finding.severity.toUpperCase()} · {finding.title}</b><span className="text-zinc-500">{finding.file}:{finding.line}</span></div><code className="mt-1 block break-all text-zinc-400">{finding.evidence}</code><p className="mt-1 text-zinc-500">{finding.recommendation}</p></div>)}
            {assessments[`${site.id}:source`].finding_count === 0 && <p className="text-[11px] text-emerald-300">No configured risk patterns matched. This does not mean the application has no vulnerabilities.</p>}
            <p className="text-[10px] text-zinc-600">{assessments[`${site.id}:source`].scope}</p>
          </div>}
        </article>)}</div>
        <p className="text-[11px] text-slate-500">Website review checks one public page with a bounded read-only HTTPS request, and only on sites you have verified. Source review needs code you are authorized to assess. Neither is a full penetration test. Ongoing attack detection requires the site to forward sanitized request telemetry. Integration records remain in backend memory and clear when it restarts.</p>
      </div>
    </section>
  </div>;
};
