import React, { useCallback, useEffect, useRef, useState } from 'react'
import { AlertTriangle, CheckCircle2, Clock, Copy, Download, Lock, Plug, Plus, RefreshCw, ShieldCheck, Trash2, Unplug } from 'lucide-react'
import { api, download } from '../api'
import { useConfirm, useToast } from '../feedback'
import { Card, Empty, ErrorNote, Modal, PageHead, SevBadge, Spinner, Tabs, canAct, num, relTime } from './ui'

export const DEFAULT_REDACT = ['password', 'passwd', 'pass', 'pwd', 'token', 'user_token', 'csrf_token', '_token', 'authenticity_token', 'access_token', 'refresh_token', 'jwt', 'auth', 'secret', 'api_key', 'apikey', 'authorization', 'session', 'sessionid', 'csrf']
const STATUS = {
  connected: { label: 'Connected', cls: 'st-mitigated', icon: CheckCircle2 },
  silent: { label: 'Silent', cls: 'st-open', icon: AlertTriangle },
  waiting: { label: 'Waiting for the collector', cls: 'st-acknowledged', icon: Clock },
  revoked: { label: 'Revoked', cls: 'st-resolved', icon: Lock },
}
const splitList = (t) => t.split(/[\n,]/).map((x) => x.trim()).filter(Boolean)

export function StatusPill({ status }) {
  const s = STATUS[status] || STATUS.waiting
  return <span className={`badge ${s.cls}`}>{s.label}</span>
}

function copy(text, toast, what = 'Copied') {
  const done = () => toast(`${what} to the clipboard`)
  if (navigator.clipboard?.writeText) navigator.clipboard.writeText(text).then(done, () => toast('Could not copy: select the text and copy it manually', 'error'))
  else toast('Clipboard is not available: select the text and copy it manually', 'error')
}

// ---------------------------------------------------------------------------------------------------------------- policy form
function PolicyForm({ initial, onSubmit, submitLabel, busy, error }) {
  const [name, setName] = useState(initial?.name || '')
  const [protectedIp, setProtectedIp] = useState(initial?.policy?.protected_ip || '')
  const [exclude, setExclude] = useState((initial?.policy?.exclude_paths || ['/health', '/healthz']).join('\n'))
  const [extra, setExtra] = useState((initial?.policy?.redact_params || []).filter((p) => !DEFAULT_REDACT.includes(p)).join(', '))
  const [pseudo, setPseudo] = useState(!!initial?.policy?.pseudonymize_ips)
  const submit = (e) => {
    e.preventDefault()
    onSubmit({ name: name.trim(), policy: { exclude_paths: splitList(exclude), redact_params: [...DEFAULT_REDACT, ...splitList(extra).map((x) => x.toLowerCase())], pseudonymize_ips: pseudo, protected_ip: protectedIp.trim() } })
  }
  return (
    <form className="grid" onSubmit={submit}>
      <label className="field">Name<input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Shop web server" required minLength={2} maxLength={64} autoFocus /></label>
      <label className="field">Protected server address (optional)
        <input value={protectedIp} onChange={(e) => setProtectedIp(e.target.value)} placeholder="e.g. 10.0.0.10" />
        <span className="muted" style={{ fontSize: '.76rem' }}>Shown as the attack target and used to raise the risk score if it is a critical asset.</span>
      </label>
      <div className="note info" style={{ margin: 0 }}>
        <b>You decide what Argus can see.</b> These rules are applied on <i>your</i> server by the collector, before anything is sent, and enforced again on arrival.
      </div>
      <label className="field">Never send requests under these paths (one per line)
        <textarea value={exclude} onChange={(e) => setExclude(e.target.value)} rows={3} placeholder={'/health\n/admin'} />
      </label>
      <label className="field">Always hide the value of these query parameters
        <input value={extra} onChange={(e) => setExtra(e.target.value)} placeholder="extra names, comma separated (e.g. sid, card)" />
        <span className="muted" style={{ fontSize: '.76rem' }}>Already hidden by default: {DEFAULT_REDACT.slice(0, 8).join(', ')}, … ({DEFAULT_REDACT.length} names)</span>
      </label>
      <label className="row" style={{ justifyContent: 'space-between', flexWrap: 'nowrap', gap: '1rem' }}>
        <span><b>Replace visitor IP addresses with pseudonyms</b><div className="muted" style={{ fontSize: '.78rem' }}>Argus still groups requests per visitor, but never sees real addresses. Blocking rules then need the real address from your own logs.</div></span>
        <span className="switch"><input type="checkbox" checked={pseudo} onChange={(e) => setPseudo(e.target.checked)} aria-label="Pseudonymise IP addresses" /><span /></span>
      </label>
      <ErrorNote error={error} />
      <button className="btn" disabled={busy || name.trim().length < 2}>{busy ? 'Saving…' : submitLabel}</button>
    </form>
  )
}

// ---------------------------------------------------------------------------------------------------------------- key + setup instructions
function KeyPanel({ apiKey, source, onDone, rotated }) {
  const toast = useToast()
  const [os, setOs] = useState('linux')
  const [live, setLive] = useState(source)
  const origin = window.location.origin
  const timer = useRef(null)
  useEffect(() => {
    let stop = false
    const tick = async () => {
      try { const s = (await api.sources()).sources.find((x) => x.id === source.id); if (!stop && s) setLive(s) } catch { /* keep polling */ }
      if (!stop) timer.current = setTimeout(tick, 3000)
    }
    tick()
    return () => { stop = true; clearTimeout(timer.current) }
  }, [source.id])
  const cmd = {
    linux: `export ARGUS_KEY='${apiKey}'\npython3 argus_collector.py --url ${origin} --file /var/log/nginx/access.log`,
    windows: `$env:ARGUS_KEY = '${apiKey}'\npython argus_collector.py --url ${origin} --file "C:\\path\\to\\access.log"`,
    docker: `docker run -d --name argus-collector --restart unless-stopped \\\n  -e ARGUS_URL=${origin} -e ARGUS_KEY='${apiKey}' \\\n  -v "$(pwd)/argus_collector.py:/app/argus_collector.py:ro" \\\n  -v /var/log/nginx:/logs:ro -v argus-collector-state:/state \\\n  python:3.11-slim python /app/argus_collector.py \\\n  --file /logs/access.log --state-file /state/state.json`,
  }[os]
  return (
    <div className="grid">
      <div className="note warn" style={{ margin: 0 }}><AlertTriangle size={14} style={{ verticalAlign: '-2px' }} /> <b>Copy this key now.</b> It is shown only once and cannot be recovered{rotated ? '; the previous key no longer works' : ''}. If you lose it, rotate it.</div>
      <div className="keybox"><code className="mono">{apiKey}</code><button className="btn sm" onClick={() => copy(apiKey, toast, 'Key copied')}><Copy size={13} /> Copy</button></div>
      <div>
        <div className="row" style={{ justifyContent: 'space-between', marginBottom: '.4rem' }}>
          <b>Run the collector next to your web server</b>
          <button className="btn ghost sm" onClick={() => download('/api/collector/download', 'argus_collector.py').catch((e) => toast(e.message, 'error'))}><Download size={13} /> Download collector</button>
        </div>
        <div className="seg" style={{ marginBottom: '.5rem' }}>{[['linux', 'Linux / macOS'], ['windows', 'Windows'], ['docker', 'Docker']].map(([id, l]) => <button key={id} className={os === id ? 'on' : ''} onClick={() => setOs(id)}>{l}</button>)}</div>
        <pre className="code">{cmd}</pre>
        <div className="row"><button className="btn ghost sm" onClick={() => copy(cmd, toast, 'Command copied')}><Copy size={13} /> Copy command</button>
          <span className="muted" style={{ fontSize: '.78rem' }}>Needs Python 3.8+ (nothing else). If Argus runs on this same computer and the collector runs in Docker, use <span className="mono">http://host.docker.internal:PORT</span> as the URL.</span></div>
      </div>
      <div className={`note ${live.status === 'connected' ? 'ok' : 'info'}`} style={{ margin: 0 }} role="status">
        {live.status === 'connected'
          ? <><CheckCircle2 size={14} style={{ verticalAlign: '-2px' }} /> <b>Connected!</b> Argus is receiving data ({num(live.events_total)} events so far). The dashboard is now in Live mode.</>
          : <><Clock size={14} style={{ verticalAlign: '-2px' }} /> Waiting for the collector to connect… this updates automatically.</>}
      </div>
      <button className="btn" onClick={onDone}>{live.status === 'connected' ? 'Finish' : 'Close (it keeps listening)'}</button>
    </div>
  )
}

// ---------------------------------------------------------------------------------------------------------------- wizard
const KINDS = [
  { id: 'web_access_log', label: 'Web server access log', text: 'Nginx, Apache, Caddy and similar. Detects SQL injection, XSS, path traversal, command injection, brute force, scans and floods.', ready: true },
  { id: 'honeypot', label: 'Honeypot', text: 'A decoy server that records real attackers.', ready: false },
  { id: 'auth_log', label: 'Authentication logs', text: 'SSH, Windows and identity-provider sign-ins.', ready: false },
  { id: 'endpoint', label: 'Endpoint (EDR) logs', text: 'Malware and ransomware activity on laptops and servers.', ready: false },
]

function Wizard({ onClose, onCreated }) {
  const [step, setStep] = useState(0)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [created, setCreated] = useState(null)
  const create = async (body) => {
    setBusy(true); setError('')
    try { const r = await api.createSource({ ...body, kind: 'web_access_log' }); setCreated(r); setStep(2); onCreated() } catch (e) { setError(e.message) }
    setBusy(false)
  }
  return (
    <Modal title="Connect a source" onClose={onClose} wide>
      <div className="steps" aria-label="Progress">{['Choose type', 'Name & privacy', 'Connect'].map((l, i) => <span key={l} className={i === step ? 'on' : i < step ? 'done' : ''}><i>{i < step ? '✓' : i + 1}</i>{l}</span>)}</div>
      {step === 0 && (
        <div className="grid">
          <div className="kinds">{KINDS.map((k) => (
            <button key={k.id} className={`kind ${k.ready ? '' : 'off'}`} disabled={!k.ready} onClick={() => setStep(1)}>
              <b>{k.label}</b>{!k.ready && <span className="badge st-resolved">Coming soon</span>}<span className="muted">{k.text}</span>
            </button>))}</div>
          <div className="muted" style={{ fontSize: '.8rem' }}>Argus never reaches into your systems. A small collector on your side reads the log you point it at and sends only what you allow.</div>
        </div>)}
      {step === 1 && <PolicyForm onSubmit={create} submitLabel="Create source and get key" busy={busy} error={error} />}
      {step === 2 && created && <KeyPanel apiKey={created.api_key} source={created.source} onDone={onClose} />}
    </Modal>
  )
}

function EditModal({ source, onClose, onSaved }) {
  const toast = useToast()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const save = async (body) => {
    setBusy(true); setError('')
    try { await api.updateSource(source.id, body); toast('Source updated. The collector applies new privacy rules within 30 seconds.'); onSaved(); onClose() } catch (e) { setError(e.message) }
    setBusy(false)
  }
  return <Modal title={`Edit “${source.name}”`} onClose={onClose}><PolicyForm initial={source} onSubmit={save} submitLabel="Save changes" busy={busy} error={error} /></Modal>
}

// ---------------------------------------------------------------------------------------------------------------- source card
function SourceCard({ s, admin, reload }) {
  const toast = useToast()
  const confirm = useConfirm()
  const [edit, setEdit] = useState(false)
  const [newKey, setNewKey] = useState(null)
  const p = s.policy || {}
  const act = async (fn, msg) => { try { const r = await fn(); if (msg) toast(msg); reload(); return r } catch (e) { toast(e.message, 'error') } return null }
  const rotate = async () => {
    const r = await confirm({ title: 'Rotate the API key?', confirmLabel: 'Rotate', body: 'The current key stops working immediately. The collector must be updated with the new key.' })
    if (r.ok) { const out = await act(() => api.rotateSource(s.id)); if (out) setNewKey(out) }
  }
  const revoke = async () => { const r = await confirm({ title: 'Revoke this source?', danger: true, confirmLabel: 'Revoke', body: 'The collector is cut off immediately (it will receive “401”). You can re-activate it later by rotating the key.' }); if (r.ok) act(() => api.revokeSource(s.id), 'Source revoked') }
  const remove = async () => { const r = await confirm({ title: `Delete “${s.name}”?`, danger: true, confirmLabel: 'Delete', body: 'The key is destroyed. Alerts and events already recorded are kept.' }); if (r.ok) act(() => api.deleteSource(s.id), 'Source deleted') }
  return (
    <article className="src-card">
      <header className="row" style={{ justifyContent: 'space-between', flexWrap: 'nowrap' }}>
        <div><h3>{s.name}</h3><span className="muted" style={{ fontSize: '.8rem' }}>{s.kind_label} · key <span className="mono">{s.key_prefix}…</span></span></div>
        <StatusPill status={s.status} />
      </header>
      {s.status === 'silent' && <div className="note error" style={{ margin: 0 }}>No data or heartbeat for {relTime(s.last_contact).replace(' ago', '')}. The collector may be stopped, or logging was switched off. Attackers sometimes disable logging.</div>}
      <dl className="kv" style={{ gridTemplateColumns: '120px 1fr' }}>
        <dt>Last contact</dt><dd>{relTime(s.last_contact)}</dd>
        <dt>Events / threats</dt><dd>{num(s.events_total)} / {num(s.threats_total)}{s.rejected_total > 0 && <span className="muted"> · {num(s.rejected_total)} rejected</span>}</dd>
        {s.info?.version && <><dt>Collector</dt><dd className="mono">v{s.info.version}{s.info.hostname ? ` on ${s.info.hostname}` : ''}</dd></>}
        {p.protected_ip && <><dt>Protects</dt><dd className="mono">{p.protected_ip}</dd></>}
      </dl>
      <div className="chips">
        <span className="chip static"><ShieldCheck size={11} /> {(p.redact_params || []).length} secrets redacted</span>
        <span className="chip static">{(p.exclude_paths || []).length} paths excluded</span>
        {p.pseudonymize_ips && <span className="chip static"><Lock size={11} /> IPs pseudonymised</span>}
      </div>
      {admin && (
        <div className="row" style={{ marginTop: '.2rem' }}>
          <button className="btn ghost sm" onClick={() => setEdit(true)}>Edit privacy</button>
          <button className="btn ghost sm" onClick={rotate}><RefreshCw size={13} /> Rotate key</button>
          {s.status !== 'revoked' && <button className="btn ghost sm" onClick={revoke}><Unplug size={13} /> Revoke</button>}
          <button className="btn ghost sm" onClick={remove} aria-label={`Delete ${s.name}`}><Trash2 size={13} /></button>
        </div>)}
      {edit && <EditModal source={s} onClose={() => setEdit(false)} onSaved={reload} />}
      {newKey && <Modal title="New API key" onClose={() => setNewKey(null)} wide><KeyPanel apiKey={newKey.api_key} source={newKey.source} rotated onDone={() => setNewKey(null)} /></Modal>}
    </article>
  )
}

// ---------------------------------------------------------------------------------------------------------------- coverage
const COV = {
  covered: { label: 'Covered', cls: 'cov-ok' },
  silent: { label: 'Source silent', cls: 'cov-warn' },
  waiting: { label: 'Waiting for data', cls: 'cov-wait' },
  uncovered: { label: 'Not covered', cls: 'cov-no' },
  demo: { label: 'Demo only', cls: 'cov-demo' },
}

export function CoveragePanel({ cov }) {
  if (!cov) return <Spinner />
  const s = cov.summary
  return (
    <div className="grid">
      <div className={`note ${cov.mode === 'live' ? 'ok' : 'info'}`} style={{ margin: 0 }}>
        {cov.mode === 'live'
          ? <><b>Live mode.</b> {cov.sources.filter((x) => x.status === 'connected').length} real source(s) connected. Argus can see <b>{s.covered}</b> of {s.total} attack types from them; the rest need other kinds of logs.</>
          : <><b>Demo mode.</b> No real source is connected, so everything on the dashboard is simulated. Connect a source to see what Argus can really monitor.</>}
      </div>
      <div className="cov-grid">
        {cov.items.map((i) => {
          const c = COV[i.status]
          return (
            <div key={i.attack_type} className={`cov-card ${c.cls}`}>
              <div className="row" style={{ justifyContent: 'space-between', flexWrap: 'nowrap' }}><b>{i.attack_type}</b><SevBadge severity={i.severity} /></div>
              <span className="cov-status">{c.label}</span>
              {i.via.length > 0 && <span className="muted" style={{ fontSize: '.76rem' }}>via {i.via.join(', ')}</span>}
              {i.note && <span className="muted" style={{ fontSize: '.74rem' }}>{i.note}</span>}
              {i.status === 'uncovered' && i.needs && <span className="muted" style={{ fontSize: '.76rem' }}>Needs: {i.needs}</span>}
            </div>)
        })}
      </div>
      <Card title="Kinds of source">
        <div className="table-wrap" style={{ maxHeight: 'none' }}><table><thead><tr><th>Source</th><th>Status</th><th>Can detect</th></tr></thead><tbody>
          {cov.kinds.map((k) => <tr key={k.kind}><td><b>{k.label}</b><div className="muted" style={{ fontSize: '.76rem' }}>{k.description}</div></td>
            <td>{k.available ? <span className="badge st-mitigated">{k.live ? 'Available · live' : 'Available · upload'}</span> : <span className="badge st-resolved">Planned</span>}</td>
            <td className="muted" style={{ fontSize: '.8rem' }}>{k.covers.length > 8 ? `${k.covers.length} attack types` : k.covers.join(', ')}</td></tr>)}
        </tbody></table></div>
        <div className="muted" style={{ fontSize: '.78rem', marginTop: '.5rem' }}>Web access logs record URLs, not request bodies: attacks hidden in POST bodies cannot be seen from them.</div>
      </Card>
    </div>
  )
}

// ---------------------------------------------------------------------------------------------------------------- page
export default function Sources({ user, cov, reloadCov }) {
  const admin = canAct(user, 'admin')
  const [tab, setTab] = useState('sources')
  const [sources, setSources] = useState(null)
  const [error, setError] = useState('')
  const [wizard, setWizard] = useState(false)
  const load = useCallback(async () => { try { setSources((await api.sources()).sources); setError('') } catch (e) { setError(e.message) }; if (reloadCov) reloadCov() }, [reloadCov])
  useEffect(() => { load(); const id = setInterval(load, 8000); return () => clearInterval(id) }, [load])
  return (
    <>
      <PageHead eyebrow="Monitor" title="Sources & coverage" subtitle="Connect real systems and see exactly what Argus can, and cannot, detect. You decide what is shared, and can revoke access at any time.">
        {admin ? <button className="btn" onClick={() => setWizard(true)}><Plus size={15} /> Connect a source</button> : <span className="muted" style={{ fontSize: '.8rem' }}>Only an Admin can connect sources</span>}
      </PageHead>
      <ErrorNote error={error} />
      <Tabs value={tab} onChange={setTab} tabs={[{ id: 'sources', label: `Connected sources${sources ? ` (${sources.length})` : ''}` }, { id: 'coverage', label: 'Coverage' }]} />
      {tab === 'sources' && (!sources ? <Spinner /> : sources.length === 0 ? (
        <Card><Empty>
          <Plug size={28} style={{ marginBottom: '.5rem' }} />
          <p><b>No sources connected yet.</b></p>
          <p className="muted" style={{ maxWidth: 520, margin: '.4rem auto 1rem' }}>Argus is showing simulated demo traffic. Connect a web server's access log to monitor a real system in real time. You choose what is shared, and you can revoke access at any time.</p>
          {admin ? <button className="btn" onClick={() => setWizard(true)}><Plus size={15} /> Connect your first source</button> : <span className="muted">Ask an Admin to connect one.</span>}
          <p className="muted" style={{ fontSize: '.78rem', marginTop: '1rem' }}>No server handy? The Docker lab in <span className="mono">lab/README.md</span> starts a vulnerable website you can attack safely on your own computer.</p>
        </Empty></Card>
      ) : <div className="src-grid">{sources.map((s) => <SourceCard key={s.id} s={s} admin={admin} reload={load} />)}</div>)}
      {tab === 'coverage' && <CoveragePanel cov={cov} />}
      {wizard && <Wizard onClose={() => { setWizard(false); load() }} onCreated={load} />}
    </>
  )
}
