import React, { useCallback, useEffect, useRef, useState } from 'react'
import { Check, ChevronDown, X, ShieldCheck, Terminal } from 'lucide-react'
import { api } from '../api'
import { Bar, Card, Empty, ErrorNote, PageHead, SEV_COLOR, ScopeSwitch, SevBadge, Spinner, StatusBadge, canAct, fmtShort, fmtTime, isPseudonymised, pct, resolveScope } from './ui'

const ATTACKS = ['SQL Injection', 'XSS', 'Brute Force', 'Path Traversal', 'Command Injection', 'Web Reconnaissance', 'DDoS', 'Phishing', 'Malware', 'Ransomware', 'Botnet', 'Port Scanning', 'Insider Threat', 'MITM', 'Zero-Day']
const KEY_FEATURES = ['dst_port', 'src_bytes', 'dst_bytes', 'duration', 'conn_count_src', 'distinct_dst_ports', 'failed_logins', 'syn_ratio', 'payload_entropy', 'sql_kw_count', 'script_tag_count', 'domain_age_days', 'beacon_interval_std', 'dns_query_rate', 'smb_write_rate', 'off_hours', 'unusual_dest', 'cert_mismatch']

function FilterSelect({ label, value, options, onChange }) {
  const [open, setOpen] = useState(false)
  const root = useRef(null)
  const selected = options.find((option) => option.value === value) || options[0]

  useEffect(() => {
    if (open) root.current?.querySelector('[aria-selected="true"]')?.focus()
  }, [open])

  useEffect(() => {
    if (!open) return undefined
    const dismiss = (event) => {
      if (event.type === 'keydown' && event.key === 'Escape') {
        setOpen(false)
        root.current?.querySelector('.filter-trigger')?.focus()
      } else if (event.type === 'pointerdown' && !root.current?.contains(event.target)) setOpen(false)
    }
    document.addEventListener('keydown', dismiss)
    document.addEventListener('pointerdown', dismiss)
    return () => {
      document.removeEventListener('keydown', dismiss)
      document.removeEventListener('pointerdown', dismiss)
    }
  }, [open])

  const handleKeys = (event) => {
    if (event.key === 'Escape') {
      event.preventDefault()
      setOpen(false)
      root.current?.querySelector('.filter-trigger')?.focus()
      return
    }
    if (!['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) return
    event.preventDefault()
    const choices = [...root.current.querySelectorAll('[role="option"]')]
    const current = choices.indexOf(document.activeElement)
    const next = event.key === 'Home' ? 0 : event.key === 'End' ? choices.length - 1
      : (current + (event.key === 'ArrowDown' ? 1 : -1) + choices.length) % choices.length
    choices[next]?.focus()
  }

  return (
    <div className={`filter-select ${open ? 'is-open' : ''}`} ref={root} onKeyDown={handleKeys}>
      <button className="filter-trigger" type="button" aria-label={`${label}: ${selected.label}`} aria-haspopup="listbox" aria-expanded={open} onClick={() => setOpen((state) => !state)}>
        <span className="filter-caption">{label}</span><span className="filter-value">{selected.label}</span><ChevronDown size={14} className="filter-chevron" aria-hidden="true" />
      </button>
      {open && <div className="filter-options" role="listbox" aria-label={label}>
        {options.map((option) => (
          <button key={option.value} type="button" role="option" aria-selected={option.value === value} className={`filter-option ${option.value === value ? 'selected' : ''}`} onClick={() => { onChange(option.value); setOpen(false); root.current?.querySelector('.filter-trigger')?.focus() }}>
            <span>{option.label}</span>{option.value === value && <Check size={14} aria-hidden="true" />}
          </button>))}
      </div>}
    </div>
  )
}

const STATUS_FILTERS = [{ value: '', label: 'All statuses' }, ...['open', 'acknowledged', 'mitigated', 'resolved', 'false_positive'].map((s) => ({ value: s, label: s.replace('_', ' ') }))]
const SEVERITY_FILTERS = [{ value: '', label: 'All severities' }, ...['Critical', 'High', 'Medium', 'Low'].map((s) => ({ value: s, label: s }))]
const ATTACK_FILTERS = [{ value: '', label: 'All attack types' }, ...ATTACKS.map((s) => ({ value: s, label: s }))]
const SORT_FILTERS = [{ value: 'time', label: 'Newest' }, { value: 'risk', label: 'Highest risk' }, { value: 'count', label: 'Most frequent' }]

function AlertDrawer({ id, user, onClose, onChanged }) {
  const [a, setA] = useState(null)
  const [recs, setRecs] = useState(null)
  const [error, setError] = useState('')
  const [result, setResult] = useState(null)
  const [busy, setBusy] = useState(false)
  const [tab, setTab] = useState('mitigate')
  const analyst = canAct(user, 'analyst')

  const load = useCallback(async () => {
    try {
      const [al, r] = await Promise.all([api.alert(id), api.alertRecs(id)])
      setA(al); setRecs(r); setError('')
    } catch (e) { setError(e.message) }
  }, [id])
  useEffect(() => { load() }, [load])
  useEffect(() => { const k = (e) => { if (e.key === 'Escape') onClose() }; window.addEventListener('keydown', k); return () => window.removeEventListener('keydown', k) }, [onClose])

  const act = async (fn) => {
    setBusy(true); setError('')
    try { const r = await fn(); await load(); onChanged(); return r } catch (e) { setError(e.message) } finally { setBusy(false) }
  }

  return (
    <div className="drawer-bg" onClick={onClose}>
      <aside className="drawer" onClick={(e) => e.stopPropagation()} aria-label="Alert details">
        <div className="row" style={{ justifyContent: 'space-between' }}>
          <h2>Alert #{id}</h2><button className="btn ghost sm" onClick={onClose} aria-label="Close"><X size={14} /></button>
        </div>
        <ErrorNote error={error} />
        {!a || !recs ? <Spinner /> : (
          <>
            <Card>
              <div className="row" style={{ justifyContent: 'space-between' }}>
                <div><h2>{a.attack_type}</h2><span className="muted" style={{ fontSize: '.8rem' }}>MITRE ATT&CK {recs.mitre} (indicative)</span></div>
                <div className="row"><SevBadge severity={a.severity} /><StatusBadge status={a.status} /></div>
              </div>
              <p className="muted" style={{ fontSize: '.85rem', margin: '.5rem 0' }}>{recs.description}</p>
              <dl className="kv">
                <dt>Source → target</dt><dd className="mono">{a.src_ip}{isPseudonymised(a.src_ip) && <span className="badge role-viewer" style={{ marginLeft: '.4rem' }} title="The collector replaced the real address with a stable pseudonym">pseudonymised</span>}{a.dst_ip && a.dst_ip !== '0.0.0.0' ? ` → ${a.dst_ip}` : ''}{a.event?.dst_port ? `:${a.event.dst_port}` : ''}</dd>
                {a.source_name && <><dt>Reported by</dt><dd>{a.source_name}</dd></>}
                {a.source_kind === 'web_access_log' && a.event?.features && <><dt>Request</dt><dd className="mono" style={{ wordBreak: 'break-all' }}>{a.event.features.method} {a.event.features.path} → {a.event.features.status || '–'}{a.event.features.host ? ` (host ${a.event.features.host})` : ''}</dd>
                  {a.event.features.ua && <><dt>User-Agent</dt><dd className="mono" style={{ wordBreak: 'break-all', fontSize: '.78rem' }}>{a.event.features.ua}</dd></>}</>}
                <dt>Risk score</dt><dd>{a.risk_score} / 100 <Bar value={a.risk_score / 100} color={SEV_COLOR[a.severity]} /></dd>
                <dt>Confidence</dt><dd>{pct(a.confidence, 0)}</dd>
                <dt>Detected by</dt><dd>{a.sources.join(', ') || '–'}</dd>
                <dt>Occurrences</dt><dd>{a.count > 1 && a.last_seen - a.first_seen > 1 ? `${a.count} times, between ${fmtTime(a.first_seen)} and ${fmtTime(a.last_seen)}` : `${a.count} time, at ${fmtTime(a.last_seen)}`}</dd>
                {a.handled_by && <><dt>Last handled by</dt><dd>{a.handled_by}</dd></>}
                {a.event?.payload_sample && <><dt>{a.source_kind === 'web_access_log' ? 'Full request line' : 'Payload sample'}</dt><dd className="mono" style={{ wordBreak: 'break-all' }}>{a.event.payload_sample}</dd></>}
              </dl>
              {analyst && (
                <div className="row" style={{ marginTop: '.7rem' }}>
                  {a.status === 'open' && <button className="btn ghost sm" disabled={busy} onClick={() => act(() => api.setStatus(id, 'acknowledged'))}>Acknowledge</button>}
                  <button className="btn ghost sm" disabled={busy} onClick={() => act(() => api.setStatus(id, 'resolved'))}>Resolve</button>
                  <button className="btn ghost sm" disabled={busy} onClick={() => act(() => api.setStatus(id, 'false_positive'))}>Mark false positive</button>
                </div>)}
            </Card>

            <Card title="Why was this flagged?" right={<span className="muted" style={{ fontSize: '.75rem' }}>local explanation (feature-group occlusion)</span>}>
              {!a.explanation?.length ? <Empty>No explanation available.</Empty> : a.explanation.map((x) => (
                <div key={x.factor} style={{ marginBottom: '.5rem' }}>
                  <div className="row" style={{ justifyContent: 'space-between', fontSize: '.85rem' }}>
                    <span>{x.factor} <span className="muted mono">({x.feature} = {x.value})</span></span><span>{pct(x.share, 0)}</span>
                  </div>
                  <Bar value={x.share} />
                </div>))}
            </Card>

            <div>
              <div className="tabs">
                <button className={tab === 'mitigate' ? 'active' : ''} onClick={() => setTab('mitigate')}>Mitigation options</button>
                <button className={tab === 'compare' ? 'active' : ''} onClick={() => setTab('compare')}>Compare detection models</button>
              </div>
              {tab === 'mitigate' && (
                <div className="grid">
                  {result && (
                    <div className="note ok"><ShieldCheck size={14} /> <strong>{result.title}</strong> — {result.message}
                      {result.rule_text && <pre className="code"><Terminal size={12} /> {result.rule_text}</pre>}
                      {result.blocked_ip && <div>IP <span className="mono">{result.blocked_ip}</span> added to the (simulated) blocklist.</div>}
                    </div>)}
                  {recs.mitigation_options.map((o) => (
                    <div className="opt" key={o.id}>
                      <div className="row" style={{ justifyContent: 'space-between' }}><strong>{o.title}</strong><span className="badge st-resolved">{o.kind}</span></div>
                      <span className="muted" style={{ fontSize: '.82rem' }}>{o.description}</span>
                      <div className="row muted" style={{ fontSize: '.78rem' }}>
                        <span>Effectiveness: <strong style={{ color: 'var(--text)' }}>{o.effectiveness}</strong></span><span>Disruption: {o.disruption}</span><span>Time: {o.time_to_apply}</span>
                      </div>
                      {analyst && <button className="btn sm" style={{ alignSelf: 'flex-start' }} disabled={busy || a.status === 'mitigated'}
                        onClick={async () => { const r = await act(() => api.mitigate(id, o.id)); if (r) setResult(r) }}>Apply (simulate)</button>}
                    </div>))}
                  {a.mitigations.length > 0 && <div className="muted" style={{ fontSize: '.8rem' }}>History: {a.mitigations.map((m) => `${m.title} by ${m.applied_by}`).join(' · ')}</div>}
                </div>)}
              {tab === 'compare' && (
                <div className="table-wrap"><table><thead><tr><th>Model</th><th>Approach</th><th>{a.attack_type} F1</th><th>Recall</th><th>Overall acc.</th><th>FPR</th><th>ms/event</th><th>Rating</th></tr></thead><tbody>
                  {recs.detection_options.map((d) => (
                    <tr key={d.id} title={d.complexity}><td><strong>{d.model}</strong></td><td className="muted">{d.approach}</td>
                      <td>{pct(d.class_f1 ?? d.roc_auc)}</td><td>{pct(d.class_recall ?? d.recall)}</td><td>{pct(d.accuracy)}</td><td>{pct(d.false_positive_rate)}</td><td>{d.infer_ms ?? '–'}</td><td>{d.effectiveness}</td></tr>))}
                </tbody></table>
                  <div className="muted" style={{ fontSize: '.75rem', marginTop: '.5rem' }}>Measured on the hold-out set of the active training run. Hover a row for time complexity. For Zero-Day the figure shown is ROC-AUC against benign traffic.</div></div>)}
            </div>
          </>)}
      </aside>
    </div>
  )
}

export default function Alerts({ user, focusId, clearFocus, scope = 'all', scopePref = 'auto', setScopePref = () => {}, mode = 'demo' }) {
  const [f, setF] = useState({ status: '', severity: '', attack_type: '', q: '', sort: 'time' })
  const [page, setPage] = useState(0)
  const [data, setData] = useState({ alerts: [], total: 0 })
  const [loading, setLoading] = useState(true)
  const [open, setOpen] = useState(focusId || null)
  const [error, setError] = useState('')
  const size = 25
  // The Alerts page omits the Demo filter. If Demo was selected elsewhere, fall back to Auto here.
  const alertScopePref = scopePref === 'demo' ? 'auto' : scopePref
  const alertScope = resolveScope(alertScopePref, mode)

  const load = useCallback(async () => {
    try { setData(await api.alerts({ ...f, scope: alertScope, limit: size, offset: page * size })); setError('') } catch (e) { setError(e.message) } finally { setLoading(false) }
  }, [f, page, alertScope])
  useEffect(() => { load(); const id = setInterval(load, 8000); return () => clearInterval(id) }, [load])
  useEffect(() => { if (focusId) setOpen(focusId) }, [focusId])
  useEffect(() => { if (scopePref === 'demo') setScopePref('auto') }, [scopePref, setScopePref])
  const set = (k) => (next) => { const value = typeof next === 'string' ? next : next.target.value; setF((current) => ({ ...current, [k]: value })); setPage(0) }

  return (
    <>
      <PageHead eyebrow="Monitor" title="Alerts" subtitle="Repeated detections from the same source are grouped into one alert. Open one to see why it was flagged and how to respond." />
      <Card>
        <div className="row alert-filters-row" style={{ marginBottom: '.8rem' }}>
          <input placeholder="Search IP or attack…" value={f.q} onChange={set('q')} maxLength={64} aria-label="Search" />
          <FilterSelect label="Status" value={f.status} options={STATUS_FILTERS} onChange={set('status')} />
          <FilterSelect label="Severity" value={f.severity} options={SEVERITY_FILTERS} onChange={set('severity')} />
          <FilterSelect label="Attack type" value={f.attack_type} options={ATTACK_FILTERS} onChange={set('attack_type')} />
          <FilterSelect label="Sort" value={f.sort} options={SORT_FILTERS} onChange={set('sort')} />
          <ScopeSwitch value={alertScopePref} onChange={(v) => { setScopePref(v); setPage(0) }} mode={mode} exclude={['demo']} />
          <span className="muted alert-count" aria-live="polite">{loading ? 'Loading alerts…' : `${data.total} alerts`}</span>
        </div>
        <ErrorNote error={error} />
        {loading && <div className="alert-loading" role="status" aria-label="Loading alerts">{Array.from({ length: 5 }, (_, row) => <div className="alert-skeleton-row" key={row}>{Array.from({ length: 9 }, (_, col) => <span className={`alert-skeleton-cell w${(row + col) % 3}`} key={col} />)}</div>)}</div>}
        <div className="table-wrap" style={{ maxHeight: 'none' }}><table><thead><tr><th>#</th><th>Last seen</th><th>Attack</th><th>Severity</th><th>Risk</th><th>From → target</th><th>Reported by</th><th>Hits</th><th>Status</th></tr></thead><tbody>
          {data.alerts.map((a) => (
            <tr key={a.id} className="click" onClick={() => setOpen(a.id)}>
              <td>{a.id}</td><td className="nowrap">{fmtShort(a.last_seen)}</td><td className="nowrap"><strong>{a.attack_type}</strong></td><td><SevBadge severity={a.severity} /></td><td>{a.risk_score}</td>
              <td className="mono nowrap">{a.src_ip}{a.dst_ip && a.dst_ip !== '0.0.0.0' ? ` → ${a.dst_ip}` : ''}</td><td className="muted nowrap" style={{ fontSize: '.8rem' }}>{a.source_name || (a.origin === 'upload' ? 'Upload' : a.origin === 'lab' ? 'Simulated test (legacy)' : a.origin === 'connector' ? '(deleted source)' : 'Simulated')}</td><td>{a.count}</td><td><StatusBadge status={a.status} /></td>
            </tr>))}
          {!loading && data.alerts.length === 0 && <tr><td colSpan="9" className="empty">No alerts match.</td></tr>}
        </tbody></table></div>
        <div className="row" style={{ justifyContent: 'center', marginTop: '.8rem' }}>
          <button className="btn ghost sm" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button>
          <span className="muted">Page {page + 1} of {Math.max(1, Math.ceil(data.total / size))}</span>
          <button className="btn ghost sm" disabled={(page + 1) * size >= data.total} onClick={() => setPage(page + 1)}>Next</button>
        </div>
      </Card>
      {open && <AlertDrawer id={open} user={user} onClose={() => { setOpen(null); clearFocus && clearFocus() }} onChanged={load} />}
    </>
  )
}
