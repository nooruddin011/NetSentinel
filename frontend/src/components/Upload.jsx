import React, { useCallback, useEffect, useRef, useState } from 'react'
import { Eye, Trash2, Upload as UploadIcon } from 'lucide-react'
import { Bar as RBar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api } from '../api'
import { useChart } from '../theme'
import { useConfirm, useToast } from '../feedback'
import { Card, Empty, ErrorNote, PageHead, PALETTE, SevBadge, RoleBadge, canAct, fmtTime, pct } from './ui'

export default function Upload({ user }) {
  const c = useChart()
  const confirm = useConfirm()
  const toast = useToast()
  const [res, setRes] = useState(null)
  const [jobs, setJobs] = useState([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [over, setOver] = useState(false)
  const input = useRef(null)

  const loadJobs = useCallback(async () => { try { setJobs((await api.jobs()).jobs) } catch { /* non-critical */ } }, [])
  useEffect(() => { loadJobs() }, [loadJobs])

  const send = async (file) => {
    if (!file) return
    setBusy(true); setError(''); setRes(null)
    try { setRes(await api.upload(file)); loadJobs() } catch (e) { setError(e.message) }
    setBusy(false)
  }

  const isAdmin = user.role === 'admin'
  const view = async (id) => { try { const j = await api.job(id); setRes({ job_id: id, ...j.summary }); window.scrollTo({ top: 0, behavior: 'smooth' }) } catch (e) { setError(e.message) } }
  const remove = async (j) => {
    const r = await confirm({ title: 'Delete this upload log?', danger: true, confirmLabel: 'Delete',
      body: `“${j.filename}” (${j.rows_total} rows${isAdmin && j.created_by !== user.username ? `, uploaded by ${j.created_by}` : ''}) will be removed from the history.`,
      checkbox: 'Also delete the alerts and events found in this upload' })
    if (!r.ok) return
    try {
      const out = await api.deleteJob(j.id, r.checked)
      toast(r.checked ? `Upload deleted with ${out.alerts_deleted} alert(s) and ${out.events_deleted} event(s).` : 'Upload log deleted.')
      if (res?.job_id === j.id) setRes(null)
      loadJobs()
    } catch (e) { toast(e.message, 'error') }
  }

  if (!canAct(user, 'analyst')) return <><PageHead eyebrow="Analyse" title="Upload & analyse" /><div className="note warn">Your role (Viewer) cannot upload files. Ask an Analyst or Admin to upgrade your access.</div></>
  const byAttack = res ? Object.entries(res.by_attack).map(([name, value]) => ({ name, value })) : []
  const ev = res?.evaluation

  return (
    <>
      <PageHead eyebrow="Analyse" title="Upload & analyse" subtitle="Analyse a CSV of network flows with the full hybrid pipeline. Flagged rows become alerts.">
        <a className="btn ghost sm" href="/sample_traffic.csv" download>Download sample file</a>
      </PageHead>
      <div className={`drop ${over ? 'over' : ''}`} onDragOver={(e) => { e.preventDefault(); setOver(true) }} onDragLeave={() => setOver(false)}
        onDrop={(e) => { e.preventDefault(); setOver(false); send(e.dataTransfer.files[0]) }}>
        <UploadIcon size={28} />
        <p style={{ margin: '.5rem 0' }}>Drag a .csv here, or <button className="btn sm" onClick={() => input.current.click()} disabled={busy}>choose a file</button></p>
        <p style={{ fontSize: '.8rem' }}>Columns: <span className="mono">src_ip, dst_ip, protocol, dst_port, src_bytes, dst_bytes, duration, payload_sample, …</span> (CICIDS-style headers are recognised; a <span className="mono">label</span> column enables accuracy evaluation). Missing columns use typical-traffic defaults.</p>
        <input ref={input} type="file" accept=".csv,text/csv" hidden onChange={(e) => { send(e.target.files[0]); e.target.value = '' }} />
      </div>
      {busy && <div className="note">Analysing…</div>}
      <ErrorNote error={error} />
      {res && (
        <div className="grid g2" style={{ marginTop: '1rem' }}>
          <Card title={`Result — job #${res.job_id}`}>
            <dl className="kv">
              <dt>Rows analysed</dt><dd>{res.rows.toLocaleString()} in {res.seconds}s ({res.rows_per_second.toLocaleString()} rows/s)</dd>
              <dt>Flagged as threats</dt><dd><strong>{res.flagged.toLocaleString()}</strong> ({pct(res.flagged / res.rows)})</dd>
              <dt>New alerts</dt><dd>{res.alerts_created}</dd>
              <dt>Severity</dt><dd className="row">{Object.entries(res.by_severity).map(([s, n]) => <span key={s}><SevBadge severity={s} /> {n}</span>)}</dd>
              {res.columns_missing.length > 0 && <><dt>Defaulted columns</dt><dd className="muted" style={{ fontSize: '.8rem' }}>{res.columns_missing.length} of 30 features were absent and used typical-traffic defaults; detection quality drops accordingly.</dd></>}
            </dl>
            <h3 style={{ margin: '.8rem 0 .3rem' }}>Top sources</h3>
            <div className="table-wrap" style={{ maxHeight: 180 }}><table><tbody>{res.top_sources.map((s) => <tr key={s.ip}><td className="mono">{s.ip}</td><td>{s.events} events</td></tr>)}</tbody></table></div>
          </Card>
          <Card title="Detected attack types">
            <div className="chart">{byAttack.length === 0 ? <Empty>No threats found.</Empty> : <ResponsiveContainer><BarChart data={byAttack} layout="vertical" margin={{ left: 10 }}>
              <CartesianGrid stroke={c.grid} horizontal={false} /><XAxis type="number" stroke={c.axis} fontSize={11} /><YAxis type="category" dataKey="name" stroke={c.text} fontSize={11} width={130} />
              <Tooltip {...c.tip} /><RBar dataKey="value" radius={[0, 4, 4, 0]}>{byAttack.map((_, i) => <Cell key={i} fill={PALETTE[i % PALETTE.length]} />)}</RBar></BarChart></ResponsiveContainer>}</div>
          </Card>
          {ev && (
            <Card title="Evaluation against your labels" className="">
              <dl className="kv"><dt>Labelled rows</dt><dd>{ev.labelled_rows} ({ev.unmapped_labels} labels not recognised)</dd><dt>Accuracy</dt><dd>{pct(ev.accuracy)}</dd><dt>Detection rate</dt><dd>{pct(ev.detection_rate)}</dd><dt>False-positive rate</dt><dd>{pct(ev.false_positive_rate, 2)}</dd></dl>
              <div className="table-wrap" style={{ maxHeight: 220 }}><table><thead><tr><th>Class</th><th>Prec.</th><th>Recall</th><th>F1</th><th>n</th></tr></thead><tbody>{Object.entries(ev.per_class).map(([c, m]) => <tr key={c}><td>{c}</td><td>{pct(m.precision)}</td><td>{pct(m.recall)}</td><td>{pct(m.f1)}</td><td>{m.support}</td></tr>)}</tbody></table></div>
            </Card>)}
        </div>)}
      <Card title={isAdmin ? 'Upload history (all users)' : 'My upload history'} right={!isAdmin && <span className="muted" style={{ fontSize: '.75rem' }}>Only you can see these</span>}>
        <div className="table-wrap"><table><thead><tr><th>#</th><th>File</th>{isAdmin && <th>Uploaded by</th>}<th>When</th><th>Status</th><th>Rows</th><th>Flagged</th><th /></tr></thead><tbody>
          {jobs.map((j) => (
            <tr key={j.id}><td>{j.id}</td><td>{j.filename}</td>{isAdmin && <td>{j.created_by}</td>}<td>{fmtTime(j.created_at)}</td><td>{j.status}</td><td>{j.rows_total}</td><td>{j.rows_flagged}</td>
              <td><div className="row" style={{ gap: '.3rem', flexWrap: 'nowrap' }}>
                {j.status === 'done' && <button className="btn ghost sm" onClick={() => view(j.id)} title="View results"><Eye size={13} /></button>}
                <button className="btn ghost sm" onClick={() => remove(j)} title="Delete log" aria-label={`Delete upload ${j.filename}`}><Trash2 size={13} /></button></div></td></tr>))}
          {jobs.length === 0 && <tr><td colSpan={isAdmin ? 8 : 7} className="empty">No uploads yet.</td></tr>}
        </tbody></table></div>
      </Card>
    </>
  )
}
