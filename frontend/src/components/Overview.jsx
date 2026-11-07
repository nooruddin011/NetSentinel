import React, { useCallback, useEffect, useState } from 'react'
import { Activity, AlertTriangle, Eye, ShieldCheck, Users, Gauge, FileDown, Plug, Upload as UploadIcon } from 'lucide-react'
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Legend, Line, LineChart, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api, download } from '../api'
import { useChart } from '../theme'
import { Card, Empty, ErrorNote, PageHead, PALETTE, SEV_COLOR, ScopeSwitch, SevBadge, Stat, bytes, canAct, num, SimChip } from './ui'

function Heatmap({ cells }) {
  if (!cells.length) return <Empty>No threats recorded in this window yet.</Empty>
  const types = [...new Set(cells.map((c) => c.attack_type))].sort()
  const grid = {}
  let max = 1
  cells.forEach((c) => { grid[`${c.attack_type}|${c.hour}`] = c.count; max = Math.max(max, c.count) })
  return (
    <div className="heat-scroll">
      <div className="heat" role="img" aria-label="Attack heatmap by type and hour of day (UTC)">
        <span />
        {Array.from({ length: 24 }, (_, h) => <span key={h} className="muted" style={{ textAlign: 'center' }}>{h % 3 === 0 ? h : ''}</span>)}
        {types.map((t, row) => (
          <React.Fragment key={t}>
            <span className="lab" title={t}>{t}</span>
            {Array.from({ length: 24 }, (_, h) => {
              const v = grid[`${t}|${h}`] || 0
              return <span key={h} className={`cell ${v ? 'has-events' : ''}`} title={`${t} @ ${h}:00 UTC: ${v}`} style={{ '--heat-delay': `${(row * 24 + h) * 8}ms`, ...(v ? { background: `rgba(var(--heat-rgb),${0.18 + 0.82 * (v / max)})` } : {}) }} />
            })}
          </React.Fragment>
        ))}
      </div>
    </div>
  )
}

const RANGES = [{ h: 6, label: '6 h' }, { h: 24, label: '24 h' }, { h: 72, label: '3 d' }, { h: 168, label: '7 d' }]

// does an event from this origin belong in the selected view?
const inScope = (origin, scope) => scope === 'all' || (scope === 'live' ? origin === 'connector' : scope === 'demo' ? ['stream', 'seed', 'lab'].includes(origin) : scope === 'upload' ? origin === 'upload' : true)

export default function Overview({ user, live, openAlert, goTo, scope = 'all', scopePref = 'auto', setScopePref = () => {}, mode = 'demo', cov = null }) {
  const c = useChart()
  const [hours, setHours] = useState(24)
  const [sim, setSim] = useState(null)
  const [ov, setOv] = useState(null)
  const [timeline, setTimeline] = useState([])
  const [heat, setHeat] = useState([])
  const [sources, setSources] = useState([])
  const [forecast, setForecast] = useState(null)
  const [error, setError] = useState('')

  const load = useCallback(async () => {
    try {
      const [o, t, h, s, f, sm] = await Promise.all([api.overview(hours, scope), api.timeline(Math.min(hours, 72), scope), api.heatmap(168, scope), api.topSources(hours, scope), api.forecast(6, scope), api.simulation()])
      setOv(o); setTimeline(t.points); setHeat(h.cells); setSources(s.sources); setForecast(f); setSim(sm); setError('')
    } catch (e) { setError(e.message) }
  }, [hours, scope])

  useEffect(() => { load(); const id = setInterval(load, 10000); return () => clearInterval(id) }, [load])

  const fcData = forecast
    ? [...forecast.history.slice(-12).map((p) => ({ hour: p.hour, threats: p.threats })),
       ...forecast.forecast.map((v, i) => ({ hour: `+${i + 1}h`, forecast: v, band: [forecast.lower[i], forecast.upper[i]] }))]
    : []
  const sev = ov ? Object.entries(ov.by_severity).map(([name, value]) => ({ name, value })).filter((d) => d.value) : []
  const t = live.latestThreat && inScope(live.latestThreat.origin, scope) ? live.latestThreat : null
  const feed = live.events.filter((e) => inScope(e.origin, scope))
  const series = live.series.filter((e) => inScope(e.origin, scope))
  const silent = (cov?.sources || []).filter((s) => s.status === 'silent')
  const liveSources = (cov?.sources || []).filter((s) => s.status === 'connected')
  const label = RANGES.find((r) => r.h === hours)?.label || '24 h'

  return (
    <>
      <PageHead eyebrow="Monitor" title="Threat overview" subtitle="Live detections from your connected systems, with stored history, trends and a short-term forecast.">
          <ScopeSwitch value={scopePref} onChange={setScopePref} mode={mode} />
          <div className="seg" role="group" aria-label="Time range">{RANGES.map((r) => <button key={r.h} className={hours === r.h ? 'on' : ''} onClick={() => setHours(r.h)}>{r.label}</button>)}</div>
          {canAct(user, 'analyst') && goTo && <button className="btn sm" onClick={() => goTo('upload')}><UploadIcon size={14} /> Upload dataset</button>}
          <button className="btn ghost sm" onClick={() => download('/api/reports/summary.pdf?hours=24', 'cyberwatch-report.pdf').catch((e) => setError(e.message))}><FileDown size={14} /> PDF report</button>
          {canAct(user, 'analyst') && <button className="btn ghost sm" onClick={() => download('/api/reports/alerts.csv', 'alerts.csv').catch((e) => setError(e.message))}><FileDown size={14} /> CSV export</button>}
      </PageHead>
      <ErrorNote error={error} />
      {silent.length > 0 && (
        <div className="banner warn" role="alert"><span><AlertTriangle size={15} style={{ verticalAlign: '-3px' }} /> <b>{silent.map((s) => s.name).join(', ')}</b> stopped reporting. Monitoring of that system is paused: the collector may be down, or logging was switched off.</span>
          <button className="btn ghost sm" onClick={() => goTo && goTo('sources')}>Check sources</button></div>)}
      {mode === 'live'
        ? <div className="banner live"><span><span className="dot live" style={{ display: 'inline-block', marginRight: '.4rem' }} /> <b>Live mode</b> · monitoring {liveSources.length} real source{liveSources.length === 1 ? '' : 's'}: {liveSources.map((s) => s.name).join(', ') || '—'}. Simulated traffic is off.</span>
            <button className="btn ghost sm" onClick={() => goTo && goTo('sources')}>Sources & coverage</button></div>
        : <div className="banner demo"><span><b>Demo mode</b> · this dashboard is showing simulated traffic. Connect a real system to monitor it live.</span>
            <button className="btn sm" onClick={() => goTo && goTo('sources')}><Plug size={14} /> {canAct(user, 'admin') ? 'Connect a source' : 'See sources'}</button></div>}
      <div className="grid overview-heatmap">
        <Card title="Attack heatmap — type × hour of day (UTC, last 7 days)">
          <Heatmap cells={heat} />
        </Card>
      </div>
      <Card title="At a glance" className="overview-metrics">
        <div className="stats">
          <Stat label="Events" count={ov?.total_events} icon={Activity} delay={0} sub={`last ${label} · ${live.counts.total} live this session`} />
          <Stat label="Threats" count={ov?.threats} icon={AlertTriangle} tone={ov?.threats ? 'danger' : ''} delay={0.06} sub={ov ? `${((100 * ov.threats) / Math.max(ov.total_events, 1)).toFixed(1)}% of traffic` : ''} />
          <Stat label="Open alerts" count={ov?.open_alerts} icon={Eye} delay={0.12} sub={`${ov?.critical_open ?? 0} critical`} />
          <Stat label="Attackers" count={ov?.unique_attackers} icon={Users} delay={0.18} sub="distinct sources" />
          <Stat label="Avg risk" count={ov?.avg_risk} decimals={1} icon={Gauge} delay={0.24} sub="score out of 100" />
          <Stat label="Mitigations" count={ov?.mitigations_applied} icon={ShieldCheck} delay={0.3} sub={`simulated · ${ov?.blocked_events ?? 0} blocked events`} />
        </div>
      </Card>

      {t && (
        <div className="note" style={{ borderColor: SEV_COLOR[t.severity] }}>
          <div className="row" style={{ justifyContent: 'space-between' }}>
            <span><strong>Latest threat:</strong> {t.attack_type} <SevBadge severity={t.severity} /> from <span className="mono">{t.src_ip}</span> → <span className="mono">{t.dst_ip}</span> · risk {t.risk_score} · confidence {(t.confidence * 100).toFixed(0)}%</span>
            {t.alert_id && <button className="btn sm" onClick={() => openAlert(t.alert_id)}>Review & mitigate</button>}
          </div>
        </div>
      )}

      <div className="overview-bento-grid">
        <Card className="overview-bento-wide" title="Live traffic (bytes per event)" right={sim?.enabled && scope !== 'live' ? <SimChip /> : <span className="muted" style={{ fontSize: '.75rem' }}>{scope === 'live' ? 'real events only' : 'scope: ' + scope}</span>}>
          <div className="chart">
            {series.length === 0 ? <Empty>{scope === 'live' ? 'Waiting for real events from your connected source…' : `Waiting for the live stream… (status: ${live.status})`}</Empty> : (
              <ResponsiveContainer><AreaChart data={series}>
                <CartesianGrid stroke={c.grid} vertical={false} /><XAxis dataKey="t" hide /><YAxis stroke={c.axis} fontSize={11} width={50} />
                <Tooltip {...c.tip} /><Legend />
                <Area dataKey="normal" name="Normal" stroke={c.ice} fill={c.ice} fillOpacity={0.16} strokeWidth={1.8} isAnimationActive animationDuration={850} animationEasing="ease-out" />
                <Area dataKey="threat" name="Threat" stroke={c.danger} fill={c.danger} fillOpacity={0.24} strokeWidth={2} isAnimationActive animationDuration={950} animationEasing="ease-out" />
              </AreaChart></ResponsiveContainer>)}
          </div>
        </Card>
        <Card title="Threats per hour + 6 h forecast" right={<span className="muted" style={{ fontSize: '.75rem' }}>Holt smoothing</span>}>
          <div className="chart">
            <ResponsiveContainer><LineChart data={fcData}>
              <CartesianGrid stroke={c.grid} vertical={false} /><XAxis dataKey="hour" stroke={c.axis} fontSize={11} /><YAxis stroke={c.axis} fontSize={11} width={30} allowDecimals={false} />
              <Tooltip {...c.tip} /><Legend />
              <Line dataKey="threats" name="Observed" stroke={c.danger} strokeWidth={2.2} dot={false} connectNulls isAnimationActive animationDuration={850} animationEasing="ease-out" />
              <Line dataKey="forecast" name="Forecast" stroke={c.accent} strokeWidth={2.2} strokeDasharray="5 4" dot connectNulls isAnimationActive animationDuration={1050} animationEasing="ease-out" />
            </LineChart></ResponsiveContainer>
          </div>
        </Card>
        <Card title={`Severity (last ${label})`}>
          <div className="chart">
            {sev.length === 0 ? <Empty>No threats yet.</Empty> : (
              <ResponsiveContainer><PieChart>
                <Pie data={sev} dataKey="value" nameKey="name" innerRadius={55} outerRadius={85} paddingAngle={3} isAnimationActive animationDuration={900} animationEasing="ease-out">{sev.map((s) => <Cell key={s.name} fill={SEV_COLOR[s.name]} />)}</Pie>
                <Tooltip {...c.tip} /><Legend />
              </PieChart></ResponsiveContainer>)}
          </div>
        </Card>
        <Card className="overview-bento-wide" title={`Attack types (last ${label})`}>
          <div className="chart">
            {!ov?.by_attack.length ? <Empty>No threats yet.</Empty> : (
              <ResponsiveContainer><BarChart data={ov.by_attack} layout="vertical" margin={{ left: 10 }}>
                <CartesianGrid stroke={c.grid} horizontal={false} /><XAxis type="number" stroke={c.axis} fontSize={11} allowDecimals={false} /><YAxis type="category" dataKey="name" stroke={c.text} fontSize={11} width={130} />
                <Tooltip {...c.tip} cursor={{ fill: 'rgba(127,127,127,.12)' }} />
                <Bar dataKey="value" radius={[0, 5, 5, 0]} isAnimationActive animationDuration={800} animationEasing="ease-out">{ov.by_attack.map((_, i) => <Cell key={i} fill={PALETTE[i % PALETTE.length]} />)}</Bar>
              </BarChart></ResponsiveContainer>)}
          </div>
        </Card>
      </div>

      <div className="grid g2 overview-tables">
        <Card title={`Top attacking sources (${label})`}>
          {sources.length === 0 ? <Empty>No attackers recorded.</Empty> : (
            <div className="table-wrap"><table><thead><tr><th>Source</th><th>Events</th><th>Main attack</th><th>Max risk</th><th /></tr></thead><tbody>
              {sources.map((s) => <tr key={s.src_ip}><td className="mono">{s.src_ip}</td><td>{s.events}</td><td>{s.top_attack}</td><td>{s.max_risk}</td><td>{s.blocked && <span className="badge st-mitigated">blocked</span>}</td></tr>)}
            </tbody></table></div>)}
        </Card>
        <Card title="Live event feed" right={<span className="muted" style={{ fontSize: '.75rem' }}>{bytes(ov?.bytes_total)} analysed / {label}</span>}>
          <div className="table-wrap" style={{ maxHeight: 260 }}><table><thead><tr><th>Time</th><th>From</th><th>Feed</th><th>Verdict</th><th>Sev.</th></tr></thead><tbody>
            {feed.slice(0, 25).map((e) => (
              <tr key={e.key} className={e.verdict === 'threat' ? 'threat click' : ''} onClick={() => e.alert_id && openAlert(e.alert_id)}>
                <td className="nowrap">{e.timeStr}</td><td className="mono nowrap">{e.src_ip}</td><td className="muted" style={{ fontSize: '.78rem' }}>{e.origin === 'connector' ? (e.source || 'Live source') : e.origin === 'lab' ? 'Attack Lab' : e.origin === 'upload' ? 'Upload' : 'Simulated'}</td>
                <td>{e.verdict === 'threat' ? <strong style={{ color: 'var(--danger)' }}>{e.attack_type}</strong> : <span className="muted">normal</span>}</td><td><SevBadge severity={e.severity} /></td>
              </tr>))}
            {feed.length === 0 && <tr><td colSpan="5" className="empty">Waiting for events…</td></tr>}
          </tbody></table></div>
        </Card>
      </div>
    </>
  )
}
