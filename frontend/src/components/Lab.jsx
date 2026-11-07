import React, { useState } from 'react'
import { Box, CheckCircle2, Search, XCircle } from 'lucide-react'
import { api } from '../api'
import { Card, ErrorNote, PageHead, SevBadge, canAct, pct } from './ui'

const SCENARIOS = ['DDoS', 'SQL Injection', 'XSS', 'Phishing', 'Brute Force', 'Malware', 'Ransomware', 'Botnet', 'Port Scanning', 'Insider Threat', 'MITM', 'Zero-Day']
const EXAMPLES = ["wireless mouse", "' OR 1=1 --", "<script>alert(document.cookie)</script>", "1' UNION SELECT username,password FROM users--", "%3Cimg%20src=x%20onerror=alert(1)%3E"]

function Result({ r, openAlert }) {
  if (!r) return null
  const threat = r.verdict === 'threat'
  return (
    <div className="note" style={{ borderColor: threat ? 'var(--danger)' : 'var(--ok)' }}>
      <div className="row" style={{ justifyContent: 'space-between' }}>
        <strong>{threat ? `${r.attack_type} detected` : 'Normal traffic'}</strong>
        <span className="row">{threat && <SevBadge severity={r.severity} />}
          {r.injected_scenario && (r.correct ? <span className="badge st-mitigated"><CheckCircle2 size={11} /> matches injected “{r.injected_scenario}”</span> : <span className="badge st-open"><XCircle size={11} /> injected “{r.injected_scenario}”</span>)}</span>
      </div>
      <div className="muted" style={{ fontSize: '.82rem', marginTop: '.3rem' }}>
        {threat ? <>Risk {r.risk_score}/100 · confidence {pct(r.confidence, 0)} · detected by {r.sources.join(', ')}{r.blocked ? ' · source is on the blocklist' : ''}</> : <>No signature matched and the ML ensemble considers this benign.</>}
      </div>
      {r.explanation?.length > 0 && <div style={{ fontSize: '.82rem', marginTop: '.4rem' }}>Top factors: {r.explanation.slice(0, 3).map((x) => `${x.factor} (${pct(x.share, 0)})`).join(', ')}</div>}
      {r.alert_id && <button className="btn sm" style={{ marginTop: '.5rem' }} onClick={() => openAlert(r.alert_id)}>Open alert #{r.alert_id}</button>}
    </div>
  )
}

export default function Lab({ user, openAlert }) {
  const [q, setQ] = useState('')
  const [shopRes, setShopRes] = useState(null)
  const [labRes, setLabRes] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState('')
  if (!canAct(user, 'analyst')) return <><h1>Attack Lab</h1><div className="note warn">The Attack Lab requires the Analyst or Admin role.</div></>

  const search = async (text) => {
    setBusy('search'); setError('')
    try { setShopRes(await api.detectEvent({ payload_sample: `/search?q=${text}`, src_ip: '198.51.100.23', dst_ip: '10.0.0.10', protocol: 'TCP' })) } catch (e) { setError(e.message) }
    setBusy('')
  }
  const run = async (s) => {
    setBusy(s); setError('')
    try { setLabRes(await api.labSimulate(s)) } catch (e) { setError(e.message) }
    setBusy('')
  }

  return (
    <>
      <PageHead eyebrow="Analyse" title="Attack lab" subtitle={<>Safe, simulated attacks against a demo shop. Nothing is sent to a real system; every event goes through the real detection pipeline with <em>no label</em>. To attack a <b>real</b> website, use the Docker lab and connect it under Sources.</>} />
      <ErrorNote error={error} />
      <div className="grid g2">
        <Card title="1 · Type into the shop search (real payload inspection)">
          <div className="shop">
            <div className="shop-nav"><Box size={20} /><strong>TechMart</strong>
              <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search products…" onKeyDown={(e) => e.key === 'Enter' && search(q)} maxLength={500} aria-label="Shop search" />
              <button className="btn sm" onClick={() => search(q)} disabled={busy === 'search'} aria-label="Search"><Search size={14} /></button></div>
            <div className="hero"><h3>Gadgets at great prices</h3><span style={{ fontSize: '.8rem' }}>Try the examples below — the server inspects the text, not the browser.</span></div>
            <div className="products">{[1, 2, 3].map((i) => <div className="p" key={i}>Gadget Pro {i}<br />$199</div>)}</div>
          </div>
          <div className="row" style={{ margin: '.7rem 0' }}>{EXAMPLES.map((x) => <button key={x} className="chip" onClick={() => { setQ(x); search(x) }} title={x}>{x.length > 26 ? `${x.slice(0, 26)}…` : x}</button>)}</div>
          <Result r={shopRes} openAlert={openAlert} />
        </Card>
        <Card title="2 · Launch a simulated attack">
          <div className="scen">{SCENARIOS.map((s) => <button key={s} className="btn ghost sm" disabled={!!busy} onClick={() => run(s)}>{busy === s ? '…' : s}</button>)}</div>
          <div className="muted" style={{ fontSize: '.78rem', margin: '.7rem 0' }}>Each click generates one flow with the traffic profile of that attack (some are deliberately “stealthy”), analyses it, and tells you whether the platform recognised it. “Zero-Day” uses a traffic family the models were never trained on.</div>
          <Result r={labRes} openAlert={openAlert} />
        </Card>
      </div>
    </>
  )
}
