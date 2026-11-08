import React, { useEffect, useRef, useState } from 'react'
import { X } from 'lucide-react'
import { initials, roleLabel } from '../brand'

export const SEV_COLOR = { Critical: '#ef6a6a', High: '#f2994a', Medium: '#e6c35c', Low: '#8fbbd6' }
export const PALETTE = ['#d6a95a', '#8fbbd6', '#7fc29b', '#ef6a6a', '#c9b8a0', '#d98f7a', '#9bb0a4', '#e6c35c', '#6fa0a8', '#e0a0b4', '#b8a27a', '#a9c4d4']

export const fmtTime = (ts) => new Date(ts * 1000).toLocaleString()
export const fmtShort = (ts) => new Date(ts * 1000).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
export const pct = (v, d = 1) => (v === null || v === undefined ? '–' : `${(v * 100).toFixed(d)}%`)
export const num = (v) => (v === null || v === undefined ? '–' : Number(v).toLocaleString())
export const bytes = (n) => {
  if (n === null || n === undefined) return '–'
  const u = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0, v = Number(n)
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++ }
  return `${v.toFixed(i ? 1 : 0)} ${u[i]}`
}
export const canAct = (user, role) => ({ viewer: 1, analyst: 2, admin: 3 }[user?.role] >= { viewer: 1, analyst: 2, admin: 3 }[role])

// Fades and lifts content in as it scrolls into view (never hides anything where IntersectionObserver is unavailable).
export function Reveal({ as: Tag = 'div', delay = 0, className = '', style, children, ...rest }) {
  const ref = useRef(null)
  const [shown, setShown] = useState(typeof IntersectionObserver === 'undefined')
  useEffect(() => {
    if (shown) return undefined
    const el = ref.current
    if (!el) return undefined
    const io = new IntersectionObserver((entries) => { if (entries.some((e) => e.isIntersecting)) { setShown(true); io.disconnect() } }, { threshold: 0.05, rootMargin: '0px 0px -3% 0px' })
    io.observe(el)
    return () => io.disconnect()
  }, [shown])
  return <Tag ref={ref} className={`reveal ${shown ? 'in' : ''} ${className}`} style={{ '--d': `${delay}s`, ...style }} {...rest}>{children}</Tag>
}

export function useCountUp(target, duration = 900) {
  const [v, setV] = useState(target)
  useEffect(() => {
    const reduce = typeof window !== 'undefined' && window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches
    if (typeof target !== 'number' || !Number.isFinite(target) || typeof requestAnimationFrame === 'undefined' || reduce) { setV(target); return undefined }
    let raf, start = null
    const step = (t) => {
      if (start === null) start = t
      const p = Math.min(1, (t - start) / duration)
      setV(target * (1 - Math.pow(1 - p, 3)))
      if (p < 1) raf = requestAnimationFrame(step)
    }
    raf = requestAnimationFrame(step)
    return () => cancelAnimationFrame(raf)
  }, [target, duration])
  return v
}

export function PageHead({ eyebrow, title, subtitle, children }) {
  return (
    <header className="page-head">
      <div>
        {eyebrow && <div className="eyebrow">{eyebrow}</div>}
        <h1 className="page-title">{title}</h1>
        {subtitle && <p className="page-sub">{subtitle}</p>}
      </div>
      {children && <div className="head-actions">{children}</div>}
    </header>
  )
}

export function Card({ title, right, children, className = '', delay = 0 }) {
  return (
    <Reveal as="section" delay={delay} className={`card ${className}`}>
      {(title || right) && (
        <header className="card-head">
          <h3>{title}</h3>
          {right}
        </header>
      )}
      {children}
    </Reveal>
  )
}

// `count` (a number) animates up from zero; `value` is shown as given.
export function Stat({ label, value, count, icon: Icon, tone, sub, delay = 0, decimals = 0 }) {
  const n = useCountUp(count)
  const shown = count === undefined ? (value ?? '–') : (count === null || Number.isNaN(count) ? '–' : Number(decimals ? (typeof n === 'number' ? n : count).toFixed(decimals) : Math.round(typeof n === 'number' ? n : count)).toLocaleString())
  return (
    <Reveal delay={delay} className={`stat ${tone || ''}`}>
      <div className="stat-top"><span>{label}</span>{Icon && <i className="stat-ico"><Icon size={15} /></i>}</div>
      <div className="stat-value">{shown}</div>
      {sub && <div className="stat-sub">{sub}</div>}
    </Reveal>
  )
}

export const SevBadge = ({ severity }) => (severity ? <span className={`badge sev-${severity.toLowerCase()}`}>{severity}</span> : <span className="muted">–</span>)
export const StatusBadge = ({ status }) => <span className={`badge st-${status}`}>{status.replace('_', ' ')}</span>
export const Empty = ({ children }) => <div className="empty">{children}</div>
export const ErrorNote = ({ error }) => (error ? <div className="note error" role="alert">{error}</div> : null)
export const Spinner = ({ label = 'Loading…' }) => <div className="skeleton" role="status" aria-label={label}><i /><i /><i /></div>

export function Tabs({ tabs, value, onChange }) {
  return (
    <div className="tabs" role="tablist">
      {tabs.map((t) => (
        <button key={t.id} role="tab" aria-selected={value === t.id} className={value === t.id ? 'active' : ''} onClick={() => onChange(t.id)}>{t.label}</button>
      ))}
    </div>
  )
}

export function Bar({ value, color = 'var(--accent)' }) {
  return <div className="bar"><div style={{ width: `${Math.max(0, Math.min(100, value * 100))}%`, background: color }} /></div>
}

export const RoleBadge = ({ role }) => <span className={`badge role-${role}`}>{roleLabel(role)}</span>
export const Avatar = ({ user, large }) => <span className={`avatar ${large ? 'lg' : ''}`} aria-hidden="true">{initials(user)}</span>
export const SimChip = () => <span className="sim-chip" title="Traffic is generated by the built-in simulator. Switch it off in Admin > Settings.">SIMULATED DEMO FEED</span>

// Live password-rule checklist + strength meter (mirrors the server policy in backend/app/security/passwords.py).
export function passwordRules(pw, username = '') {
  return [
    { ok: pw.length >= 10, label: 'At least 10 characters' },
    { ok: /[a-z]/.test(pw) && /[A-Z]/.test(pw), label: 'Upper and lower case letters' },
    { ok: /\d/.test(pw), label: 'At least one digit' },
    { ok: !(username && username.length >= 3 && pw.toLowerCase().includes(username.toLowerCase())), label: 'Does not contain your username' },
  ]
}
export function PasswordHelp({ password, username }) {
  const rules = passwordRules(password, username)
  const total = rules.filter((r) => r.ok).length + (password.length >= 14 ? 1 : 0)  // 0..5
  const level = !password ? 0 : total <= 1 ? 1 : total === 2 ? 2 : total <= 4 ? 3 : 4
  return (
    <div style={{ display: 'grid', gap: '.5rem' }}>
      <div className={`strength s${level}`} aria-label="Password strength"><i /><i /><i /><i /></div>
      <ul className="checklist">{rules.map((r) => <li key={r.label} className={r.ok ? 'ok' : ''}>{r.ok ? '✓' : '○'} {r.label}</li>)}</ul>
    </div>
  )
}

// ---- shared helpers for the connector features ------------------------------------------------------------------
export function relTime(ts) {
  if (!ts) return 'never'
  const s = Math.max(0, Date.now() / 1000 - ts)
  if (s < 10) return 'just now'
  if (s < 60) return `${Math.floor(s)} s ago`
  if (s < 3600) return `${Math.floor(s / 60)} min ago`
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`
  return `${Math.floor(s / 86400)} d ago`
}

// Sources that pseudonymise IPs live in 100.64.0.0/10 (see collector README).
export const isPseudonymised = (ip) => /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(ip || '')

export function Modal({ title, onClose, children, wide }) {
  useEffect(() => {
    const k = (e) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', k)
    return () => window.removeEventListener('keydown', k)
  }, [onClose])
  return (
    <div className="modal-bg" onMouseDown={onClose}>
      <div className={`modal ${wide ? 'wide' : ''}`} role="dialog" aria-modal="true" aria-label={title} onMouseDown={(e) => e.stopPropagation()}>
        <div className="modal-head"><h3>{title}</h3><button className="icon-btn" onClick={onClose} aria-label="Close"><X size={15} /></button></div>
        {children}
      </div>
    </div>
  )
}

export const SCOPES = [
  { id: 'auto', label: 'Auto', hint: 'Live data when a real source is connected, otherwise everything' },
  { id: 'live', label: 'Live', hint: 'Only events from connected real sources' },
  { id: 'demo', label: 'Demo', hint: 'Only simulated demo traffic' },
  { id: 'upload', label: 'Uploads', hint: 'Only uploaded datasets' },
  { id: 'all', label: 'All', hint: 'Everything, real and simulated' },
]
export const resolveScope = (pref, mode) => (pref === 'auto' ? (mode === 'live' ? 'live' : 'all') : pref)

export function ScopeSwitch({ value, onChange, mode, exclude = [] }) {
  return (
    <div className="seg" role="group" aria-label="Data shown">
      {SCOPES.filter((s) => !exclude.includes(s.id)).map((s) => (
        <button key={s.id} className={value === s.id ? 'on' : ''} onClick={() => onChange(s.id)} title={s.hint}>
          {s.label}{s.id === 'auto' ? ` (${resolveScope('auto', mode)})` : ''}
        </button>))}
    </div>
  )
}
