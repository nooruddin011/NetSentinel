import React, { useCallback, useEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { Activity, BellRing, Brain, ChevronDown, ChevronUp, Lock, LogOut, Moon, Plug, Settings, Sun, Upload as UploadIcon } from 'lucide-react'
import { api, getToken, onUnauthorized, setToken } from './api'
import { BRAND, roleLabel } from './brand'
import { useTheme } from './theme'
import useLiveFeed from './hooks/useLiveFeed'
import Login from './components/Login'
import Logo from './components/Logo'
import Overview from './components/Overview'
import Alerts from './components/Alerts'
import Models from './components/Models'
import Sources from './components/Sources'
import Upload from './components/Upload'
import Admin from './components/Admin'
import Account from './components/Account'
import Chatbot from './components/Chatbot'
import ErrorBoundary from './components/ErrorBoundary'
import { Avatar, RoleBadge, Spinner, canAct, resolveScope } from './components/ui'

const GROUPS = [
  { label: 'Monitor', items: [
    { id: 'overview', label: 'Overview', icon: Activity, role: 'viewer' },
    { id: 'alerts', label: 'Alerts', icon: BellRing, role: 'viewer' },
    { id: 'sources', label: 'Sources', icon: Plug, role: 'viewer' }] },
  { label: 'Analyse', items: [
    { id: 'models', label: 'Models', icon: Brain, role: 'viewer' },
    { id: 'upload', label: 'Upload & Analyse', icon: UploadIcon, role: 'analyst' }] },
  { label: 'Manage', items: [{ id: 'admin', label: 'Admin', icon: Settings, role: 'admin' }] },
]
const STATUS_TEXT = { live: 'Live', connecting: 'Connecting…', reconnecting: 'Reconnecting…', unauthorised: 'Not authorised' }

function NavAccessHint({ label, Icon, message }) {
  const anchor = useRef(null)
  const [position, setPosition] = useState(null)
  const updatePosition = useCallback(() => {
    const rect = anchor.current?.getBoundingClientRect()
    if (!rect) return
    setPosition({
      left: Math.min(rect.right + 10, Math.max(10, window.innerWidth - 222)),
      top: Math.min(Math.max(rect.top + rect.height / 2, 36), window.innerHeight - 36),
    })
  }, [])
  useEffect(() => {
    if (!position) return undefined
    window.addEventListener('scroll', updatePosition, true)
    window.addEventListener('resize', updatePosition)
    return () => {
      window.removeEventListener('scroll', updatePosition, true)
      window.removeEventListener('resize', updatePosition)
    }
  }, [position, updatePosition])

  return (
    <span ref={anchor} className="nav-hint-wrap" onMouseEnter={updatePosition} onMouseLeave={() => setPosition(null)}>
      <button data-nav-id="upload" className="nav locked" aria-label={`${label}. ${message}`} disabled>
        <Icon size={17} /> <span className="nav-label">{label}</span>
      </button>
      {position && createPortal(
        <span className="nav-hint is-visible" role="tooltip" style={position}>{message}</span>,
        document.body,
      )}
    </span>
  )
}

function Console({ user, onLogout, onSession }) {
  const { theme, toggle } = useTheme()
  const [view, setView] = useState('overview')
  const [mobileNavOpen, setMobileNavOpen] = useState(false)
  const [focusAlert, setFocusAlert] = useState(null)
  const [train, setTrain] = useState(null)
  const [cov, setCov] = useState(null)               // coverage + Demo/Live mode, refreshed regularly
  const [scopePref, setScopePref] = useState('auto') // which data the dashboards show: auto | live | demo | upload | all
  const live = useLiveFeed(true)
  const mode = cov?.mode || 'demo'
  const scope = resolveScope(scopePref, mode)
  const activeSection = GROUPS.find((group) => group.items.some((item) => item.id === view))?.label || 'Account'
  const openAlert = useCallback((id) => { setFocusAlert(id); setView('alerts') }, [])
  const dot = live.status === 'live' ? 'live' : live.status === 'unauthorised' ? 'bad' : ''
  const feedLabel = live.status === 'live' ? 'Feed connected' : STATUS_TEXT[live.status] || live.status
  const training = train?.state === 'running'
  useEffect(() => { setMobileNavOpen(false) }, [view])
  useEffect(() => {
    if (!mobileNavOpen) return undefined
    const closeOnEscape = (event) => { if (event.key === 'Escape') setMobileNavOpen(false) }
    window.addEventListener('keydown', closeOnEscape)
    return () => window.removeEventListener('keydown', closeOnEscape)
  }, [mobileNavOpen])
  useEffect(() => { window.scrollTo({ top: 0, behavior: 'auto' }) }, [view])  // every page opens at the top
  // A single passive scroll listener drives the console's layered background parallax.
  useEffect(() => {
    const shell = document.querySelector('.shell')
    if (!shell) return undefined
    const reduce = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches
    if (reduce) return undefined
    let frame = 0
    const paint = () => {
      frame = 0
      const shift = Math.min(window.scrollY * 0.08, 110)
      shell.style.setProperty('--parallax-grid', `${(-shift * 0.28).toFixed(1)}px`)
      shell.style.setProperty('--parallax-glow', `${(-shift * 0.72).toFixed(1)}px`)
    }
    const onScroll = () => { if (!frame) frame = window.requestAnimationFrame(paint) }
    window.addEventListener('scroll', onScroll, { passive: true })
    window.addEventListener('resize', onScroll, { passive: true })
    onScroll()
    return () => { window.removeEventListener('scroll', onScroll); window.removeEventListener('resize', onScroll); if (frame) window.cancelAnimationFrame(frame) }
  }, [])
  // Pointer lighting is delegated so newly rendered cards and tabs participate automatically.
  useEffect(() => {
    const shell = document.querySelector('.shell')
    if (!shell || window.matchMedia?.('(prefers-reduced-motion: reduce)').matches) return undefined
    let active = null, frame = 0, latest = null
    const clear = () => {
      active?.style.removeProperty('--pointer-x'); active?.style.removeProperty('--pointer-y'); active = null
    }
    const onMove = (event) => {
      latest = event
      if (frame) return
      frame = window.requestAnimationFrame(() => {
        frame = 0
        const panel = latest.target.closest?.('.card, .src-card')
        if (!panel || !shell.contains(panel)) { clear(); return }
        if (active !== panel) clear()
        active = panel
        const rect = panel.getBoundingClientRect()
        panel.style.setProperty('--pointer-x', `${latest.clientX - rect.left}px`)
        panel.style.setProperty('--pointer-y', `${latest.clientY - rect.top}px`)
      })
    }
    const onLeave = (event) => { if (!shell.contains(event.relatedTarget)) clear() }
    shell.addEventListener('pointermove', onMove, { passive: true })
    shell.addEventListener('pointerleave', onLeave)
    return () => { shell.removeEventListener('pointermove', onMove); shell.removeEventListener('pointerleave', onLeave); if (frame) window.cancelAnimationFrame(frame); clear() }
  }, [])
  const reloadCov = useCallback(async () => { try { setCov(await api.coverage()) } catch { /* transient */ } }, [])
  useEffect(() => { reloadCov(); const id = setInterval(reloadCov, 10000); return () => clearInterval(id) }, [reloadCov])
  const scopeProps = { scope, scopePref, setScopePref, mode, cov }

  // Training status is tracked here (not inside the Models page) so progress survives switching tabs.
  const mounted = useRef(true)
  useEffect(() => {
    mounted.current = true
    let timer
    const tick = async () => {
      try { const s = await api.retrainStatus(); if (mounted.current) setTrain(s) } catch { /* transient */ }
      if (mounted.current) timer = setTimeout(tick, 3000)
    }
    tick()
    return () => { mounted.current = false; clearTimeout(timer) }
  }, [])

  return (
    <div className="shell">
      <nav id="argus-mobile-nav" className={`sidebar ${mobileNavOpen ? 'mobile-open' : ''}`} aria-label="Main">
        <div className="brand"><Logo size={36} /><span>{BRAND.name}<small>Threat intelligence</small></span></div>
        {GROUPS.map((g) => {
          // Keep privileged destinations out of the navigation for users who cannot access them.
          // Analyst-only tools remain visible so viewers can discover the feature and how to request access.
          const items = g.items.filter((item) => item.id !== 'admin' || canAct(user, 'admin'))
          if (!items.length) return null
          return (
          <div className="nav-section" key={g.label}>
            <div className="nav-group">{g.label}</div>
            {items.map((n) => {
              const allowed = canAct(user, n.role)
              const accessHint = n.id === 'upload'
                ? 'Contact an Admin to request Analyst access.'
                : `${n.label} requires the ${roleLabel(n.role)} role (you are signed in as ${roleLabel(user.role)})`
              return (
                n.id === 'upload' && !allowed ? (
                  <NavAccessHint key={n.id} label={n.label} Icon={n.icon} message={accessHint} />
                ) : (
                  <button key={n.id} data-nav-id={n.id} className={`nav ${view === n.id ? 'active' : ''} ${allowed ? '' : 'locked'}`} aria-label={n.label} aria-current={view === n.id ? 'page' : undefined} disabled={!allowed}
                    title={allowed ? n.label : accessHint} onClick={() => { setView(n.id); setMobileNavOpen(false) }}>
                    <n.icon size={17} /> <span className="nav-label">{n.label}</span>
                    {!allowed && <Lock size={12} className="lock" />}
                    {n.id === 'models' && training && <span className="pulse" title="Model training in progress" />}
                  </button>
                ))
            })}
          </div>
          )
        })}
        <button className="mobile-nav-more" onClick={() => setMobileNavOpen((open) => !open)} aria-label={mobileNavOpen ? 'Close navigation menu' : 'Open more navigation options'} aria-expanded={mobileNavOpen} aria-controls="argus-mobile-nav">
          {mobileNavOpen ? <><span>Close menu</span><ChevronDown size={16} /></> : <><span>More</span><ChevronUp size={16} /></>}
        </button>
        <div className="side-foot">
          <div className="account-controls">
            <button className="user-card" onClick={() => { setView('account'); setMobileNavOpen(false) }} title="Open your account" aria-label="Open your account">
              <Avatar user={user} />
              <span className="who"><b>{user.full_name || user.username}</b><RoleBadge role={user.role} /></span>
            </button>
            <div className="foot-actions">
              <button className="icon-btn" onClick={toggle} aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`} title="Toggle theme">{theme === 'dark' ? <Sun size={15} /> : <Moon size={15} />}</button>
              <button className="btn ghost sm" onClick={() => onLogout()}><LogOut size={14} /> Sign out</button>
            </div>
          </div>
        </div>
      </nav>
      <main className="main">
        <header className="console-topbar" aria-label="Console status">
          <div className="console-context">
            <span className="console-mark" aria-hidden="true" />
            <span>ARGUS</span>
            <span className="console-context-separator">/</span>
            <span>{activeSection}</span>
          </div>
          <div className={`console-feed ${live.status === 'live' ? 'is-connected' : ''}`}>
            <span className={`dot ${dot}`} />
            <span>{feedLabel}</span>
            <span className="console-feed-separator" />
            <span className="console-mode">{mode === 'live' ? 'Live data' : 'Demo data'}</span>
          </div>
        </header>
        <ErrorBoundary resetKey={view}>
          <div className="page" data-view={view} key={view}>
          {view === 'overview' && <Overview user={user} live={live} openAlert={openAlert} goTo={setView} {...scopeProps} />}
          {view === 'alerts' && <Alerts user={user} focusId={focusAlert} clearFocus={() => setFocusAlert(null)} {...scopeProps} />}
          {view === 'sources' && <Sources user={user} cov={cov} reloadCov={reloadCov} goTo={setView} />}
          {view === 'models' && <Models user={user} train={train} setTrain={setTrain} />}
          {view === 'upload' && <Upload user={user} />}
          {view === 'admin' && canAct(user, 'admin') && <Admin user={user} />}
          {view === 'account' && <Account user={user} onSession={onSession} onLogout={onLogout} />}
          </div>
        </ErrorBoundary>
      </main>
      <Chatbot />
    </div>
  )
}

export default function App() {
  const [user, setUser] = useState(null)
  const [checking, setChecking] = useState(!!getToken())
  const [notice, setNotice] = useState('')

  const logout = useCallback((reason) => {
    setToken(null); setUser(null)
    setNotice(typeof reason === 'string' ? reason : '')
  }, [])
  useEffect(() => { onUnauthorized((msg) => logout(msg || 'Your session has ended. Please sign in again.')) }, [logout])
  useEffect(() => {
    if (!getToken()) return
    api.me().then(setUser).catch(() => setToken(null)).finally(() => setChecking(false))
  }, [])

  const startSession = useCallback((res) => { setToken(res.access_token); setUser(res.user); setNotice('') }, [])

  if (checking) return <Spinner label="Restoring session…" />
  if (!user) return <Login onLogin={startSession} notice={notice} />
  return <Console user={user} onLogout={logout} onSession={startSession} />
}
