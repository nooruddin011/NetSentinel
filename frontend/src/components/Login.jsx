import React, { useEffect, useMemo, useRef, useState } from 'react'
import { AlertTriangle, ArrowDown, ChevronDown, Eye, EyeOff, KeyRound, Lock, LogIn, Moon, Sun, User, UserPlus, X } from 'lucide-react'
import { api } from '../api'
import { BRAND } from '../brand'
import { useTheme } from '../theme'
import Logo from './Logo'
import FaqAccordion from './FaqAccordion'
import ImageScatter from './ImageScatter'
import LoginFeatureGrid from './LoginFeatureGrid'
import { PasswordHelp, passwordRules } from './ui'

function Field({ icon: Icon, label, children, trail }) {
  return (
    <label className="field">{label}
      <span className="input-wrap">{Icon && <Icon size={16} className="lead" />}{children}{trail}</span>
    </label>
  )
}

export default function Login({ onLogin, notice }) {
  const { theme, toggle } = useTheme()
  const [mode, setMode] = useState('signin')
  const [cfg, setCfg] = useState({ registration_enabled: true })
  const [username, setUsername] = useState('')
  const [fullName, setFullName] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [show, setShow] = useState(false)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const [authOpen, setAuthOpen] = useState(false)
  const [platformOpen, setPlatformOpen] = useState(false)
  const headerRef = useRef(null)
  const authTriggerRef = useRef(null)

  useEffect(() => { api.authConfig().then(setCfg).catch(() => {}) }, [])
  useEffect(() => { setError(null) }, [mode])
  useEffect(() => {
    if (notice) {
      setMode('signin')
      setAuthOpen(true)
    }
  }, [notice])
  useEffect(() => {
    const onPointerDown = (event) => {
      if (!headerRef.current?.contains(event.target)) {
        setAuthOpen(false)
        setPlatformOpen(false)
      }
    }
    const onKeyDown = (event) => {
      if (event.key !== 'Escape') return
      setAuthOpen(false)
      setPlatformOpen(false)
      authTriggerRef.current?.focus()
    }
    document.addEventListener('pointerdown', onPointerDown)
    document.addEventListener('keydown', onKeyDown)
    return () => {
      document.removeEventListener('pointerdown', onPointerDown)
      document.removeEventListener('keydown', onKeyDown)
    }
  }, [])

  const registering = mode === 'register'
  const rulesOk = useMemo(() => passwordRules(password, username).every((r) => r.ok), [password, username])
  const usernameOk = /^[A-Za-z0-9_.@-]{3,64}$/.test(username.trim())
  const canSubmit = registering ? usernameOk && rulesOk && password === confirm && !busy : username.trim() && password && !busy

  const openAuth = (nextMode, event) => {
    authTriggerRef.current = event.currentTarget
    setMode(nextMode)
    setError(null)
    setAuthOpen(true)
    setPlatformOpen(false)
  }

  const submit = async (e) => {
    e.preventDefault()
    if (!canSubmit) return
    setBusy(true); setError(null)
    try {
      const res = registering ? await api.register(username.trim(), password, fullName.trim()) : await api.login(username.trim(), password)
      onLogin(res)
    } catch (err) {
      setError({ text: err.message, kind: err.status === 403 && !registering ? 'blocked' : 'error' })
      setBusy(false)
    }
  }

  const eye = (
    <button type="button" className="trail" onClick={() => setShow(!show)} aria-label={show ? 'Hide password' : 'Show password'}>
      {show ? <EyeOff size={16} /> : <Eye size={16} />}
    </button>
  )

  return (
    <div className="auth landing">
      <header className="landing-nav" ref={headerRef}>
        <div className="landing-nav-inner">
          <a className="landing-brand" href="#landing-home" aria-label={`${BRAND.name} home`}>
            <Logo size={31} /><span>{BRAND.name}</span>
          </a>

          <div className="landing-nav-center">
            <button
              className={`landing-platform-trigger${platformOpen ? ' is-open' : ''}`}
              type="button"
              aria-expanded={platformOpen}
              aria-controls="platform-menu"
              onClick={() => { setPlatformOpen(true); setAuthOpen(false) }}
              onMouseEnter={() => setPlatformOpen(true)}
            >
              Platform <ChevronDown size={15} />
            </button>
            <div className="platform-menu" id="platform-menu" hidden={!platformOpen}>
                <a href="#auth-features" onClick={() => setPlatformOpen(false)}>
                  <span className="platform-menu-index">01</span>
                  <span><b>Explore the platform</b><small>Detection, sources, privacy, and response</small></span>
                </a>
                <a href="#auth-faq" onClick={() => setPlatformOpen(false)}>
                  <span className="platform-menu-index">02</span>
                  <span><b>Frequently asked questions</b><small>Clear answers about capabilities and limits</small></span>
                </a>
            </div>
          </div>

          <div className="landing-nav-actions">
            <button className="icon-btn landing-theme" onClick={toggle} aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`} title="Toggle theme">
              {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
            </button>
            <button className="landing-signin" type="button" onClick={(event) => openAuth('signin', event)}>
              Sign in
            </button>
            {cfg.registration_enabled && (
              <button className="btn landing-create" type="button" onClick={(event) => openAuth('register', event)}>
                Create account
              </button>
            )}
          </div>

          {authOpen && (
            <div className="auth-popover" role="dialog" aria-modal="false" aria-labelledby="auth-popover-title">
              <div className="auth-popover-heading">
                <div>
                  <p className="auth-popover-eyebrow">{registering ? 'Join the workspace' : 'Secure access'}</p>
                  <h2 id="auth-popover-title">{registering ? 'Create your account' : 'Welcome back'}</h2>
                </div>
                <button className="icon-btn" type="button" onClick={() => setAuthOpen(false)} aria-label="Close sign-in panel"><X size={17} /></button>
              </div>
              <p className="sub">{registering ? 'New accounts start with read-only Viewer access.' : `Sign in to your ${BRAND.name} console.`}</p>

              {cfg.registration_enabled && (
                <div className="auth-tabs" role="tablist" data-pos={registering ? 1 : 0}>
                  <span className="slider" aria-hidden="true" />
                  <button type="button" role="tab" aria-selected={!registering} className={!registering ? 'on' : ''} onClick={() => setMode('signin')}><LogIn size={15} /> Sign in</button>
                  <button type="button" role="tab" aria-selected={registering} className={registering ? 'on' : ''} onClick={() => setMode('register')}><UserPlus size={15} /> Create account</button>
                </div>
              )}

              {notice && !error && <div className="alert-box info" role="status"><AlertTriangle size={16} /> <span>{notice}</span></div>}
              {error && (
                <div className={`alert-box ${error.kind}`} role="alert">
                  {error.kind === 'blocked' ? <Lock size={16} /> : <AlertTriangle size={16} />}
                  <span>{error.kind === 'blocked' && <b style={{ display: 'block' }}>Account disabled</b>}{error.text}</span>
                </div>
              )}

              <form className="auth-form" onSubmit={submit} noValidate>
                {registering && <Field icon={User} label="Full name (optional)"><input value={fullName} onChange={(e) => setFullName(e.target.value)} placeholder="e.g. Maria Lopez" autoComplete="name" maxLength={64} /></Field>}
                <Field icon={User} label="Username"><input autoFocus value={username} onChange={(e) => setUsername(e.target.value)} placeholder={registering ? 'Pick a username (no spaces)' : 'Your username'} autoComplete="username" maxLength={64} /></Field>
                {registering && username && !usernameOk && <div className="auth-note" style={{ textAlign: 'left', color: 'var(--danger)' }}>Use 3–64 characters: letters, digits and _ . - @ (no spaces).</div>}
                <Field icon={KeyRound} label="Password" trail={eye}>
                  <input type={show ? 'text' : 'password'} value={password} onChange={(e) => setPassword(e.target.value)} placeholder={registering ? 'Create a strong password' : 'Your password'} autoComplete={registering ? 'new-password' : 'current-password'} maxLength={256} />
                </Field>
                {registering && (
                  <>
                    <PasswordHelp password={password} username={username} />
                    <Field icon={KeyRound} label="Confirm password"><input type={show ? 'text' : 'password'} value={confirm} onChange={(e) => setConfirm(e.target.value)} placeholder="Repeat the password" autoComplete="new-password" maxLength={256} /></Field>
                    {confirm && password !== confirm && <div className="auth-note" style={{ textAlign: 'left', color: 'var(--danger)' }}>Passwords do not match.</div>}
                  </>
                )}
                <button className="btn block" disabled={!canSubmit}>{busy ? 'Please wait…' : registering ? 'Create account' : 'Sign in'}</button>
              </form>

              {registering
                ? <p className="auth-note">An <b>Admin</b> can upgrade your access to <b>Analyst</b>.</p>
                : !cfg.registration_enabled && <p className="auth-note">Accounts are created by an Admin. Contact your administrator for access.</p>}
            </div>
          )}
        </div>
      </header>

      <main className="landing-main">
        <section className="landing-hero" id="landing-home" aria-labelledby="landing-title">
          <ImageScatter />
          <div className="landing-hero-copy">
            <p className="landing-eyebrow"><span /> Threat detection &amp; monitoring</p>
            <h1 id="landing-title">See the signal.<br /><span>Understand the threat.</span></h1>
            <p className="landing-lead">A clear console for reviewing web access-log events, analyzing uploaded flow data, and understanding why activity was flagged.</p>
            <button className="landing-hero-cta" type="button" onClick={(event) => openAuth('signin', event)}>
              Sign in to your dashboard <ArrowDown size={15} />
            </button>
            <p className="landing-hero-note">Illustrations are decorative. No live system data is shown here.</p>
          </div>
        </section>
        <LoginFeatureGrid />
        <FaqAccordion />
      </main>
    </div>
  )
}
