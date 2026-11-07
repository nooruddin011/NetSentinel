import React, { useEffect, useState } from 'react'
import { KeyRound, LogOut, Moon, ShieldCheck, Sun } from 'lucide-react'
import { api } from '../api'
import { roleLabel } from '../brand'
import { useTheme } from '../theme'
import { useToast } from '../feedback'
import { Avatar, Card, ErrorNote, PageHead, PasswordHelp, RoleBadge, fmtTime, passwordRules } from './ui'

const ROLE_INFO = {
  viewer: 'Read-only: dashboards, alerts, model metrics, reports and the assistant.',
  analyst: 'Everything a Viewer can do, plus uploading datasets, the Attack Lab, triaging alerts and applying (simulated) mitigations.',
  admin: 'Everything an Analyst can do, plus user management, model retraining, settings and the audit log.',
}

export default function Account({ user, onSession, onLogout }) {
  const { theme, toggle } = useTheme()
  const toast = useToast()
  const [profile, setProfile] = useState(user)
  useEffect(() => { api.me().then(setProfile).catch(() => {}) }, [])
  const [cur, setCur] = useState('')
  const [pw, setPw] = useState('')
  const [pw2, setPw2] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const ok = passwordRules(pw, user.username).every((r) => r.ok) && pw === pw2 && cur && pw !== cur

  const submit = async (e) => {
    e.preventDefault()
    if (!ok) return
    setBusy(true); setError('')
    try {
      const res = await api.changePassword(cur, pw)
      onSession(res) // the server issued a fresh token: older sessions are invalidated
      setCur(''); setPw(''); setPw2('')
      toast('Password changed. Other devices have been signed out.')
    } catch (err) { setError(err.message) }
    setBusy(false)
  }

  return (
    <>
      <PageHead eyebrow="Account" title="My account" subtitle="Your profile, appearance and password." />
      <div className="grid g2">
        <Card title="Profile">
          <div className="row" style={{ gap: '1rem', marginBottom: '1rem' }}>
            <Avatar user={user} large />
            <div><h2>{user.full_name || user.username}</h2><div className="muted mono">{user.username}</div><div style={{ marginTop: '.3rem' }}><RoleBadge role={user.role} /></div></div>
          </div>
          <div className="note info" style={{ display: 'flex', gap: '.5rem' }}><ShieldCheck size={16} style={{ flex: 'none', marginTop: 2 }} /><span><b>{roleLabel(user.role)}.</b> {ROLE_INFO[user.role]}</span></div>
          <dl className="kv" style={{ marginTop: '.8rem' }}>
            <dt>Last sign-in</dt><dd>{profile.last_login ? fmtTime(profile.last_login) : 'This is your first session'}</dd>
            <dt>Member since</dt><dd>{profile.created_at ? fmtTime(profile.created_at) : '–'}</dd>
          </dl>
          <div className="row" style={{ marginTop: '1rem' }}>
            <button className="btn ghost sm" onClick={toggle}>{theme === 'dark' ? <Sun size={14} /> : <Moon size={14} />} {theme === 'dark' ? 'Light' : 'Dark'} theme</button>
            <button className="btn ghost sm" onClick={() => onLogout()}><LogOut size={14} /> Sign out</button>
          </div>
        </Card>
        <Card title="Change password">
          <form className="grid" onSubmit={submit}>
            <label className="field">Current password<input type="password" value={cur} onChange={(e) => setCur(e.target.value)} autoComplete="current-password" /></label>
            <label className="field">New password<input type="password" value={pw} onChange={(e) => setPw(e.target.value)} autoComplete="new-password" /></label>
            <PasswordHelp password={pw} username={user.username} />
            <label className="field">Confirm new password<input type="password" value={pw2} onChange={(e) => setPw2(e.target.value)} autoComplete="new-password" /></label>
            {pw2 && pw !== pw2 && <div className="muted" style={{ color: 'var(--danger)', fontSize: '.8rem' }}>Passwords do not match.</div>}
            <ErrorNote error={error} />
            <button className="btn" disabled={!ok || busy}><KeyRound size={15} /> {busy ? 'Saving…' : 'Update password'}</button>
          </form>
        </Card>
      </div>
    </>
  )
}
