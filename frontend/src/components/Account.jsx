import React, { useEffect, useState } from 'react'
import { KeyRound, LogOut, Moon, ShieldCheck, Sun, Trash2 } from 'lucide-react'
import { api } from '../api'
import { roleLabel } from '../brand'
import { useTheme } from '../theme'
import { useConfirm, useToast } from '../feedback'
import { Avatar, Card, ErrorNote, PageHead, PasswordHelp, RoleBadge, fmtTime, passwordRules } from './ui'
import GoogleSignInButton from './GoogleSignInButton'

const ROLE_INFO = {
  viewer: 'Read-only: dashboards, alerts, model metrics, reports and the assistant.',
  analyst: 'Everything a Viewer can do, plus uploading datasets, triaging alerts and applying (simulated) mitigations.',
  admin: 'Everything an Analyst can do, plus user management, model retraining, settings and the audit log.',
}

export default function Account({ user, onSession, onLogout, onAccountDeleted }) {
  const { theme, toggle } = useTheme()
  const toast = useToast()
  const confirm = useConfirm()
  const [profile, setProfile] = useState(user)
  useEffect(() => { api.me().then(setProfile).catch(() => {}) }, [])
  const [authConfig, setAuthConfig] = useState(null)
  const [googleIdentity, setGoogleIdentity] = useState(null)
  const [googleError, setGoogleError] = useState('')
  useEffect(() => {
    api.authConfig().then(setAuthConfig).catch(() => {})
    api.googleIdentity().then(setGoogleIdentity).catch(() => {})
  }, [])
  const [cur, setCur] = useState('')
  const [pw, setPw] = useState('')
  const [pw2, setPw2] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [deleteError, setDeleteError] = useState('')
  const [deleting, setDeleting] = useState(false)
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

  const linkGoogle = async (credential) => {
    setGoogleError('')
    try {
      const result = await api.linkGoogle(credential)
      setGoogleIdentity({ linked: true, email: result.email })
      toast('Google sign-in linked to this account.')
    } catch (err) { setGoogleError(err.message) }
  }

  const deleteOwnerAccount = async () => {
    setDeleteError('')
    setDeleting(true)
    try {
      const { users } = await api.users()
      const successor = users.find((member) => member.id !== user.id && member.role === 'admin' && member.is_active)
      if (!successor) {
        setDeleteError('Promote another active Admin before deleting your account. That Admin will become the workspace owner.')
        setDeleting(false)
        return
      }
      const first = await confirm({
        title: 'Delete your owner account?', danger: true, confirmLabel: 'Continue',
        body: 'Your account will be permanently deleted. Workspace data and other users will remain.'
      })
      if (!first.ok) { setDeleting(false); return }
      const second = await confirm({
        title: 'Confirm account deletion', danger: true, confirmLabel: 'Delete my account',
        body: `${successor.full_name || successor.username} will become the workspace owner. You will be signed out and cannot recover this account.`
      })
      if (!second.ok) { setDeleting(false); return }
      await api.deleteAccount()
      toast('Owner account deleted. Workspace ownership transferred.')
      onAccountDeleted()
    } catch (err) {
      setDeleteError(err.message)
      setDeleting(false)
    }
  }

  return (
    <>
      <PageHead eyebrow="Account" title="My account" subtitle="Your profile, appearance and password." />
      <div className="grid g2">
        <Card title="Profile">
          <div className="row" style={{ gap: '1rem', marginBottom: '1rem' }}>
            <Avatar user={user} large />
            <div><h2>{user.full_name || user.username}</h2><div className="muted mono">{user.username}</div><div style={{ marginTop: '.3rem' }}><RoleBadge role={user.is_workspace_owner ? 'owner' : user.role} /></div></div>
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
          {user.is_workspace_owner && <div className="owner-delete-section">
            <h3>Delete owner account</h3>
            <p className="auth-note">This deletes your account but keeps workspace data and users. An active Admin must be available to take ownership.</p>
            <ErrorNote error={deleteError} />
            <button className="btn danger sm" type="button" disabled={deleting} onClick={deleteOwnerAccount}><Trash2 size={14} /> {deleting ? 'Checking workspace…' : 'Delete my account'}</button>
          </div>}
          {user.is_workspace_owner ? <div className="google-link-section">
            <h3>Google sign-in</h3>
            {googleIdentity?.linked
              ? <p className="auth-note">Connected as <b>{googleIdentity.email}</b>. You can use this Google account the next time you sign in.</p>
              : <>
                <p className="auth-note">Link your Google account to sign in to this existing workspace account.</p>
                {authConfig?.google_client_id && <GoogleSignInButton clientId={authConfig.google_client_id} theme={theme} onCredential={linkGoogle} onError={(err) => setGoogleError(err.message)} />}
                {!authConfig?.google_client_id && authConfig && <p className="auth-note">Google sign-in has not been configured by the server administrator.</p>}
                {googleError && <ErrorNote error={googleError} />}
              </>}
          </div> : <div className="google-link-section"><h3>Google sign-in</h3><p className="auth-note">Google sign-in is reserved for the workspace owner. Use the username and password provided by your Admin.</p></div>}
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
