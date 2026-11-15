import React, { useEffect, useRef, useState } from 'react'
import { Check, ImagePlus, KeyRound, LogOut, MessageSquareText, Pencil, ShieldCheck, Trash2, X } from 'lucide-react'
import { api } from '../api'
import { roleLabel } from '../brand'
import { useTheme } from '../theme'
import { useConfirm, useToast } from '../feedback'
import { Avatar, Card, ErrorNote, Modal, PageHead, PasswordHelp, RoleBadge, fmtTime, passwordRules } from './ui'
import GoogleSignInButton from './GoogleSignInButton'
import { FilterSelect } from './Alerts'

const ROLE_INFO = {
  viewer: 'Read-only: dashboards, alerts, model metrics, reports and the assistant.',
  analyst: 'Everything a Viewer can do, plus uploading datasets, triaging alerts and applying (simulated) mitigations.',
  admin: 'Everything an Analyst can do, plus user management, model retraining, settings and the audit log.',
}

export default function Account({ user, onSession, onLogout, onAccountDeleted, onProfileUpdate }) {
  const { theme } = useTheme()
  const toast = useToast()
  const confirm = useConfirm()
  const [profile, setProfile] = useState(user)
  useEffect(() => { setProfile(user) }, [user])
  useEffect(() => { api.me().then((me) => { setProfile(me); onProfileUpdate(me) }).catch(() => {}) }, [onProfileUpdate])
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
  const [requestMessage, setRequestMessage] = useState('')
  const [requestError, setRequestError] = useState('')
  const [requestBusy, setRequestBusy] = useState(false)
  const [requestOpen, setRequestOpen] = useState(false)
  const [requests, setRequests] = useState([])
  const [editingProfile, setEditingProfile] = useState(false)
  const [nameDraft, setNameDraft] = useState(user.full_name || '')
  const [avatarDraft, setAvatarDraft] = useState(user.avatar_data || null)
  const [profileError, setProfileError] = useState('')
  const [savingProfile, setSavingProfile] = useState(false)
  const photoInput = useRef(null)
  const [deleteOpen, setDeleteOpen] = useState(false)
  const [deleteVerifyOpen, setDeleteVerifyOpen] = useState(false)
  const [deletePassword, setDeletePassword] = useState('')
  const [deleteAdmins, setDeleteAdmins] = useState([])
  const [deleteSuccessor, setDeleteSuccessor] = useState('')
  const [deleteGoogleCredential, setDeleteGoogleCredential] = useState('')
  const requestedRole = user.role === 'viewer' ? 'analyst' : user.role === 'analyst' ? 'admin' : null
  const pendingRequest = requests.find((item) => item.status === 'pending')
  const loadRequests = async () => { try { setRequests((await api.roleRequests()).requests || []) } catch { /* inbox still reports request history */ } }
  useEffect(() => { if (requestedRole && !user.is_workspace_owner) loadRequests() }, [requestedRole, user.is_workspace_owner])

  const submitRoleRequest = async (event) => {
    event.preventDefault()
    if (!requestedRole || requestMessage.trim().length < 12 || requestBusy) return
    setRequestBusy(true); setRequestError('')
    try {
      await api.createRoleRequest({ requested_role: requestedRole, message: requestMessage.trim() })
      setRequestMessage('')
      toast(`Your ${roleLabel(requestedRole)} access request was sent to the workspace owner.`)
      await loadRequests()
    } catch (err) { setRequestError(err.message) }
    setRequestBusy(false)
  }

  const openProfileEditor = () => {
    setNameDraft(profile.full_name || '')
    setAvatarDraft(profile.avatar_data || null)
    setProfileError('')
    setEditingProfile(true)
  }

  const chooseAvatar = async (event) => {
    const file = event.target.files?.[0]
    event.target.value = ''
    if (!file) return
    if (!file.type.startsWith('image/') || file.size > 8 * 1024 * 1024) {
      setProfileError('Choose an image smaller than 8 MB.')
      return
    }
    try {
      const image = await createImageBitmap(file)
      const scale = Math.min(1, 256 / Math.max(image.width, image.height))
      const canvas = document.createElement('canvas')
      canvas.width = Math.max(1, Math.round(image.width * scale))
      canvas.height = Math.max(1, Math.round(image.height * scale))
      canvas.getContext('2d').drawImage(image, 0, 0, canvas.width, canvas.height)
      image.close?.()
      const blob = await new Promise((resolve, reject) => canvas.toBlob((result) => result ? resolve(result) : reject(new Error('Could not process that image.')), 'image/jpeg', .82))
      if (blob.size > 280000) throw new Error('That image is still too large after resizing. Choose another photo.')
      const reader = new FileReader()
      reader.onload = () => { setAvatarDraft(reader.result); setProfileError('') }
      reader.onerror = () => setProfileError('Could not read that image.')
      reader.readAsDataURL(blob)
    } catch (err) { setProfileError(err.message || 'Choose a valid image file.') }
  }

  const saveProfile = async (event) => {
    event.preventDefault()
    setSavingProfile(true); setProfileError('')
    try {
      const updated = await api.updateProfile({ full_name: nameDraft.trim() || null, avatar_data: avatarDraft })
      setProfile(updated); onProfileUpdate(updated); setEditingProfile(false); toast('Profile updated.')
    } catch (err) { setProfileError(err.message) }
    setSavingProfile(false)
  }

  const openDeleteOptions = async () => {
    setDeleteError(''); setDeleting(true)
    try {
      const { users } = await api.users()
      const activeAdmins = users.filter((member) => member.id !== user.id && member.role === 'admin' && member.is_active)
      setDeleteAdmins(activeAdmins)
      if (!activeAdmins.length) {
        setDeleteError('Promote another active Admin before deleting your account. The workspace must have an Admin owner.')
        setDeleteOpen(true); setDeleting(false); return
      }
      setDeleteSuccessor(String(activeAdmins[0].id))
      setDeleteOpen(true)
    } catch (err) { setDeleteError(err.message); setDeleteOpen(true) }
    setDeleting(false)
  }

  const beginDeleteConfirmation = async () => {
    const successor = deleteAdmins.find((member) => String(member.id) === deleteSuccessor)
    if (!successor) { setDeleteError('Select an active Admin to take over this workspace.'); return }
    const first = await confirm({
      title: 'Delete your owner account?', danger: true, confirmLabel: 'Continue',
      body: `${successor.full_name || successor.username} will become the workspace owner. Your account will be permanently removed; workspace data and other users will remain.`
    })
    if (!first.ok) return
    setDeleteOpen(false)
    setDeletePassword(''); setDeleteGoogleCredential(''); setDeleteError(''); setDeleteVerifyOpen(true)
  }

  const submitDeleteAccount = async (event) => {
    event.preventDefault()
    if (!deletePassword && !deleteGoogleCredential) { setDeleteError('Verify with your password or linked Google account to continue.'); return }
    setDeleting(true); setDeleteError('')
    try {
      await api.deleteAccount({ successor_admin_id: Number(deleteSuccessor), current_password: deletePassword || undefined, google_credential: deleteGoogleCredential || undefined })
      toast('Owner account deleted. Workspace data has been retained.')
      onAccountDeleted()
    } catch (err) { setDeleteError(err.message); setDeleting(false) }
  }
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

  return (
    <>
      <PageHead eyebrow="Account" title="My account" subtitle="Your profile, appearance and password." />
      <div className="grid g2">
        <Card title="Profile" right={<button className="icon-btn profile-edit-button" type="button" onClick={editingProfile ? () => setEditingProfile(false) : openProfileEditor} aria-label={editingProfile ? 'Close profile editor' : 'Edit profile'} title={editingProfile ? 'Close profile editor' : 'Edit profile'}>{editingProfile ? <X size={15} /> : <Pencil size={15} />}</button>}>
          <div className="row" style={{ gap: '1rem', marginBottom: '1rem' }}>
            <Avatar user={profile} large />
            <div><h2>{profile.full_name || profile.username}</h2><div className="muted mono">{profile.username}</div><div style={{ marginTop: '.3rem' }}><RoleBadge role={profile.is_workspace_owner ? 'owner' : profile.role} /></div></div>
          </div>
          <div className="note info" style={{ display: 'flex', gap: '.5rem' }}><ShieldCheck size={16} style={{ flex: 'none', marginTop: 2 }} /><span><b>{roleLabel(user.role)}.</b> {ROLE_INFO[user.role]}</span></div>
          <dl className="kv" style={{ marginTop: '.8rem' }}>
            <dt>Last sign-in</dt><dd>{profile.last_login ? fmtTime(profile.last_login) : 'This is your first session'}</dd>
            <dt>Member since</dt><dd>{profile.created_at ? fmtTime(profile.created_at) : '–'}</dd>
          </dl>
          <div className="row" style={{ marginTop: '1rem' }}>
            {requestedRole && !user.is_workspace_owner && <button className="btn ghost sm" type="button" onClick={() => { setRequestError(''); setRequestOpen(true) }}><MessageSquareText size={14} /> {pendingRequest ? 'Request pending' : 'Request higher role'}</button>}
            <button className="btn ghost sm" onClick={() => onLogout()}><LogOut size={14} /> Sign out</button>
            {user.is_workspace_owner && <button className="btn ghost sm account-delete-trigger" type="button" onClick={deleteOpen ? () => setDeleteOpen(false) : openDeleteOptions}><Trash2 size={14} /> Delete account</button>}
          </div>
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
      {editingProfile && <Modal title="Edit your profile" onClose={() => setEditingProfile(false)}>
        <form className="profile-editor" onSubmit={saveProfile}>
          <div className="profile-editor-photo"><Avatar user={{ ...profile, avatar_data: avatarDraft }} large /><div><b>Profile photo</b><p className="muted">Images are resized and stored with your workspace account.</p><div className="row"><button className="btn ghost sm" type="button" onClick={() => photoInput.current?.click()}><ImagePlus size={14} /> Choose photo</button>{avatarDraft && <button className="btn ghost sm" type="button" onClick={() => setAvatarDraft(null)}>Remove</button>}</div><input ref={photoInput} type="file" accept="image/*" hidden onChange={chooseAvatar} /></div></div>
          <label className="field">Display name<input value={nameDraft} onChange={(event) => setNameDraft(event.target.value)} maxLength={64} placeholder="How your name appears in NetSentinel" /></label>
          <div className="muted profile-username-note">Username <span className="mono">{profile.username}</span> is used to sign in and cannot be changed here.</div>
          <ErrorNote error={profileError} />
          <div className="row"><button className="btn" disabled={savingProfile}><Check size={14} /> {savingProfile ? 'Saving…' : 'Save profile'}</button><button className="btn ghost" type="button" onClick={() => setEditingProfile(false)}>Cancel</button></div>
        </form>
      </Modal>}
      {deleteOpen && user.is_workspace_owner && <Modal title="Delete workspace owner account" onClose={() => setDeleteOpen(false)}>
        <div className="owner-delete-dialog">
          <p className="muted">Your owner account will be permanently removed. Workspace data, connected sources and other users will be kept. Choose an active Admin to take ownership.</p>
          {deleteAdmins.length > 0 && <label className="field">New workspace owner<FilterSelect label="New owner" value={deleteSuccessor} options={deleteAdmins.map((member) => ({ value: String(member.id), label: member.full_name || member.username }))} onChange={setDeleteSuccessor} /></label>}
          <ErrorNote error={deleteError} />
          <div className="row owner-delete-dialog-actions"><button className="btn ghost" type="button" onClick={() => setDeleteOpen(false)}>Cancel</button><button className="btn danger" type="button" disabled={deleting || !deleteAdmins.length} onClick={beginDeleteConfirmation}><Trash2 size={14} /> Continue</button></div>
        </div>
      </Modal>}
      {requestOpen && <Modal title="Request higher access" onClose={() => setRequestOpen(false)}>
        <div className="account-role-request-modal">
          <span className="inbox-eyebrow">Workspace access</span>
          <p className="muted">Request <b>{roleLabel(requestedRole)}</b> access from your workspace owner. Explain what you need; only the owner can see this message.</p>
          {pendingRequest ? <div className="role-request-pending"><span className="inbox-status pending">Pending</span><div><b>Your request is with the owner</b><p className="muted">You can follow the decision in your Inbox.</p></div></div> : <form className="grid" onSubmit={submitRoleRequest}>
            <label className="field">Message to the owner<textarea value={requestMessage} onChange={(event) => setRequestMessage(event.target.value)} rows={4} maxLength={600} minLength={12} placeholder="I need to upload and analyse event datasets for my investigation." required /></label>
            <div className="request-character-count">{requestMessage.trim().length}/600 characters</div>
            <ErrorNote error={requestError} />
            <button className="btn" disabled={requestBusy || requestMessage.trim().length < 12}><MessageSquareText size={15} /> {requestBusy ? 'Sending request…' : `Request ${roleLabel(requestedRole)} access`}</button>
          </form>}
        </div>
      </Modal>}
      {deleteVerifyOpen && <div className="modal-bg" onClick={() => { if (!deleting) setDeleteVerifyOpen(false) }}>
        <form className="modal owner-delete-verify" role="dialog" aria-modal="true" aria-label="Verify account deletion" onClick={(event) => event.stopPropagation()} onSubmit={submitDeleteAccount}>
          <span className="inbox-eyebrow">Final verification</span><h3>Confirm account deletion</h3>
          <p className="muted">For your security, verify your identity. Your selected Admin will take ownership and workspace data will remain.</p>
          <label className="field">Workspace password<input type="password" value={deletePassword} onChange={(event) => { setDeletePassword(event.target.value); setDeleteGoogleCredential('') }} autoComplete="current-password" /></label>
          {googleIdentity?.linked && authConfig?.google_client_id && <div className="delete-google-verify"><span className="muted">Or verify with linked Google account</span>{deleteGoogleCredential ? <span className="delete-google-done"><Check size={14} /> Google identity verified</span> : <GoogleSignInButton clientId={authConfig.google_client_id} theme={theme} onCredential={(credential) => { setDeleteGoogleCredential(credential); setDeletePassword('') }} onError={(err) => setDeleteError(err.message)} />}</div>}
          <ErrorNote error={deleteError} />
          <div className="row" style={{ justifyContent: 'flex-end' }}><button type="button" className="btn ghost" onClick={() => setDeleteVerifyOpen(false)} disabled={deleting}>Cancel</button><button className="btn danger" disabled={deleting || (!deletePassword && !deleteGoogleCredential)}><Trash2 size={14} /> {deleting ? 'Deleting…' : 'Delete account'}</button></div>
        </form>
      </div>}
    </>
  )
}
