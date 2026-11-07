import React, { useCallback, useEffect, useState } from 'react'
import { KeyRound, Trash2, UserPlus } from 'lucide-react'
import { api } from '../api'
import { roleLabel } from '../brand'
import { useConfirm, useToast } from '../feedback'
import { Avatar, Card, Empty, PageHead, ErrorNote, PasswordHelp, RoleBadge, Spinner, Tabs, bytes, fmtTime, passwordRules } from './ui'

const ROLES = ['viewer', 'analyst', 'admin']
const USERNAME_OK = /^[A-Za-z0-9_.@-]{3,64}$/

function ResetPassword({ target, onClose, onDone }) {
  const [pw, setPw] = useState('')
  const [error, setError] = useState('')
  const ok = passwordRules(pw, target.username).every((r) => r.ok)
  const submit = async (e) => {
    e.preventDefault()
    try { await api.updateUser(target.id, { password: pw }); onDone(); onClose() } catch (err) { setError(err.message) }
  }
  return (
    <div className="modal-bg" onClick={onClose}>
      <form className="modal" role="dialog" aria-modal="true" aria-label="Reset password" onClick={(e) => e.stopPropagation()} onSubmit={submit}>
        <h3>Reset password for {target.username}</h3>
        <p className="muted" style={{ margin: '.4rem 0 .8rem', fontSize: '.85rem' }}>They will be signed out everywhere and must use the new password.</p>
        <div className="grid">
          <input type="password" autoFocus value={pw} onChange={(e) => setPw(e.target.value)} placeholder="New password" autoComplete="new-password" />
          <PasswordHelp password={pw} username={target.username} />
          <ErrorNote error={error} />
          <div className="row" style={{ justifyContent: 'flex-end' }}><button type="button" className="btn ghost" onClick={onClose}>Cancel</button><button className="btn" disabled={!ok}>Reset password</button></div>
        </div>
      </form>
    </div>
  )
}

function Users({ me }) {
  const toast = useToast()
  const confirm = useConfirm()
  const [users, setUsers] = useState(null)
  const [form, setForm] = useState({ username: '', full_name: '', password: '', role: 'viewer' })
  const [error, setError] = useState('')
  const [reset, setReset] = useState(null)
  const load = useCallback(async () => { try { setUsers((await api.users()).users) } catch (e) { setError(e.message) } }, [])
  useEffect(() => { load() }, [load])

  const run = async (fn, okMsg) => {
    setError('')
    try { await fn(); if (okMsg) toast(okMsg); load(); return true } catch (e) { setError(e.message); toast(e.message, 'error'); return false }
  }
  const remove = async (u) => {
    const r = await confirm({ title: `Delete ${u.username}?`, danger: true, confirmLabel: 'Delete user', body: 'The account is removed permanently. Their past alerts and audit entries stay. To keep the account but block access, use Disable instead.' })
    if (r.ok) run(() => api.deleteUser(u.id), 'User deleted')
  }
  const usernameOk = USERNAME_OK.test(form.username)
  const canCreate = usernameOk && passwordRules(form.password, form.username).every((r) => r.ok)

  return (
    <div className="grid g2">
      <Card title={`Users${users ? ` (${users.length})` : ''}`}>
        <ErrorNote error={error} />
        {!users ? <Spinner /> : <div className="table-wrap" style={{ maxHeight: 520 }}><table><thead><tr><th>User</th><th>Role</th><th>Status</th><th>Last sign-in</th><th /></tr></thead><tbody>
          {users.map((u) => {
            const self = u.id === me.id
            return (
              <tr key={u.id}>
                <td><div className="row" style={{ flexWrap: 'nowrap' }}><Avatar user={u} /><div><b>{u.full_name || u.username}</b>{self && <span className="muted"> (you)</span>}<div className="muted mono">{u.username}</div></div></div></td>
                <td><select value={u.role} disabled={self} title={self ? 'You cannot change your own role' : undefined} onChange={(e) => run(() => api.updateUser(u.id, { role: e.target.value }), `${u.username} is now ${roleLabel(e.target.value)}`)} aria-label={`Role of ${u.username}`}>{ROLES.map((r) => <option key={r} value={r}>{roleLabel(r)}</option>)}</select></td>
                <td>{u.is_active ? <span className="badge st-mitigated">Active</span> : <span className="badge st-open">Disabled</span>}</td>
                <td className="muted">{u.last_login ? fmtTime(u.last_login) : 'Never'}</td>
                <td><div className="row" style={{ gap: '.3rem', flexWrap: 'nowrap' }}>
                  <button className="btn ghost sm" disabled={self} onClick={() => run(() => api.updateUser(u.id, { is_active: !u.is_active }), u.is_active ? 'User disabled' : 'User enabled')}>{u.is_active ? 'Disable' : 'Enable'}</button>
                  <button className="btn ghost sm" onClick={() => setReset(u)} title="Reset password" aria-label={`Reset password for ${u.username}`}><KeyRound size={13} /></button>
                  <button className="btn ghost sm" disabled={self} onClick={() => remove(u)} title="Delete user" aria-label={`Delete ${u.username}`}><Trash2 size={13} /></button></div></td>
              </tr>)
          })}
        </tbody></table></div>}
      </Card>
      <Card title="Create user">
        <form className="grid" onSubmit={async (e) => { e.preventDefault(); if (await run(() => api.createUser({ ...form, full_name: form.full_name || null }), 'User created')) setForm({ username: '', full_name: '', password: '', role: 'viewer' }) }}>
          <label className="field">Full name (optional)<input value={form.full_name} onChange={(e) => setForm({ ...form, full_name: e.target.value })} maxLength={64} /></label>
          <label className="field">Username<input value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} required autoComplete="off" /></label>
          {form.username && !usernameOk && <div style={{ color: 'var(--danger)', fontSize: '.8rem' }}>Use 3–64 characters: letters, digits and _ . - @ (no spaces).</div>}
          <label className="field">Password<input type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} required autoComplete="new-password" /></label>
          <PasswordHelp password={form.password} username={form.username} />
          <label className="field">Role<select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>{ROLES.map((r) => <option key={r} value={r}>{roleLabel(r)}</option>)}</select></label>
          <button className="btn" disabled={!canCreate}><UserPlus size={15} /> Create user</button>
          <div className="muted" style={{ fontSize: '.78rem' }}><RoleBadge role="viewer" /> dashboards, alerts, reports · <RoleBadge role="analyst" /> + upload, Attack Lab, triage, mitigate · <RoleBadge role="admin" /> + users, retraining, settings.</div>
        </form>
      </Card>
      {reset && <ResetPassword target={reset} onClose={() => setReset(null)} onDone={() => toast(`Password reset for ${reset.username}`)} />}
    </div>
  )
}

function Settings() {
  const toast = useToast()
  const [sys, setSys] = useState(null)
  const [sim, setSim] = useState(null)
  const [error, setError] = useState('')
  useEffect(() => { Promise.all([api.system(), api.simulation()]).then(([a, b]) => { setSys(a); setSim(b) }).catch((e) => setError(e.message)) }, [])
  const saveSim = async (patch) => { try { setSim(await api.setSimulation(patch)); toast('Simulator settings saved') } catch (e) { toast(e.message, 'error') } }
  const toggleReg = async (enabled) => { try { await api.setRegistration(enabled); setSys({ ...sys, registration_enabled: enabled }); toast(enabled ? 'Self-registration enabled' : 'Self-registration disabled') } catch (e) { toast(e.message, 'error') } }
  if (!sys || !sim) return <><ErrorNote error={error} /><Spinner /></>
  return (
    <div className="grid g2">
      <Card title="Sign-ups">
        <label className="row" style={{ justifyContent: 'space-between', flexWrap: 'nowrap', gap: '1rem' }}>
          <span><b>Allow self-registration</b><div className="muted" style={{ fontSize: '.8rem' }}>Visitors can create their own account on the login page. New accounts are always <b>Viewer</b> (read-only); upgrade them under Users. Limited to 10 sign-ups per IP per hour.</div></span>
          <span className="switch"><input type="checkbox" checked={sys.registration_enabled} onChange={(e) => toggleReg(e.target.checked)} aria-label="Allow self-registration" /><span /></span>
        </label>
      </Card>
      <Card title="Demo traffic simulator">
        <div className="grid">
          <div>
            <b>When should simulated traffic run?</b>
            <div className="seg" style={{ margin: '.5rem 0' }} role="group" aria-label="Simulator mode">
              {[['auto', 'Auto'], ['on', 'Always on'], ['off', 'Off']].map(([id, label]) => <button key={id} className={sim.mode === id ? 'on' : ''} onClick={() => saveSim({ mode: id })}>{label}</button>)}
            </div>
            <div className="muted" style={{ fontSize: '.8rem' }}>
              <b>Auto</b> (recommended): demo traffic runs only while no real source is connected, so real and simulated data never mix. <b>Always on</b> mixes demo traffic into the live dashboard (useful for presentations). <b>Off</b> shows only real or uploaded data.
            </div>
            <div className="note info" style={{ margin: '.6rem 0 0' }}>
              Right now: simulator is <b>{sim.enabled ? 'running' : 'stopped'}</b> · {sim.live_connected ? 'a real source is connected' : 'no real source is connected'}. It only generates traffic while a dashboard is open.
            </div>
          </div>
          <label className="field">Interval: {sim.interval}s<input type="range" min="0.2" max="5" step="0.1" value={sim.interval} onChange={(e) => setSim({ ...sim, interval: +e.target.value })} onMouseUp={() => saveSim({ interval: sim.interval })} onTouchEnd={() => saveSim({ interval: sim.interval })} /></label>
          <label className="field">Share of attack traffic: {Math.round(sim.attack_ratio * 100)}%<input type="range" min="0" max="0.9" step="0.01" value={sim.attack_ratio} onChange={(e) => setSim({ ...sim, attack_ratio: +e.target.value })} onMouseUp={() => saveSim({ attack_ratio: sim.attack_ratio })} onTouchEnd={() => saveSim({ attack_ratio: sim.attack_ratio })} /></label>
        </div>
      </Card>
    </div>
  )
}

function System() {
  const [s, setS] = useState(null); const [error, setError] = useState('')
  useEffect(() => { api.system().then(setS).catch((e) => setError(e.message)) }, [])
  if (!s) return <><ErrorNote error={error} /><Spinner /></>
  const up = s.uptime_seconds
  const rows = [
    ['Version', `${s.app_name} ${s.version} (${s.environment})`], ['Connected sources', s.sources], ['Web model trained', s.web_model_trained_at || '–'], ['Uptime', `${Math.floor(up / 3600)} h ${Math.floor((up % 3600) / 60)} min`],
    ['Detection models', s.model_members.join(', ')], ['Trained', s.model_trained_at || '–'], ['Training data', s.dataset || '–'],
    ['Prediction cache', `${s.cache.hits} hits / ${s.cache.misses} misses (${Math.round(s.cache.hit_rate * 100)}%)`], ['Dashboards connected', s.stream_clients],
    ['Users', s.users], ['Database size', bytes(s.db_bytes)], ['Data retention', `${s.retention_days} days`], ['Email alerts', s.email_alerts ? 'Configured' : 'Not configured (set SMTP_HOST and ALERT_EMAIL_TO)'],
  ]
  return <Card title="System status"><dl className="kv" style={{ gridTemplateColumns: '210px 1fr' }}>{rows.map(([k, v]) => <React.Fragment key={k}><dt>{k}</dt><dd>{v}</dd></React.Fragment>)}</dl></Card>
}

function Blocklist() {
  const toast = useToast()
  const [d, setD] = useState(null); const [error, setError] = useState('')
  const load = useCallback(() => api.mitigations().then(setD).catch((e) => setError(e.message)), [])
  useEffect(() => { load() }, [load])
  if (!d) return <><ErrorNote error={error} /><Spinner /></>
  return (
    <div className="grid g2">
      <Card title="Simulated blocklist"><ErrorNote error={error} />
        <div className="table-wrap"><table><thead><tr><th>IP</th><th>Reason</th><th>By</th><th /></tr></thead><tbody>
          {d.blocklist.map((b) => <tr key={b.ip}><td className="mono">{b.ip}</td><td className="muted">{b.reason}</td><td>{b.created_by}</td><td><button className="btn ghost sm" onClick={() => api.unblock(b.ip).then(() => { toast('IP removed from blocklist'); load() }).catch((e) => toast(e.message, 'error'))}>Remove</button></td></tr>)}
          {d.blocklist.length === 0 && <tr><td colSpan="4" className="empty">Nothing blocked.</td></tr>}</tbody></table></div></Card>
      <Card title="Applied mitigations (simulated)"><div className="table-wrap"><table><thead><tr><th>When</th><th>Alert</th><th>Action</th><th>By</th></tr></thead><tbody>
        {d.mitigations.map((m) => <tr key={m.id}><td>{fmtTime(m.applied_at)}</td><td>#{m.alert_id} {m.attack_type}</td><td>{m.title}</td><td>{m.applied_by}</td></tr>)}
        {d.mitigations.length === 0 && <tr><td colSpan="4" className="empty">None yet.</td></tr>}</tbody></table></div></Card>
    </div>
  )
}

function Audit() {
  const [rows, setRows] = useState(null); const [error, setError] = useState('')
  useEffect(() => { api.audit().then((r) => setRows(r.entries)).catch((e) => setError(e.message)) }, [])
  return (
    <Card title="Audit log (latest 100)"><ErrorNote error={error} />{!rows ? <Spinner /> : rows.length === 0 ? <Empty>No entries.</Empty> : <div className="table-wrap" style={{ maxHeight: 540 }}><table><thead><tr><th>When</th><th>User</th><th>Action</th><th>Target</th><th>Detail</th><th>IP</th></tr></thead><tbody>
      {rows.map((r) => <tr key={r.id}><td>{fmtTime(r.ts)}</td><td>{r.username}</td><td>{r.action}</td><td>{r.target}</td><td className="muted">{r.detail}</td><td className="mono">{r.ip}</td></tr>)}</tbody></table></div>}</Card>
  )
}

export default function Admin({ user }) {
  const [tab, setTab] = useState('users')
  return (
    <>
      <PageHead eyebrow="Manage" title="Administration" subtitle="Users, settings, system status and the audit trail." />
      <Tabs value={tab} onChange={setTab} tabs={[{ id: 'users', label: 'Users' }, { id: 'settings', label: 'Settings' }, { id: 'system', label: 'System' }, { id: 'block', label: 'Blocklist & mitigations' }, { id: 'audit', label: 'Audit log' }]} />
      {tab === 'users' && <Users me={user} />}{tab === 'settings' && <Settings />}{tab === 'system' && <System />}{tab === 'block' && <Blocklist />}{tab === 'audit' && <Audit />}
    </>
  )
}
