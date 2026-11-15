import React, { useCallback, useEffect, useRef, useState } from 'react'
import { Bell, Check, Inbox as InboxIcon, X } from 'lucide-react'
import { api } from '../api'
import { roleLabel } from '../brand'
import { useToast } from '../feedback'
import { fmtTime } from './ui'

export default function Inbox({ user, onUserUpdate }) {
  const toast = useToast()
  const [open, setOpen] = useState(false)
  const [tab, setTab] = useState('requests')
  const [requests, setRequests] = useState([])
  const [notifications, setNotifications] = useState([])
  const [unread, setUnread] = useState(0)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(null)
  const root = useRef(null)
  const latestNotice = useRef(null)
  const owner = Boolean(user.is_workspace_owner)

  const load = useCallback(async (announce = false) => {
    try {
      const [r, n] = await Promise.all([api.roleRequests(), api.notifications()])
      setRequests(r.requests || [])
      setNotifications(n.notifications || [])
      setUnread(n.unread || 0)
      const newest = n.notifications?.[0]
      const isNew = latestNotice.current !== null && newest && newest.id > latestNotice.current
      if (isNew && announce) toast(newest.title, 'info')
      if (isNew && ['role_approved', 'role_changed'].includes(newest.kind)) {
        api.me().then(onUserUpdate).catch(() => {})
      }
      if (newest) latestNotice.current = newest.id
      else if (latestNotice.current === null) latestNotice.current = 0
      setError('')
    } catch (err) { setError(err.message) }
  }, [toast])

  useEffect(() => {
    load()
    const timer = window.setInterval(() => load(true), 15000)
    return () => window.clearInterval(timer)
  }, [load])

  useEffect(() => {
    if (!open) return undefined
    const dismiss = (event) => {
      if (event.key === 'Escape') setOpen(false)
      else if (event.type === 'pointerdown' && !root.current?.contains(event.target)) setOpen(false)
    }
    document.addEventListener('keydown', dismiss)
    document.addEventListener('pointerdown', dismiss)
    return () => { document.removeEventListener('keydown', dismiss); document.removeEventListener('pointerdown', dismiss) }
  }, [open])

  const showTab = async (next) => {
    setTab(next)
    if (next === 'notifications' && unread) {
      try { await api.markNotificationsRead(); setUnread(0); await load() } catch (err) { setError(err.message) }
    }
  }

  const decide = async (item, decision) => {
    setBusy(item.id); setError('')
    try {
      await api.decideRoleRequest(item.id, decision)
      toast(decision === 'approved' ? `${item.full_name || item.username} is now ${roleLabel(item.requested_role)}.` : 'Access request declined.', decision === 'approved' ? 'ok' : 'info')
      await load()
    } catch (err) { setError(err.message) }
    setBusy(null)
  }

  const pendingCount = owner ? requests.filter((item) => item.status === 'pending').length : 0
  const count = pendingCount + unread
  return (
    <div className="console-inbox-wrap" ref={root}>
      <button className="console-inbox-button" type="button" aria-label={`Inbox${count ? `, ${count} unread` : ''}`} aria-expanded={open} onClick={() => { setOpen((value) => !value); if (!open) load() }}>
        <InboxIcon size={16} /><span>Inbox</span>{count > 0 && <span className="inbox-count">{count > 9 ? '9+' : count}</span>}
      </button>
      {open && <section className="inbox-panel" aria-label="Inbox">
        <div className="inbox-panel-head"><div><span className="inbox-eyebrow">Workspace</span><h3>Inbox</h3></div><button type="button" className="icon-btn" onClick={() => setOpen(false)} aria-label="Close inbox"><X size={15} /></button></div>
        <div className="inbox-tabs" role="tablist" aria-label="Inbox sections">
          <button type="button" role="tab" aria-selected={tab === 'requests'} className={tab === 'requests' ? 'active' : ''} onClick={() => showTab('requests')}>Requests{owner && pendingCount > 0 && <span>{pendingCount}</span>}</button>
          <button type="button" role="tab" aria-selected={tab === 'notifications'} className={tab === 'notifications' ? 'active' : ''} onClick={() => showTab('notifications')}>Notifications{unread > 0 && <span>{unread}</span>}</button>
        </div>
        {error && <div className="inbox-error" role="alert">{error}</div>}
        <div className="inbox-items">
          {tab === 'requests' && (owner
            ? requests.length ? requests.map((item) => <article className="inbox-item" key={item.id}>
                <div className="inbox-item-title"><b>{item.full_name || item.username}</b><span className="inbox-role">{roleLabel(item.requested_role)}</span></div>
                <div className="inbox-subtitle mono">{item.username} / {fmtTime(item.created_at)}</div>
                <p>{item.message}</p>
                <div className="inbox-item-actions"><button className="btn sm" disabled={busy === item.id} onClick={() => decide(item, 'approved')}><Check size={14} /> Approve</button><button className="btn ghost sm" disabled={busy === item.id} onClick={() => decide(item, 'declined')}><X size={14} /> Decline</button></div>
              </article>) : <div className="inbox-empty"><Check size={18} /><b>All caught up</b><span>No pending access requests.</span></div>
            : requests.length ? requests.map((item) => <article className="inbox-item" key={item.id}>
                <div className="inbox-item-title"><b>Request: {roleLabel(item.requested_role)}</b><span className={`inbox-status ${item.status}`}>{item.status}</span></div>
                <div className="inbox-subtitle">{fmtTime(item.created_at)}</div><p>{item.message}</p>
                {item.reviewed_at && <div className="role-reviewed-by">{item.status === 'approved' ? 'Approved' : 'Declined'} by {item.reviewer_full_name || item.reviewer_username || 'workspace owner'} <span>· {fmtTime(item.reviewed_at)}</span></div>}
              </article>) : <div className="inbox-empty"><InboxIcon size={18} /><b>No requests yet</b><span>Requests you send to your workspace owner will appear here.</span></div>
          )}
          {tab === 'notifications' && (notifications.length ? notifications.map((item) => <article className={`inbox-item inbox-notice ${!item.read_at ? 'unread' : ''}`} key={item.id}>
              <div className="inbox-item-title"><b>{item.title}</b>{!item.read_at && <i />}</div><p>{item.message}</p><div className="inbox-subtitle">{fmtTime(item.created_at)}</div>
            </article>) : <div className="inbox-empty"><Bell size={18} /><b>No notifications</b><span>Workspace updates will show up here.</span></div>
          )}
        </div>
        <div className="inbox-panel-foot">Updates automatically while this workspace is open.</div>
      </section>}
    </div>
  )
}
