import React, { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react'
import { CheckCircle2, Info, XCircle } from 'lucide-react'

const ToastCtx = createContext(() => {})
const ConfirmCtx = createContext(async () => ({ ok: false, checked: false }))
export const useToast = () => useContext(ToastCtx)
export const useConfirm = () => useContext(ConfirmCtx)

// Toasts (non-blocking feedback) and a themed confirm dialog (replaces window.confirm).
export function FeedbackProvider({ children }) {
  const [toasts, setToasts] = useState([])
  const [dlg, setDlg] = useState(null)
  const [checked, setChecked] = useState(false)
  const seq = useRef(0)

  const toast = useCallback((message, kind = 'ok') => {
    const id = ++seq.current
    setToasts((t) => [...t, { id, message, kind }])
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), kind === 'error' ? 6000 : 3800)
  }, [])

  const confirm = useCallback((opts) => new Promise((resolve) => { setChecked(false); setDlg({ ...opts, resolve }) }), [])
  const close = useCallback((ok) => { setDlg((d) => { if (d) d.resolve({ ok, checked }); return null }) }, [checked])

  useEffect(() => {
    if (!dlg) return undefined
    const onKey = (e) => { if (e.key === 'Escape') close(false) }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [dlg, close])

  const Icon = { ok: CheckCircle2, error: XCircle, info: Info }
  return (
    <ToastCtx.Provider value={toast}>
      <ConfirmCtx.Provider value={confirm}>
        {children}
        <div className="toasts" aria-live="polite">
          {toasts.map((t) => { const I = Icon[t.kind] || Info; return <div key={t.id} className={`toast ${t.kind}`}><I size={16} /> <span>{t.message}</span></div> })}
        </div>
        {dlg && (
          <div className="modal-bg" onClick={() => close(false)}>
            <div className="modal" role="dialog" aria-modal="true" aria-label={dlg.title} onClick={(e) => e.stopPropagation()}>
              <h3>{dlg.title}</h3>
              <p className="muted" style={{ margin: '.5rem 0 .8rem' }}>{dlg.body}</p>
              {dlg.checkbox && <label className="row" style={{ marginBottom: '1rem', fontSize: '.88rem' }}><input type="checkbox" checked={checked} onChange={(e) => setChecked(e.target.checked)} /> {dlg.checkbox}</label>}
              <div className="row" style={{ justifyContent: 'flex-end' }}>
                <button className="btn ghost" onClick={() => close(false)}>Cancel</button>
                <button className={`btn ${dlg.danger ? 'danger' : ''}`} onClick={() => close(true)} autoFocus>{dlg.confirmLabel || 'Confirm'}</button>
              </div>
            </div>
          </div>)}
      </ConfirmCtx.Provider>
    </ToastCtx.Provider>
  )
}
