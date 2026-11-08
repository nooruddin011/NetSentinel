import React, { useEffect, useRef, useState } from 'react'
import { MessageSquare, Send, Trash2, X } from 'lucide-react'
import { api } from '../api'
import { BRAND } from '../brand'
import Logo from './Logo'

const SUGGESTIONS = ['Status summary', 'What can you detect?', 'Critical alerts', 'Top attackers', 'What is SQL injection?', 'How do I stop brute force?', 'Which model is best?']
const now = () => new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
const welcome = () => [{ role: 'bot', t: now(), text: 'Hi! I answer from your own data. Ask about current alerts, attackers, what Argus can detect, an attack type, or model accuracy.' }]

// Render **bold** segments without dangerouslySetInnerHTML (replies may contain attacker-controlled text).
const Rich = ({ text }) => text.split(/(\*\*[^*]+\*\*)/g).map((p, i) => (p.startsWith('**') && p.endsWith('**') ? <strong key={i}>{p.slice(2, -2)}</strong> : <React.Fragment key={i}>{p}</React.Fragment>))

export default function Chatbot() {
  const [open, setOpen] = useState(false)
  const [msgs, setMsgs] = useState(welcome)
  const [text, setText] = useState('')
  const [busy, setBusy] = useState(false)
  const messages = useRef(null)
  const input = useRef(null)
  const panel = useRef(null)

  useEffect(() => {
    const list = messages.current
    if (list) list.scrollTo({ top: list.scrollHeight, behavior: 'smooth' })
  }, [msgs, busy, open])
  useEffect(() => { if (open) input.current?.focus() }, [open])
  useEffect(() => {
    if (!open) return undefined
    const k = (e) => { if (e.key === 'Escape') setOpen(false) }
    window.addEventListener('keydown', k)
    return () => window.removeEventListener('keydown', k)
  }, [open])
  useEffect(() => {
    if (!open) return undefined
    const chatPanel = panel.current
    if (!chatPanel) return undefined
    const keepScrollInside = (event) => {
      // The message list owns scrolling; wheel gestures over the rest of the panel
      // must not scroll the dashboard behind it.
      if (!event.target.closest?.('.chat-msgs')) event.preventDefault()
    }
    const closeOutside = (event) => {
      if (event.target.closest?.('.chat-fab')) return
      if (!chatPanel.contains(event.target)) setOpen(false)
    }
    chatPanel.addEventListener('wheel', keepScrollInside, { passive: false })
    document.addEventListener('click', closeOutside)
    return () => {
      chatPanel.removeEventListener('wheel', keepScrollInside)
      document.removeEventListener('click', closeOutside)
    }
  }, [open])

  const send = async (m) => {
    const message = (m ?? text).trim()
    if (!message || busy) return
    setText(''); setBusy(true)
    setMsgs((p) => [...p, { role: 'user', text: message, t: now() }])
    try { const r = await api.chat(message); setMsgs((p) => [...p, { role: 'bot', text: r.reply, t: now() }]) }
    catch (e) { setMsgs((p) => [...p, { role: 'bot', text: `Sorry, I could not answer that: ${e.message}`, t: now() }]) }
    setBusy(false)
  }

  if (!open) return <button className="chat-fab" onClick={() => setOpen(true)} aria-label={`Open ${BRAND.name} assistant`}><MessageSquare size={22} /></button>
  return (
    <div ref={panel} className="chat" role="dialog" aria-label={`${BRAND.name} assistant`} onClick={(event) => event.stopPropagation()}>
      <div className="chat-head">
        <div className="chat-id">
          <Logo size={34} />
          <div><b>{BRAND.name} assistant</b><span className="chat-status"><span className="dot live" /> Online · answers from your data</span></div>
        </div>
        <div className="row" style={{ gap: '.35rem', flexWrap: 'nowrap' }}>
          <button className="icon-btn" onClick={() => setMsgs(welcome())} aria-label="Clear conversation" title="Clear conversation"><Trash2 size={14} /></button>
          <button className="icon-btn" onClick={() => setOpen(false)} aria-label="Close"><X size={15} /></button>
        </div>
      </div>
      <div ref={messages} className="chat-msgs" aria-live="polite">
        {msgs.map((m, i) => (
          <div key={i} className={`msg-row ${m.role}`}>
            {m.role === 'bot' && <span className="msg-av"><Logo size={16} /></span>}
            <div className="msg-col"><div className={`msg ${m.role}`}><Rich text={m.text} /></div><span className="msg-time">{m.t}</span></div>
          </div>))}
        {busy && <div className="msg-row bot"><span className="msg-av"><Logo size={16} /></span><div className="typing" aria-label="Assistant is typing"><i /><i /><i /></div></div>}
      </div>
      {msgs.length === 1 && <div className="chat-suggest">{SUGGESTIONS.map((s) => <button key={s} className="chip" onClick={() => send(s)}>{s}</button>)}</div>}
      <div className="chat-in">
        <input ref={input} value={text} onChange={(e) => setText(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && send()} placeholder="Ask about threats, sources, models…" maxLength={500} aria-label="Message" />
        <button className="send" onClick={() => send()} disabled={busy || !text.trim()} aria-label="Send"><Send size={17} /></button>
      </div>
    </div>
  )
}
