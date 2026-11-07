import { useEffect, useRef, useState } from 'react'
import { getToken, wsUrl } from '../api'

// WebSocket with first-message authentication and exponential-backoff reconnect.
// status: 'connecting' | 'live' | 'reconnecting' | 'unauthorised'
export default function useLiveStream(enabled, onEvent) {
  const [status, setStatus] = useState('connecting')
  const [info, setInfo] = useState(null)
  const handler = useRef(onEvent)
  handler.current = onEvent

  useEffect(() => {
    if (!enabled) return undefined
    let ws, timer, stopped = false, attempt = 0
    const connect = () => {
      setStatus(attempt ? 'reconnecting' : 'connecting')
      ws = new WebSocket(wsUrl())
      ws.onopen = () => ws.send(JSON.stringify({ type: 'auth', token: getToken() }))
      ws.onmessage = (e) => {
        let m
        try { m = JSON.parse(e.data) } catch { return }
        if (m.type === 'hello') { attempt = 0; setStatus('live'); setInfo(m) }
        else if (m.type === 'event') handler.current(m)
      }
      ws.onclose = (e) => {
        if (stopped) return
        if (e.code === 1008) { setStatus('unauthorised'); return }
        setStatus('reconnecting')
        timer = setTimeout(connect, Math.min(1000 * 2 ** attempt++, 15000))
      }
    }
    connect()
    return () => { stopped = true; clearTimeout(timer); if (ws) ws.close() }
  }, [enabled])

  return { status, info }
}
