import { useCallback, useRef, useState } from 'react'
import useLiveStream from './useLiveStream'

// Aggregates the live stream once, at the app level, so charts keep their history when the user switches pages.
export default function useLiveFeed(enabled) {
  const [events, setEvents] = useState([])
  const [series, setSeries] = useState([])
  const [counts, setCounts] = useState({ total: 0, threats: 0 })
  const [latestThreat, setLatestThreat] = useState(null)
  const seq = useRef(0)

  const onEvent = useCallback((e) => {
    const t = new Date(e.ts * 1000).toLocaleTimeString()
    const row = { ...e, timeStr: t, key: ++seq.current }
    setEvents((p) => [row, ...p].slice(0, 60))
    setSeries((p) => [...p, { t, origin: e.origin, normal: e.verdict === 'threat' ? 0 : e.bytes, threat: e.verdict === 'threat' ? e.bytes : 0 }].slice(-40))
    setCounts((c) => ({ total: c.total + 1, threats: c.threats + (e.verdict === 'threat' ? 1 : 0) }))
    if (e.verdict === 'threat') setLatestThreat(row)
  }, [])

  const { status, info } = useLiveStream(enabled, onEvent)
  return { events, series, counts, latestThreat, status, info }
}
