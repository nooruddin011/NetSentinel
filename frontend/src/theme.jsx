import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'

const CHART = {
  dark: { grid: 'rgba(236,232,223,.07)', axis: '#6b756f', text: '#98a29c', accent: '#d6a95a', ice: '#bcd6e3', danger: '#ef6a6a', ok: '#7fc29b', warn: '#f2994a',
    tip: { contentStyle: { background: '#1d2321', border: '1px solid rgba(236,232,223,.14)', borderRadius: 14, color: '#ece8df', boxShadow: '0 20px 40px -12px rgba(0,0,0,.6)' }, itemStyle: { color: '#ece8df' }, labelStyle: { color: '#98a29c' } } },
  light: { grid: 'rgba(29,28,24,.09)', axis: '#9a958a', text: '#6b675d', accent: '#9a6f1f', ice: '#41667a', danger: '#c0392b', ok: '#2f7d5b', warn: '#c4691f',
    tip: { contentStyle: { background: '#fbf8f2', border: '1px solid rgba(29,28,24,.14)', borderRadius: 14, color: '#1d1c18', boxShadow: '0 20px 40px -14px rgba(60,48,20,.35)' }, itemStyle: { color: '#1d1c18' }, labelStyle: { color: '#6b675d' } } },
}
const Ctx = createContext({ theme: 'dark', toggle: () => {}, chart: CHART.dark })

function initialTheme() {
  try {
    const saved = localStorage.getItem('argus_theme')
    if (saved === 'light' || saved === 'dark') return saved
    if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) return 'light'
  } catch { /* storage unavailable */ }
  return 'dark'
}

export function ThemeProvider({ children }) {
  const [theme, setTheme] = useState(initialTheme)
  useEffect(() => {
    document.documentElement.dataset.theme = theme
    try { localStorage.setItem('argus_theme', theme) } catch { /* ignore */ }
  }, [theme])
  const toggle = useCallback(() => setTheme((t) => (t === 'dark' ? 'light' : 'dark')), [])
  const value = useMemo(() => ({ theme, toggle, chart: CHART[theme] }), [theme, toggle])
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export const useTheme = () => useContext(Ctx)
export const useChart = () => useContext(Ctx).chart
