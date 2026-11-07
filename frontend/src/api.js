// Thin API client. The JWT lives in sessionStorage (cleared when the tab closes) and is sent as a Bearer header.
const BASE = import.meta.env.VITE_API_URL || ''
const KEY = 'cw_token'
let unauthorized = () => {}  // called with a human-readable reason when the server rejects the session

export const getToken = () => sessionStorage.getItem(KEY)
export const setToken = (t) => (t ? sessionStorage.setItem(KEY, t) : sessionStorage.removeItem(KEY))
export const onUnauthorized = (fn) => { unauthorized = fn }

export function wsUrl() {
  if (BASE) return BASE.replace(/^http/, 'ws') + '/ws/stream'
  return `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws/stream`
}

function message(detail, status) {
  const clean = (m) => String(m).replace(/^Value error, /, '')
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail)) return detail.map((d) => clean(d.msg || JSON.stringify(d))).join('; ')
  return `Request failed (${status})`
}

async function request(path, opts = {}) {
  const { method = 'GET', body, form, blob } = opts
  const headers = {}
  const token = getToken()
  if (token) headers.Authorization = `Bearer ${token}`
  let payload
  if (form) payload = form
  else if (body !== undefined) { headers['Content-Type'] = 'application/json'; payload = JSON.stringify(body) }
  let res
  try {
    res = await fetch(BASE + path, { method, headers, body: payload })
  } catch {
    throw new Error('Cannot reach the backend. Is it running on port 8000?')
  }
  if (!res.ok) {
    let detail
    try { detail = (await res.json()).detail } catch { /* non-JSON error body */ }
    const text = message(detail, res.status)
    if (res.status === 401 && !path.startsWith('/api/auth/login') && !path.startsWith('/api/auth/register')) unauthorized(text)
    throw Object.assign(new Error(text), { status: res.status })
  }
  return blob ? res.blob() : res.json()
}

const qs = (o) => {
  const p = new URLSearchParams()
  Object.entries(o).forEach(([k, v]) => { if (v !== undefined && v !== null && v !== '') p.set(k, v) })
  const s = p.toString()
  return s ? `?${s}` : ''
}

export async function download(path, filename) {
  const blob = await request(path, { blob: true })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url; a.download = filename; document.body.appendChild(a); a.click(); a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export const api = {
  authConfig: () => request('/api/auth/config'),
  login: (username, password) => request('/api/auth/login', { method: 'POST', body: { username, password } }),
  register: (username, password, full_name) => request('/api/auth/register', { method: 'POST', body: { username, password, full_name: full_name || null } }),
  me: () => request('/api/auth/me'),
  changePassword: (current_password, new_password) => request('/api/auth/change-password', { method: 'POST', body: { current_password, new_password } }),
  users: () => request('/api/auth/users'),
  createUser: (b) => request('/api/auth/users', { method: 'POST', body: b }),
  updateUser: (id, b) => request(`/api/auth/users/${id}`, { method: 'PATCH', body: b }),
  deleteUser: (id) => request(`/api/auth/users/${id}`, { method: 'DELETE' }),
  overview: (hours = 24, scope = 'all') => request(`/api/stats/overview${qs({ hours, scope })}`),
  timeline: (hours = 24, scope = 'all') => request(`/api/stats/timeline${qs({ hours, scope })}`),
  heatmap: (hours = 168, scope = 'all') => request(`/api/stats/heatmap${qs({ hours, scope })}`),
  topSources: (hours = 24, scope = 'all') => request(`/api/stats/top-sources${qs({ hours, limit: 6, scope })}`),
  forecast: (horizon = 6, scope = 'all') => request(`/api/stats/forecast${qs({ horizon, scope })}`),
  alerts: (params) => request(`/api/alerts${qs(params)}`),
  alert: (id) => request(`/api/alerts/${id}`),
  setStatus: (id, status) => request(`/api/alerts/${id}`, { method: 'PATCH', body: { status } }),
  alertRecs: (id) => request(`/api/alerts/${id}/recommendations`),
  mitigate: (id, solution_id) => request(`/api/alerts/${id}/mitigate`, { method: 'POST', body: { solution_id } }),
  mitigations: () => request('/api/mitigations'),
  unblock: (ip) => request(`/api/blocklist/${encodeURIComponent(ip)}`, { method: 'DELETE' }),
  detectEvent: (b) => request('/api/detect/event', { method: 'POST', body: b }),
  upload: (file) => { const f = new FormData(); f.append('file', file); return request('/api/detect/upload', { method: 'POST', form: f }) },
  jobs: () => request('/api/detect/jobs'),
  job: (id) => request(`/api/detect/jobs/${id}`),
  deleteJob: (id, deleteFindings) => request(`/api/detect/jobs/${id}${qs({ delete_findings: deleteFindings ? 'true' : '' })}`, { method: 'DELETE' }),
  model: () => request('/api/models/active'),
  retrain: (quick) => request('/api/models/retrain', { method: 'POST', body: { quick } }),
  retrainStatus: () => request('/api/models/retrain/status'),
  chat: (message) => request('/api/chat', { method: 'POST', body: { message } }),
  audit: () => request('/api/admin/audit?limit=100'),
  simulation: () => request('/api/admin/simulation'),
  setSimulation: (b) => request('/api/admin/simulation', { method: 'POST', body: b }),
  sources: () => request('/api/sources'),
  createSource: (b) => request('/api/sources', { method: 'POST', body: b }),
  updateSource: (id, b) => request(`/api/sources/${id}`, { method: 'PATCH', body: b }),
  rotateSource: (id) => request(`/api/sources/${id}/rotate`, { method: 'POST' }),
  revokeSource: (id) => request(`/api/sources/${id}/revoke`, { method: 'POST' }),
  deleteSource: (id) => request(`/api/sources/${id}`, { method: 'DELETE' }),
  coverage: () => request('/api/coverage'),
  system: () => request('/api/admin/system'),
  setRegistration: (enabled) => request('/api/admin/registration', { method: 'POST', body: { enabled } }),
}
