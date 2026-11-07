// One place to rename the product (the backend name lives in backend/app/branding.py).
export const BRAND = { name: 'Argus', tagline: 'AI Threat Detection & Monitoring' }
export const roleLabel = (r) => (r ? r.charAt(0).toUpperCase() + r.slice(1) : '')
export const initials = (u) => {
  const src = (u?.full_name || u?.username || '?').trim()
  const parts = src.split(/[\s._@-]+/).filter(Boolean)
  return ((parts[0]?.[0] || '?') + (parts.length > 1 ? parts[1][0] : '')).toUpperCase()
}
