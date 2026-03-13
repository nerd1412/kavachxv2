export const getRiskColor = (score) => {
  if (score >= 0.75) return 'var(--red)'
  if (score >= 0.45) return 'var(--amber)'
  if (score >= 0.25) return '#f59e0b'
  return 'var(--green)'
}
export const getRiskLabel = (score) => {
  if (score >= 0.75) return 'CRITICAL'
  if (score >= 0.55) return 'HIGH'
  if (score >= 0.35) return 'MEDIUM'
  return 'LOW'
}
export const getDecisionClass = (d) => {
  if (d === 'PASS') return 'dec-pass'
  if (d === 'ALERT') return 'dec-alert'
  if (d === 'BLOCK') return 'dec-block'
  if (d === 'HUMAN_REVIEW') return 'dec-review'
  return ''
}
export const formatDateTime = (iso) => {
  if (!iso) return '—'
  const d = new Date(iso)
  return d.toLocaleString('en-IN', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit', hour12: false })
}
export const formatDate = (iso) => {
  if (!iso) return '—'
  return new Date(iso).toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' })
}
export const formatPct = (v, decimals = 1) => ((v || 0) * 100).toFixed(decimals) + '%'
export const fmtNum = (n) => typeof n === 'number' ? n.toLocaleString('en-IN') : (n ?? '—')
