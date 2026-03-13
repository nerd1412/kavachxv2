export default function StatCard({ label, value, icon: Icon, color = 'var(--accent)', change, changeDelta }) {
  const isPositive = changeDelta > 0
  return (
    <div className="stat-card">
      {Icon && <div className="stat-icon"><Icon size={32} color={color} /></div>}
      <div className="stat-label" style={{ marginBottom: 6 }}>{label}</div>
      <div className="stat-value" style={{ color }}>{value}</div>
      {change !== undefined && (
        <div className="stat-change" style={{ color: isPositive ? 'var(--green)' : changeDelta < 0 ? 'var(--red)' : 'var(--text-muted)' }}>
          <span>{isPositive ? '↑' : changeDelta < 0 ? '↓' : '—'}</span>
          <span>{change}</span>
        </div>
      )}
    </div>
  )
}
