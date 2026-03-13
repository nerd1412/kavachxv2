export default function Badge({ label, color }) {
  return (
    <span className="badge" style={{ background: color + '20', color, border: '1px solid ' + color + '40' }}>
      {label}
    </span>
  )
}
