import { useEffect, useState, useCallback } from 'react'
import { RadarChart, Radar, PolarGrid, PolarAngleAxis, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid } from 'recharts'
import { dashboardAPI, auditAPI } from '../utils/api'
import { Scale, FileCheck, AlertTriangle, CheckCircle2, Download } from 'lucide-react'

function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim()
}
function useChartColors() {
  const [c, setC] = useState({})
  useEffect(() => {
    const read = () => setC({ accent: cssVar('--accent') || '#4f46e5', border: cssVar('--border') || '#e0e2ed' })
    read()
    const obs = new MutationObserver(read)
    obs.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] })
    return () => obs.disconnect()
  }, [])
  return c
}

const FRAMEWORKS = [
  { key: 'eu_ai_act', label: 'EU AI Act', score: 82, status: 'compliant' },
  { key: 'dpdp_2023', label: 'DPDP 2023', score: 76, status: 'partial' },
  { key: 'rbi_fairness', label: 'RBI Fairness', score: 91, status: 'compliant' },
  { key: 'nist_ai_rmf', label: 'NIST AI RMF', score: 69, status: 'partial' },
  { key: 'iso_42001', label: 'ISO 42001', score: 55, status: 'gap' },
]

const radarData = FRAMEWORKS.map(f => ({ subject: f.label, score: f.score }))

const INITIAL_STATS = { total_inferences: 0, policy_violations_today: 0, active_models: 0, fairness_issues_detected: 0 }

export default function ComplianceDashboard() {
  const [stats, setStats] = useState(INITIAL_STATS)
  const [violations, setViolations] = useState([])
  const [loading, setLoading] = useState(true)
  const col = useChartColors()

  const load = useCallback(async (silent = false) => {
    if (!silent) setLoading(true)
    try {
      const [s, v] = await Promise.all([dashboardAPI.getStats(), auditAPI.getLogs({ limit: 20 })])
      if (s.data) setStats(s.data)
      if (v.data) setViolations(v.data)
    } catch (err) {
      console.error("Failed to load compliance data:", err)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
    
    // Live WebSocket connection
    const apiBase = import.meta.env.VITE_API_URL || (import.meta.env.PROD ? `${window.location.origin}/api/v1` : 'http://localhost:8005/api/v1')
    const wsBase = apiBase.replace(/^http/, 'ws').replace('/api/v1', '')
    const wsURL = `${wsBase}/api/v1/ws/stream`
    const ws = new WebSocket(wsURL)
    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data)
        if (msg.type === 'new_inference') load(true)
      } catch(e) {}
    }

    const handleRefresh = () => load(true)
    window.addEventListener('kavachx:simulation-complete', handleRefresh)
    
    return () => {
      window.removeEventListener('kavachx:simulation-complete', handleRefresh)
      ws.close()
    }
  }, [load])

  const exportComplianceReport = () => {
    const lines = [
      'KavachX Compliance Report',
      `Generated: ${new Date().toLocaleString()}`,
      '',
      'FRAMEWORK SCORES',
      ...FRAMEWORKS.map(f => `${f.label},${f.score}%,${f.status}`),
      '',
      'SUMMARY STATISTICS',
      `Total Inferences,${stats?.total_inferences ?? 'N/A'}`,
      `Policy Violations Today,${stats?.policy_violations_today ?? 'N/A'}`,
      `Active Models,${stats?.active_models ?? 'N/A'}`,
      `Fairness Issues,${stats?.fairness_issues_detected ?? 'N/A'}`,
    ]
    const blob = new Blob([lines.join('\n')], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a'); a.href = url; a.download = `kavachx-compliance-report-${Date.now()}.csv`; a.click()
    URL.revokeObjectURL(url)
  }

  const exportViolations = () => {
    const rows = [['Timestamp', 'Event Type', 'Entity', 'Actor', 'Risk Level'].join(',')]
    violations.forEach(v => rows.push([
      new Date(v.timestamp).toISOString(), v.event_type, v.entity_id || '', v.actor || '', v.risk_level || ''
    ].join(',')))
    const blob = new Blob([rows.join('\n')], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a'); a.href = url; a.download = `kavachx-violations-${Date.now()}.csv`; a.click()
    URL.revokeObjectURL(url)
  }

  const statusColor = (s) => ({ compliant: 'var(--green)', partial: 'var(--amber)', gap: 'var(--red)' }[s] || 'var(--text-muted)')
  const statusBadge = (s) => ({ compliant: 'badge-pass', partial: 'badge-alert', gap: 'badge-block' }[s] || 'badge-muted')

  return (
    <div>
      <div className="page-header">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div>
            <div className="page-eyebrow">Compliance Officer View</div>
            <h1 className="page-title">Compliance Dashboard</h1>
            <p className="page-desc">Regulatory compliance posture, policy coverage, and audit readiness</p>
          </div>
          <button className="btn btn-secondary btn-sm" onClick={exportComplianceReport}>
            <Download size={14} /> Export Report
          </button>
        </div>
      </div>

      <div className="stats-row">
        {[
          { label: 'Compliant Frameworks', value: FRAMEWORKS.filter(f => f.status === 'compliant').length, icon: CheckCircle2, color: 'var(--green)', bg: 'var(--green-light)' },
          { label: 'Partial Compliance', value: FRAMEWORKS.filter(f => f.status === 'partial').length, icon: AlertTriangle, color: 'var(--amber)', bg: 'var(--amber-light)' },
          { label: 'Coverage Gaps', value: FRAMEWORKS.filter(f => f.status === 'gap').length, icon: Scale, color: 'var(--red)', bg: 'var(--red-light)' },
          { label: 'Policy Violations Today', value: stats?.policy_violations_today ?? '—', icon: FileCheck, color: 'var(--accent)', bg: 'var(--accent-light)' },
        ].map(({ label, value, icon: Icon, color, bg }) => (
          <div key={label} className="stat-card" style={{ '--stat-color': color, '--stat-bg': bg }}>
            <div className="stat-icon"><Icon size={18} /></div>
            <div className="stat-value">{value}</div>
            <div className="stat-label">{label}</div>
          </div>
        ))}
      </div>

      <div className="grid-2 mb-20">
        {/* Radar */}
        <div className="card">
          <div className="card-header"><span className="card-title">Compliance Radar</span></div>
          <ResponsiveContainer width="100%" height={220}>
            <RadarChart data={radarData}>
              <PolarGrid stroke={col.border || '#e0e2ed'} />
              <PolarAngleAxis dataKey="subject" tick={{ fontSize: 10, fill: 'var(--text-muted)' }} />
              <Radar name="Score" dataKey="score" stroke={col.accent || '#4f46e5'} fill={col.accent || '#4f46e5'} fillOpacity={0.15} strokeWidth={2} />
              <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 12 }} />
            </RadarChart>
          </ResponsiveContainer>
        </div>

        {/* Framework Scores */}
        <div className="card">
          <div className="card-header"><span className="card-title">Framework Scores</span></div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            {FRAMEWORKS.map(f => (
              <div key={f.key}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                  <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text)' }}>{f.label}</span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ fontSize: 12, fontWeight: 700, color: statusColor(f.status) }}>{f.score}%</span>
                    <span className={`badge ${statusBadge(f.status)}`}>{f.status}</span>
                  </div>
                </div>
                <div className="risk-bar">
                  <div className="risk-fill" style={{ width: f.score + '%', background: statusColor(f.status) }} />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Recent violations */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">Recent Audit Events</span>
          <button className="btn btn-ghost btn-sm" onClick={exportViolations}><Download size={14} /> Export</button>
        </div>
        <div className="table-wrap">
          <table>
            <thead><tr><th>Timestamp</th><th>Event Type</th><th>Actor</th><th>Action</th><th>Risk Level</th></tr></thead>
            <tbody>
              {violations.length === 0 && (
                <tr><td colSpan={5} style={{ textAlign: 'center', padding: 24, color: 'var(--text-muted)' }}>No audit events yet</td></tr>
              )}
              {violations.map(v => (
                <tr key={v.id}>
                  <td className="font-mono" style={{ fontSize: 11 }}>{new Date(v.timestamp).toLocaleString()}</td>
                  <td><span className="badge badge-info">{v.event_type}</span></td>
                  <td style={{ fontSize: 12 }}>{v.actor || '—'}</td>
                  <td style={{ fontSize: 12 }}>{v.action || '—'}</td>
                  <td>
                    {v.risk_level && <span className={`badge badge-${v.risk_level === 'high' ? 'block' : v.risk_level === 'medium' ? 'alert' : 'pass'}`}>{v.risk_level}</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
