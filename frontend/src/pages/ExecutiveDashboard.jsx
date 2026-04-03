import { useState, useEffect } from 'react'
import { AreaChart, Area, XAxis, YAxis, Tooltip, CartesianGrid, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts'
import { dashboardAPI } from '../utils/api'
import { useToast } from '../context/ToastContext'
import { useTranslation } from '../context/LanguageContext'
import { SkeletonStat, SkeletonCard, Skeleton } from '../components/shared/Skeleton'
import { TrendingUp, CheckCircle2, AlertTriangle, XCircle, Shield, Activity } from 'lucide-react'

/* Read a CSS custom property value from :root as a real colour string.
   recharts passes colours as SVG presentation attributes, which do NOT
   resolve CSS variables — they need resolved hex/rgb values.           */
function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim()
}

const DEFAULT_COLORS = {
  accent: '#4f46e5',
  green: '#059669',
  amber: '#d97706',
  red: '#dc2626',
  purple: '#7c3aed',
  border: '#e0e2ed',
  bgCard: '#ffffff',
}

function useChartColors() {
  const [c, setC] = useState(DEFAULT_COLORS)
  useEffect(() => {
    const read = () => {
      const resolved = {
        accent: cssVar('--accent') || DEFAULT_COLORS.accent,
        green: cssVar('--green') || DEFAULT_COLORS.green,
        amber: cssVar('--amber') || DEFAULT_COLORS.amber,
        red: cssVar('--red') || DEFAULT_COLORS.red,
        purple: cssVar('--purple') || DEFAULT_COLORS.purple,
        border: cssVar('--border') || DEFAULT_COLORS.border,
        bgCard: cssVar('--bg-card') || DEFAULT_COLORS.bgCard,
      }
      setC(resolved)
    }
    read()
    /* Re-read when theme toggle fires (class change on <html>) */
    const obs = new MutationObserver(read)
    obs.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] })
    return () => obs.disconnect()
  }, [])
  return c
}

const StatCard = ({ label, value, icon: Icon, color, bg, delta }) => (
  <div className="stat-card fade-up" style={{ '--stat-color': color, '--stat-bg': bg }}>
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
      <div className="stat-icon"><Icon size={18} /></div>
      {delta != null && <span className={`stat-delta ${delta < 0 ? 'neg' : ''}`}>{delta > 0 ? '+' : ''}{delta}%</span>}
    </div>
    <div className="stat-value">{value ?? '—'}</div>
    <div className="stat-label">{label}</div>
  </div>
)

const TOOLTIP_STYLE = {
  background: 'var(--bg-card)',
  border: '1px solid var(--border)',
  borderRadius: 8,
  fontSize: 12,
}

// Custom tooltip for the Pie chart — inline styles ensure text is visible in both themes
const PieTooltip = ({ active, payload }) => {
  if (!active || !payload?.length) return null
  const { name, value } = payload[0]
  const fill = payload[0].payload.fill || '#4f46e5'
  return (
    <div style={{
      background: '#1a1d2e', color: '#e2e8f0',
      border: `2px solid ${fill}`,
      borderRadius: 8, padding: '6px 12px',
      fontSize: 12, fontWeight: 600, boxShadow: '0 4px 16px rgba(0,0,0,0.3)'
    }}>
      <span style={{ color: fill }}>{name}</span><br />
      <span style={{ color: '#fff', fontSize: 16 }}>{value}</span>
      <span style={{ color: '#94a3b8', fontSize: 10, marginLeft: 4 }}>inferences</span>
    </div>
  )
}

/* ── Mock data — used as initial state so charts render instantly ── */
const INITIAL_STATS = {
  total_inferences: 0, pass_rate: 1.0, blocked_count: 0,
  alert_count: 0, avg_risk_score: 0.0, active_models: 0,
  policy_violations_today: 0, fairness_issues_detected: 0,
}
const INITIAL_TREND = []
const INITIAL_BREAKDOWN = { PASS: 0, ALERT: 0, HUMAN_REVIEW: 0, BLOCK: 0 }
const INITIAL_COMPLIANCE = [
  { framework: 'EU AI Act', score: 0 },
  { framework: 'DPDP 2023', score: 0 },
  { framework: 'RBI Fairness', score: 0 },
]

export default function ExecutiveDashboard() {
  const [stats, setStats] = useState(INITIAL_STATS)
  const [trend, setTrend] = useState(INITIAL_TREND)
  const [breakdown, setBreakdown] = useState(INITIAL_BREAKDOWN)
  const [compliance, setCompliance] = useState(INITIAL_COMPLIANCE)
  const [loading, setLoading] = useState(true)
  const col = useChartColors()
  const toast = useToast()
  const { t } = useTranslation()

  useEffect(() => {
    const load = async () => {
      try {
        const [s, t, b, c] = await Promise.all([
          dashboardAPI.getStats(), dashboardAPI.getRiskTrend(),
          dashboardAPI.getEnforcementBreakdown(), dashboardAPI.getComplianceSummary(),
        ])
        if (s.data) {
          setStats(s.data)
          // Ambient risk aura — broadcast to app-layout via data attribute
          const r = s.data.avg_risk_score || 0
          document.documentElement.setAttribute('data-risk', r > 0.75 ? 'critical' : r > 0.45 ? 'high' : 'normal')
        }
        if (t.data) setTrend(t.data)
        if (b.data) setBreakdown(b.data)
        if (c.data) setCompliance(c.data)
      } catch (err) {
        console.error("Failed to load dashboard data:", err)
        toast.error("Network Error", "Unable to refresh dashboard metrics. Please check your connection.")
      } finally {
        setLoading(false)
      }
    }
    load()
    const iv = setInterval(load, 30000)
    
    // Live WebSocket connection
    const apiBase = import.meta.env.VITE_API_URL || (import.meta.env.PROD ? `${window.location.origin}/api/v1` : 'http://localhost:8000/api/v1')
    const wsBase = apiBase.replace(/^http/, 'ws').replace('/api/v1', '')
    const wsURL = `${wsBase}/api/v1/ws/stream`
    const ws = new WebSocket(wsURL)
    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data)
        if (msg.type === 'new_inference') load()
      } catch(e) {}
    }

    const onSim = () => load()
    window.addEventListener('kavachx:simulation-complete', onSim)
    
    return () => { 
      clearInterval(iv)
      window.removeEventListener('kavachx:simulation-complete', onSim)
      ws.close()
    }
  }, [])

  const displayStats = stats
  const displayTrend = trend
  const displayBreakdown = breakdown
  const displayCompliance = compliance



  const pieData = Object.entries(displayBreakdown).map(([k, v]) => ({ name: k, value: v }))
  const risk = displayStats?.avg_risk_score || 0
  const riskHex = risk > 0.75 ? (col.red || '#dc2626') : risk > 0.45 ? (col.amber || '#d97706') : (col.green || '#059669')

  const DECISION_HEX = {
    PASS: col.green || '#059669',
    ALERT: col.amber || '#d97706',
    HUMAN_REVIEW: col.purple || '#7c3aed',
    BLOCK: col.red || '#dc2626',
  }

  return (
    <div>
      <div className="page-header">
        <div className="page-eyebrow">{t('dashboard_title')}</div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div>
            <h1 className="page-title">{t('dashboard_title')}</h1>
            <p className="page-desc">{t('dashboard_desc')}</p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <button 
              onClick={() => { setLoading(true); window.dispatchEvent(new CustomEvent('kavachx:simulation-complete')); }}
              className="btn btn-secondary"
              style={{ padding: '6px 12px', fontSize: 12, display: 'flex', alignItems: 'center', gap: 6 }}
              title="Force Refresh Data"
            >
              <Activity size={14} className={loading ? 'animate-spin' : ''} />
              Manual Sync
            </button>
            <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
              <div className="status-ring">
                <div className="dot dot-green" />
              </div>
              <span style={{ fontSize: 10, color: 'var(--green)', fontFamily: 'var(--font-mono)', fontWeight: 700, letterSpacing: '.06em' }}>LIVE</span>
            </div>
          </div>
        </div>
      </div>

      <div className="stats-row" role="region" aria-label="Quick Statistics">
        {loading ? (
          <>
            <SkeletonStat />
            <SkeletonStat />
            <SkeletonStat />
            <SkeletonStat />
          </>
        ) : (
          <>
            <StatCard label={t('total_inferences')} value={displayStats?.total_inferences?.toLocaleString()} icon={TrendingUp} color="var(--accent)" bg="var(--accent-light)" />
            <StatCard label={t('pass_rate')} value={displayStats ? (displayStats.pass_rate * 100).toFixed(1) + '%' : '—'} icon={CheckCircle2} color="var(--green)" bg="var(--green-light)" delta={2.3} />
            <StatCard label={t('blocked_today')} value={displayStats?.blocked_count} icon={XCircle} color="var(--red)" bg="var(--red-light)" delta={-1} />
            <StatCard label={t('alerts_raised')} value={displayStats?.alert_count} icon={AlertTriangle} color="var(--amber)" bg="var(--amber-light)" />
          </>
        )}
      </div>

      {/* ── Bento grid: trend chart (8 cols, 2 rows) + gauge + pie stacked right ── */}
      <div className="bento-grid mb-20">
        {loading ? (
          <>
            <div className="bento-8 bento-row-2 card"><Skeleton className="skeleton-card" style={{ height: '100%' }} /></div>
            <div className="bento-4 card"><Skeleton className="skeleton-card" /></div>
            <div className="bento-4 card"><Skeleton className="skeleton-card" /></div>
          </>
        ) : (
          <>
            {/* ── Risk Trend Area Chart — main wide cell ── */}
            <div className="bento-8 bento-row-2 card" style={{ display: 'flex', flexDirection: 'column' }}>
              <div className="card-header">
                <span className="card-title">Risk Score Trend (24h)</span>
                <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>Rolling average</span>
              </div>
              {col.accent ? (
                <div style={{ flex: 1, minHeight: 0 }}>
                  <ResponsiveContainer width="100%" height="100%" minHeight={220}>
                    <AreaChart data={displayTrend}>
                      <defs>
                        <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor={col.accent} stopOpacity={0.25} />
                          <stop offset="95%" stopColor={col.accent} stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke={col.border || '#e0e2ed'} />
                      <XAxis dataKey="hour" tick={{ fontSize: 10, fill: 'var(--text-muted)' }} />
                      <YAxis domain={[0, 1]} tick={{ fontSize: 10, fill: 'var(--text-muted)' }} />
                      <Tooltip contentStyle={TOOLTIP_STYLE} />
                      <Area type="monotone" dataKey="avg_risk"
                        stroke={col.accent} strokeWidth={2} fill="url(#riskGrad)" />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              ) : (
                <div className="empty" style={{ flex: 1 }}>
                  <div className="empty-title">No trend data yet</div>
                  <div className="empty-desc">Run some inferences to populate the trend chart.</div>
                </div>
              )}
            </div>

            {/* ── Risk Gauge ── */}
            <div className="bento-4 card">
              <div className="card-header"><span className="card-title">{t('risk_score')}</span></div>
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 10, padding: '4px 0' }}>
                <div style={{ position: 'relative', width: 110, height: 110 }}>
                  <svg viewBox="0 0 120 120" style={{ transform: 'rotate(-90deg)', width: '100%', height: '100%' }}>
                    <circle cx="60" cy="60" r="50" fill="none" stroke={col.border || '#e0e2ed'} strokeWidth="9" />
                    <circle cx="60" cy="60" r="50" fill="none" stroke={riskHex} strokeWidth="9"
                      strokeDasharray={`${risk * 314} 314`} strokeLinecap="round"
                      style={{ transition: 'stroke-dasharray .8s ease', filter: `drop-shadow(0 0 6px ${riskHex}66)` }} />
                  </svg>
                  <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
                    <span style={{ fontSize: 24, fontWeight: 800, color: riskHex, fontFamily: 'var(--font-mono)', fontFeatureSettings: "'tnum' 1" }}>
                      {(risk * 100).toFixed(0)}
                    </span>
                    <span style={{ fontSize: 8, color: riskHex, fontWeight: 700, letterSpacing: '.1em' }}>
                      {risk > 0.75 ? 'HIGH' : risk > 0.45 ? 'MEDIUM' : 'LOW'}
                    </span>
                  </div>
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', textAlign: 'center' }}>Avg across all inferences</div>
                <div style={{ width: '100%', borderTop: '1px solid var(--border)', paddingTop: 10, display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Active Models</span>
                  <span style={{ fontSize: 11, fontWeight: 700, fontFamily: 'var(--font-mono)' }}>{displayStats?.active_models ?? '—'}</span>
                </div>
              </div>
            </div>

            {/* ── Enforcement Pie ── */}
            <div className="bento-4 card">
              <div className="card-header"><span className="card-title">Enforcement Decisions</span></div>
              {col.green ? (
                <>
                  <ResponsiveContainer width="100%" height={130}>
                    <PieChart>
                      <Pie data={pieData} cx="50%" cy="50%" innerRadius={35} outerRadius={55} dataKey="value" stroke="none">
                        {pieData.map(e => (
                          <Cell key={e.name} fill={DECISION_HEX[e.name] || '#8899b4'} />
                        ))}
                      </Pie>
                      <Tooltip content={<PieTooltip />} />
                    </PieChart>
                  </ResponsiveContainer>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '5px 12px', justifyContent: 'center' }}>
                    {Object.entries(DECISION_HEX).map(([k, c]) => {
                      const count = displayBreakdown[k] ?? 0
                      return (
                        <div key={k} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 10.5 }}>
                          <div style={{ width: 7, height: 7, borderRadius: 2, background: c, flexShrink: 0 }} />
                          <span style={{ color: 'var(--text-muted)' }}>{k}</span>
                          <span style={{ color: c, fontWeight: 700, fontFamily: 'var(--font-mono)' }}>{count}</span>
                        </div>
                      )
                    })}
                  </div>
                </>
              ) : (
                <Skeleton className="skeleton-card" />
              )}
            </div>
          </>
        )}
      </div>

      {/* ── Governance status row — full width ── */}
      <div className="card mb-20">
        <div className="card-header"><span className="card-title">Governance Status</span></div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 10 }}>
          {loading ? (
            [1, 2, 3].map(i => <Skeleton key={i} className="skeleton-card" style={{ height: 52 }} />)
          ) : (
            <>
              {[
                { label: 'Active Models', value: displayStats?.active_models, icon: Shield, color: 'var(--accent)' },
                { label: 'Violations Today', value: displayStats?.policy_violations_today, icon: AlertTriangle, color: 'var(--amber)' },
                { label: 'Fairness Issues', value: displayStats?.fairness_issues_detected, icon: Activity, color: 'var(--purple)' },
              ].map(({ label, value, icon: Icon, color }) => (
                <div key={label} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 14px', background: 'var(--bg-elevated)', borderRadius: 8 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <Icon size={14} style={{ color }} />
                    <span style={{ fontSize: 12, color: 'var(--text-dim)' }}>{label}</span>
                  </div>
                  <span style={{ fontSize: 16, fontWeight: 800, color, fontFamily: 'var(--font-mono)', fontFeatureSettings: "'tnum' 1" }}>{value ?? '—'}</span>
                </div>
              ))}
              <div style={{ padding: '10px 14px', background: 'var(--bg-elevated)', borderRadius: 8 }}>
                <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 8, fontWeight: 600, letterSpacing: '.05em', textTransform: 'uppercase' }}>Compliance</div>
                {displayCompliance.slice(0, 3).map(c => (
                  <div key={c.framework} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                    <span style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>{c.framework}</span>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <div style={{ width: 50, height: 3, background: 'var(--border)', borderRadius: 2 }}>
                        <div style={{ width: c.score + '%', height: '100%', background: c.score > 80 ? 'var(--green)' : 'var(--amber)', borderRadius: 2 }} />
                      </div>
                      <span style={{ fontSize: 10.5, fontWeight: 700, fontFamily: 'var(--font-mono)', minWidth: 28, textAlign: 'right' }}>{c.score}%</span>
                    </div>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  )
}
