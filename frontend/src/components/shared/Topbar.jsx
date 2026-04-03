import { useLocation } from 'react-router-dom'
import { useTheme } from '../../context/ThemeContext'
import { useAuth } from '../../context/AuthContext'
import { ChevronRight, Sun, Moon, Bell, Menu, X } from 'lucide-react'

const TITLES = {
  '/':            ['Dashboards', 'Executive View'],
  '/executive':   ['Dashboards', 'Executive View'],
  '/engineer':    ['Dashboards', 'ML Engineer'],
  '/compliance':  ['Dashboards', 'Compliance'],
  '/policies':    ['Governance', 'Policies'],
  '/models':      ['Governance', 'Model Registry'],
  '/audit':       ['Governance', 'Audit Logs'],
  '/simulate':    ['Governance', 'Simulate'],
  '/lineage':     ['Advanced', 'Data Lineage'],
  '/adversarial': ['Advanced', 'Adversarial Tests'],
  '/alerts':      ['Advanced', 'Alerts'],
  '/settings':    ['Advanced', 'Settings & API Keys'],
  '/playground':      ['Governance', 'Kavach Playground'],
  '/synthetic-media': ['BASCG P3',  'Deepfake Verifier'],
}

export default function Topbar({ onMenuClick, mobileOpen, onCmdK }) {
  const { dark, toggle } = useTheme()
  const { user } = useAuth()
  const loc = useLocation()
  const [section, title] = TITLES[loc.pathname] || ['', 'KavachX']

  return (
    <header className="topbar">
      {/* Mobile hamburger — rendered inside topbar so it's always in sync with sidebar state */}
      <button
        className="mobile-menu-btn-inline"
        onClick={onMenuClick}
        aria-label={mobileOpen ? 'Close navigation' : 'Open navigation'}
      >
        {mobileOpen ? <X size={17} /> : <Menu size={17} />}
      </button>

      {/* Mobile brand mark */}
      <div className="topbar-mobile-brand" style={{ alignItems: 'flex-start' }}>
          <svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' width='20' height='20' fill='url(#grad)' stroke='none' style={{ flexShrink: 0, marginTop: 2 }}>
            <defs>
              <linearGradient id='grad' x1='0%' y1='0%' x2='100%' y2='100%'>
                <stop offset='0%' stopColor='#a5b4fc' />
                <stop offset='50%' stopColor='#4f46e5' />
                <stop offset='100%' stopColor='#1e1b4b' />
              </linearGradient>
            </defs>
            <path d='M12 1 L1 5 V12 C1 18 6 22.5 12 24 C18 22.5 23 18 23 12 V5 Z'/>
          </svg>
        <span style={{ fontSize: 13.5, fontWeight: 800, letterSpacing: '-0.025em', color: 'var(--text)' }}>
          KavachX
        </span>
      </div>

      {/* ⌘K search trigger */}
      <button
        className="topbar-cmd-trigger"
        onClick={onCmdK}
        title="Open command palette (⌘K)"
        aria-label="Open command palette"
      >
        <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>Search…</span>
        <kbd style={{ fontSize: 9.5, padding: '1px 5px', background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 4, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', lineHeight: 1.7, flexShrink: 0 }}>⌘K</kbd>
      </button>

      {/* Breadcrumb */}
      <div className="topbar-breadcrumb">
        {section && (
          <>
            <span style={{ flexShrink: 0, fontSize: 12 }}>{section}</span>
            <ChevronRight size={11} style={{ opacity: 0.35, flexShrink: 0 }} />
          </>
        )}
        <span className="topbar-breadcrumb-active truncate">{title}</span>
      </div>

      {/* Actions */}
      <div className="topbar-actions">
        {/* System health — TEE / NAEL / Ledger */}
        <div className="sys-health" title="TEE · NAEL · Sovereign Ledger">
          <div className="sys-health-dot ok" title="TEE Attestation" />
          <div className="sys-health-dot ok" title="NAEL Licensing" />
          <div className="sys-health-dot ok" title="Sovereign Ledger" />
          <span className="sys-health-label" style={{ fontSize: 9, marginLeft: 2 }}>SYS</span>
        </div>

        <button
          className="topbar-btn"
          onClick={toggle}
          title={dark ? 'Switch to light mode' : 'Switch to dark mode'}
          aria-label="Toggle theme"
        >
          {dark ? <Sun size={14} /> : <Moon size={14} />}
        </button>

        <button className="topbar-btn" title="Notifications" aria-label="Notifications">
          <Bell size={14} />
        </button>

        {user && (
          <div style={{
            display: 'flex', alignItems: 'center', gap: 8,
            marginLeft: 4, paddingLeft: 12,
            borderLeft: '1px solid var(--border)',
          }}>
            <div style={{
              width: 28, height: 28,
              borderRadius: 7,
              background: 'linear-gradient(135deg, #4f46e5, #7c3aed)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: 10.5, fontWeight: 700, color: '#fff',
              flexShrink: 0,
            }}>
              {(user.avatar || user.name?.[0] || '?').toUpperCase()}
            </div>
            <div
              className="topbar-user-text"
              style={{ display: 'flex', flexDirection: 'column' }}
            >
              <span style={{ fontSize: 12, fontWeight: 600, lineHeight: 1.2, whiteSpace: 'nowrap', color: 'var(--text)' }}>
                {user.name}
              </span>
              <span style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', whiteSpace: 'nowrap' }}>
                {user.role_label}
              </span>
            </div>
          </div>
        )}
      </div>
    </header>
  )
}
