import { useState, useEffect } from 'react'
import { BrowserRouter, Routes, Route, Navigate, useLocation } from 'react-router-dom'
import { AuthProvider, useAuth } from './context/AuthContext'
import { ThemeProvider } from './context/ThemeContext'
import { ToastProvider } from './context/ToastContext'
import { LanguageProvider } from './context/LanguageContext'
import Sidebar from './components/shared/Sidebar'
import Topbar from './components/shared/Topbar'
import CommandPalette from './components/shared/CommandPalette'
import ErrorBoundary from './components/shared/ErrorBoundary'
import LoginPage from './pages/LoginPage'
import ExecutiveDashboard from './pages/ExecutiveDashboard'
import EngineerDashboard from './pages/EngineerDashboard'
import ComplianceDashboard from './pages/ComplianceDashboard'
import PoliciesPage from './pages/PoliciesPage'
import ModelsPage from './pages/ModelsPage'
import AuditPage from './pages/AuditPage'
import SimulatePage from './pages/SimulatePage'
import LineagePage from './pages/LineagePage'
import AdversarialPage from './pages/AdversarialPage'
import AlertsPage from './pages/AlertsPage'
import SettingsPage from './pages/SettingsPage'
import PlaygroundPage from './pages/PlaygroundPage'
import SyntheticMediaPage from './pages/SyntheticMediaPage'
import UsersPage from './pages/UsersPage'
import { Lock } from 'lucide-react'

/* ── Auth guard ── */
function RequireAuth({ children }) {
  const { user } = useAuth()
  if (!user) return <Navigate to="/login" replace />
  return children
}

/* ── Role guard ── */
function RoleGuard({ roles, children }) {
  const { user } = useAuth()
  const role = user?.role || ''
  if (!roles.includes(role)) {
    return (
      <div className="role-denied">
        <div className="role-denied-icon"><Lock size={28} /></div>
        <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--text)' }}>
          Access Restricted
        </div>
        <div style={{ fontSize: 13, color: 'var(--text-muted)', maxWidth: 360, lineHeight: 1.65 }}>
          Your role <strong style={{ color: 'var(--text-dim)' }}>{user?.role_label || role}</strong> does not
          have permission to view this page. Contact your administrator if you believe this is incorrect.
        </div>
      </div>
    )
  }
  return children
}

/* ── Role-based home redirect ── */
function HomeRedirect() {
  const { user } = useAuth()
  const role = user?.role || ''
  if (role === 'ml_engineer') return <Navigate to="/engineer" replace />
  if (role === 'compliance_officer' || role === 'auditor') return <Navigate to="/compliance" replace />
  return <ExecutiveDashboard />
}

const ALL_ROLES        = ['super_admin','compliance_officer','ml_engineer','executive','auditor']
const ENGINEERING_ROLES = ['super_admin','ml_engineer']
const COMPLIANCE_ROLES  = ['super_admin','compliance_officer','auditor']
const EXECUTIVE_ROLES   = ['super_admin','executive']

/* ── App layout shell ── */
function AppLayout() {
  const [mobileOpen, setMobileOpen] = useState(false)
  const [cmdOpen, setCmdOpen] = useState(false)
  const location = useLocation()

  // Close sidebar on any navigation
  useEffect(() => { setMobileOpen(false) }, [location.pathname])

  // ── Cmd+K / Ctrl+K global shortcut ──
  useEffect(() => {
    const handler = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault()
        setCmdOpen(prev => !prev)
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [])

  // ── Cursor-follow glow on .card elements (dark mode only) ──
  useEffect(() => {
    const handleMove = (e) => {
      const card = e.target.closest('.card')
      if (!card) return
      const r = card.getBoundingClientRect()
      card.style.setProperty('--gx', `${e.clientX - r.left}px`)
      card.style.setProperty('--gy', `${e.clientY - r.top}px`)
    }
    document.addEventListener('mousemove', handleMove, { passive: true })
    return () => document.removeEventListener('mousemove', handleMove)
  }, [])

  return (
    <div className="app-layout">
      {/* Ambient risk aura — CSS controls visibility via html[data-risk] */}
      <div className="risk-aura" aria-hidden="true" />

      <Sidebar mobileOpen={mobileOpen} onClose={() => setMobileOpen(false)} />

      <main className="app-main">
        {/* Topbar owns the hamburger button on mobile — keeps them in sync */}
        <Topbar
          onMenuClick={() => setMobileOpen(prev => !prev)}
          mobileOpen={mobileOpen}
          onCmdK={() => setCmdOpen(true)}
        />
        <div className="app-content">
          <Routes>
            {/* Home — role-based redirect */}
            <Route path="/" element={<HomeRedirect />} />

            {/* Dashboards */}
            <Route path="/executive"  element={<RoleGuard roles={EXECUTIVE_ROLES}><ExecutiveDashboard /></RoleGuard>} />
            <Route path="/engineer"   element={<RoleGuard roles={ENGINEERING_ROLES}><EngineerDashboard /></RoleGuard>} />
            <Route path="/compliance" element={<RoleGuard roles={COMPLIANCE_ROLES}><ComplianceDashboard /></RoleGuard>} />

            {/* Governance */}
            <Route path="/policies" element={<RoleGuard roles={COMPLIANCE_ROLES}><PoliciesPage /></RoleGuard>} />
            <Route path="/models"   element={<RoleGuard roles={[...ENGINEERING_ROLES,...COMPLIANCE_ROLES]}><ModelsPage /></RoleGuard>} />
            <Route path="/audit"    element={<RoleGuard roles={COMPLIANCE_ROLES}><AuditPage /></RoleGuard>} />
            <Route path="/simulate" element={<RoleGuard roles={ENGINEERING_ROLES}><SimulatePage /></RoleGuard>} />

            {/* Advanced */}
            <Route path="/lineage"     element={<RoleGuard roles={ENGINEERING_ROLES}><LineagePage /></RoleGuard>} />
            <Route path="/adversarial" element={<RoleGuard roles={ENGINEERING_ROLES}><AdversarialPage /></RoleGuard>} />
            <Route path="/alerts"      element={<RoleGuard roles={[...ENGINEERING_ROLES,...COMPLIANCE_ROLES]}><AlertsPage /></RoleGuard>} />
            <Route path="/playground"     element={<PlaygroundPage />} />
            <Route path="/synthetic-media" element={<SyntheticMediaPage />} />
            <Route path="/settings"    element={<RoleGuard roles={['super_admin', 'ml_engineer', 'compliance_officer']}><SettingsPage /></RoleGuard>} />
            <Route path="/users"       element={<RoleGuard roles={['super_admin']}><UsersPage /></RoleGuard>} />

            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </div>
      </main>

      <CommandPalette open={cmdOpen} onClose={() => setCmdOpen(false)} />
    </div>
  )
}

export default function App() {
  return (
    <ErrorBoundary>
      <LanguageProvider>
        <ThemeProvider>
          <AuthProvider>
            <ToastProvider>
              <BrowserRouter>
                <Routes>
                  <Route path="/login" element={<LoginPage />} />
                  <Route path="/*"     element={<RequireAuth><AppLayout /></RequireAuth>} />
                </Routes>
              </BrowserRouter>
            </ToastProvider>
          </AuthProvider>
        </ThemeProvider>
      </LanguageProvider>
    </ErrorBoundary>
  )
}
