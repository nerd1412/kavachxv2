import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { useTheme } from '../context/ThemeContext'
import {
  Shield, Sun, Moon, Eye, EyeOff, ArrowRight,
  ChevronRight, UserPlus, LogIn, CheckCircle
} from 'lucide-react'

/* Role quick-login card colors & descriptions */
const ROLE_META = {
  super_admin:        { color: '#f87171', bg: 'rgba(248,113,113,0.10)', icon: '🛡️', desc: 'Full system access' },
  compliance_officer: { color: '#818cf8', bg: 'rgba(129,140,248,0.10)', icon: '📋', desc: 'Policy & audit management' },
  ml_engineer:        { color: '#34d399', bg: 'rgba(52,211,153,0.10)', icon: '⚙️', desc: 'Models & simulations' },
  executive:          { color: '#fbbf24', bg: 'rgba(251,191,36,0.10)', icon: '📊', desc: 'Dashboard & reports' },
  auditor:            { color: '#a78bfa', bg: 'rgba(167,139,250,0.10)', icon: '🔍', desc: 'Read-only audit access' },
}

const REGISTER_ROLES = [
  { value: 'ml_engineer',        label: 'ML Engineer' },
  { value: 'compliance_officer', label: 'Compliance Officer' },
  { value: 'executive',          label: 'Executive' },
  { value: 'auditor',            label: 'External Auditor' },
]

export default function LoginPage() {
  const { login, register, demoAccounts } = useAuth()
  const { dark, toggle } = useTheme()
  const nav = useNavigate()
  const [tab, setTab] = useState('login') // 'login' | 'register'

  // Login state
  const [email, setEmail]     = useState('')
  const [password, setPassword] = useState('')
  const [showPw, setShowPw]   = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError]     = useState('')

  // Register state
  const [regName,  setRegName]   = useState('')
  const [regEmail, setRegEmail]  = useState('')
  const [regPw,    setRegPw]     = useState('')
  const [regPw2,   setRegPw2]    = useState('')
  const [regRole,  setRegRole]   = useState('ml_engineer')
  const [regShow,  setRegShow]   = useState(false)
  const [regSuccess, setRegSuccess] = useState(false)

  const submit = async (e) => {
    e?.preventDefault()
    setLoading(true); setError('')
    try { await login(email, password); nav('/') }
    catch (err) { setError(err.response?.data?.detail || err.message || 'Login failed') }
    finally { setLoading(false) }
  }

  const quickLogin = async (acc) => {
    setError(''); setLoading(true)
    try { await login(acc.email, acc.password); nav('/') }
    catch { setError('Quick login failed. Try again.') }
    finally { setLoading(false) }
  }

  const submitRegister = async (e) => {
    e?.preventDefault()
    if (!regName.trim() || !regEmail.trim() || !regPw.trim()) return setError('Please fill in all fields.')
    if (regPw !== regPw2) return setError('Passwords do not match.')
    if (regPw.length < 6) return setError('Password must be at least 6 characters.')
    setLoading(true); setError('')
    try {
      await register({ name: regName.trim(), email: regEmail.trim(), password: regPw, role: regRole })
      nav('/')
    } catch (err) {
      setError(err.message || 'Registration failed')
    } finally { setLoading(false) }
  }

  return (
    <div className="login-page">
      {/* Theme toggle */}
      <button className="topbar-btn" onClick={toggle}
        style={{ position: 'fixed', top: 16, right: 16, zIndex: 10 }}>
        {dark ? <Sun size={15} /> : <Moon size={15} />}
      </button>

      <div className="login-card fade-up">
        {/* Brand */}
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 11, marginBottom: 26, paddingTop: 4 }}>
          <svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' width='38' height='38' fill='url(#grad)' stroke='none' style={{ flexShrink: 0, marginTop: 2 }}>
            <defs>
              <linearGradient id='grad' x1='0%' y1='0%' x2='100%' y2='100%'>
                <stop offset='0%' stopColor='#a5b4fc' />
                <stop offset='50%' stopColor='#4f46e5' />
                <stop offset='100%' stopColor='#1e1b4b' />
              </linearGradient>
            </defs>
            <path d='M12 1 L1 5 V12 C1 18 6 22.5 12 24 C18 22.5 23 18 23 12 V5 Z'/>
          </svg>
          <div>
            <div style={{ fontSize: 21, fontWeight: 800, letterSpacing: '-.04em' }}>KavachX</div>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', letterSpacing: '.08em' }}>
              AI GOVERNANCE PLATFORM
            </div>
          </div>
        </div>

        {/* Tab switcher */}
        <div style={{
          display: 'flex', gap: 0, marginBottom: 22,
          background: 'var(--bg-elevated)',
          borderRadius: 9, padding: 3,
          border: '1px solid var(--border)',
        }}>
          {[
            { id: 'login',    icon: LogIn,     label: 'Sign In' },
            { id: 'register', icon: UserPlus,  label: 'Register' },
          ].map(t => (
            <button key={t.id} onClick={() => { setTab(t.id); setError('') }}
              style={{
                flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6,
                padding: '7px 12px', borderRadius: 7, border: 'none', cursor: 'pointer',
                fontSize: 12.5, fontWeight: 600, fontFamily: 'var(--font)',
                transition: 'all .13s',
                background: tab === t.id ? 'var(--bg-card)' : 'transparent',
                color: tab === t.id ? 'var(--text)' : 'var(--text-muted)',
                boxShadow: tab === t.id ? 'var(--shadow-xs)' : 'none',
              }}>
              <t.icon size={13} />
              {t.label}
            </button>
          ))}
        </div>

        {error && (
          <div className="alert alert-error" style={{ marginBottom: 14 }}>
            <span style={{ fontSize: 12.5 }}>{error}</span>
          </div>
        )}

        {/* ── LOGIN TAB ── */}
        {tab === 'login' && (
          <>
            <form onSubmit={submit} style={{ display: 'flex', flexDirection: 'column', gap: 13 }}>
              <div className="form-group">
                <label className="form-label">Email</label>
                <input className="form-input" type="email" placeholder="you@organization.com"
                  value={email} onChange={e => setEmail(e.target.value)} required autoComplete="email" />
              </div>
              <div className="form-group">
                <label className="form-label">Password</label>
                <div style={{ position: 'relative' }}>
                  <input className="form-input" type={showPw ? 'text' : 'password'}
                    placeholder="••••••••" value={password}
                    onChange={e => setPassword(e.target.value)} required
                    style={{ paddingRight: 38 }} />
                  <button type="button" onClick={() => setShowPw(!showPw)}
                    style={{ position: 'absolute', right: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)', background: 'none', border: 'none', cursor: 'pointer' }}>
                    {showPw ? <EyeOff size={15} /> : <Eye size={15} />}
                  </button>
                </div>
              </div>
              <button type="submit" className="btn btn-primary w-full" disabled={loading}
                style={{ justifyContent: 'center', marginTop: 4, padding: '10px 16px' }}>
                {loading
                  ? <><span className="spinner" style={{ width: 14, height: 14, borderWidth: 2 }} /> Signing in...</>
                  : <><span>Sign In</span><ArrowRight size={14} /></>
                }
              </button>
            </form>

            {/* Quick demo roles */}
            {demoAccounts.length > 0 && (
              <div style={{ marginTop: 22 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
                  <div style={{ flex: 1, height: 1, background: 'var(--border)' }} />
                  <span style={{ fontSize: 10.5, color: 'var(--text-muted)', fontWeight: 500, whiteSpace: 'nowrap' }}>
                    Demo roles — click to sign in
                  </span>
                  <div style={{ flex: 1, height: 1, background: 'var(--border)' }} />
                </div>
                <div className="grid-2" style={{ gap: 7 }}>
                  {demoAccounts.map(acc => {
                    const meta = ROLE_META[acc.role] || { color: '#6366f1', bg: 'rgba(99,102,241,0.10)', icon: '👤', desc: acc.role }
                    return (
                      <button
                        key={acc.email}
                        onClick={() => quickLogin(acc)}
                        disabled={loading}
                        style={{
                          textAlign: 'left',
                          padding: '10px 12px',
                          border: `1px solid ${meta.color}28`,
                          borderRadius: 9,
                          background: meta.bg,
                          cursor: 'pointer',
                          transition: 'all .12s',
                          display: 'flex',
                          alignItems: 'center',
                          gap: 9,
                          opacity: loading ? 0.5 : 1,
                        }}
                        onMouseEnter={e => e.currentTarget.style.borderColor = meta.color + '60'}
                        onMouseLeave={e => e.currentTarget.style.borderColor = meta.color + '28'}
                      >
                        <span style={{ fontSize: 18, lineHeight: 1, flexShrink: 0 }}>{meta.icon}</span>
                        <div style={{ minWidth: 0 }}>
                          <div style={{ fontSize: 12, fontWeight: 700, color: meta.color, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                            {acc.role_label || acc.name}
                          </div>
                          <div style={{ fontSize: 10, color: 'var(--text-muted)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                            {acc.name}
                          </div>
                        </div>
                      </button>
                    )
                  })}
                </div>
              </div>
            )}
          </>
        )}

        {/* ── REGISTER TAB ── */}
        {tab === 'register' && (
          <form onSubmit={submitRegister} style={{ display: 'flex', flexDirection: 'column', gap: 13 }}>
            <div className="form-group">
              <label className="form-label">Full Name</label>
              <input className="form-input" type="text" placeholder="Your full name"
                value={regName} onChange={e => setRegName(e.target.value)} required />
            </div>
            <div className="form-group">
              <label className="form-label">Email Address</label>
              <input className="form-input" type="email" placeholder="you@organization.com"
                value={regEmail} onChange={e => setRegEmail(e.target.value)} required />
            </div>

            {/* Role picker */}
            <div className="form-group">
              <label className="form-label">Role</label>
              <div className="grid-2" style={{ gap: 6 }}>
                {REGISTER_ROLES.map(r => {
                  const meta = ROLE_META[r.value] || {}
                  return (
                    <button key={r.value} type="button"
                      onClick={() => setRegRole(r.value)}
                      style={{
                        padding: '8px 10px',
                        border: `1px solid ${regRole === r.value ? (meta.color || 'var(--accent)') : 'var(--border)'}`,
                        borderRadius: 8,
                        background: regRole === r.value ? (meta.bg || 'var(--accent-light)') : 'var(--bg-elevated)',
                        cursor: 'pointer', transition: 'all .12s',
                        textAlign: 'left', fontFamily: 'var(--font)',
                      }}>
                      <div style={{ fontSize: 11.5, fontWeight: 600, color: regRole === r.value ? (meta.color || 'var(--accent)') : 'var(--text-dim)' }}>
                        {r.label}
                      </div>
                    </button>
                  )
                })}
              </div>
            </div>

            <div className="form-group">
              <label className="form-label">Password</label>
              <div style={{ position: 'relative' }}>
                <input className="form-input" type={regShow ? 'text' : 'password'}
                  placeholder="Min. 6 characters" value={regPw}
                  onChange={e => setRegPw(e.target.value)} required minLength={6}
                  style={{ paddingRight: 38 }} />
                <button type="button" onClick={() => setRegShow(!regShow)}
                  style={{ position: 'absolute', right: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)', background: 'none', border: 'none', cursor: 'pointer' }}>
                  {regShow ? <EyeOff size={15} /> : <Eye size={15} />}
                </button>
              </div>
            </div>
            <div className="form-group">
              <label className="form-label">Confirm Password</label>
              <input className="form-input" type={regShow ? 'text' : 'password'}
                placeholder="Repeat password" value={regPw2}
                onChange={e => setRegPw2(e.target.value)} required />
              {regPw2 && regPw !== regPw2 && (
                <span style={{ fontSize: 11, color: 'var(--red)' }}>Passwords do not match</span>
              )}
            </div>

            <button type="submit" className="btn btn-primary w-full" disabled={loading || (regPw2 && regPw !== regPw2)}
              style={{ justifyContent: 'center', marginTop: 4, padding: '10px 16px' }}>
              {loading
                ? <><span className="spinner" style={{ width: 14, height: 14, borderWidth: 2 }} /> Creating account...</>
                : <><UserPlus size={14} /><span>Create Account</span></>
              }
            </button>

            <p style={{ fontSize: 11, color: 'var(--text-muted)', textAlign: 'center', lineHeight: 1.6 }}>
              Note: Super Admin accounts cannot be self-registered.<br />
              Contact your administrator for elevated access.
            </p>
          </form>
        )}

        {/* Footer */}
        <div style={{ marginTop: 20, fontSize: 10.5, color: 'var(--text-muted)', textAlign: 'center', lineHeight: 1.6 }}>
          KavachX · India-first AI Governance &nbsp;·&nbsp;{' '}
          <span style={{ color: 'var(--accent-2)' }}>EU AI Act</span> &amp;{' '}
          <span style={{ color: 'var(--accent-2)' }}>DPDP 2023</span> ready
        </div>
      </div>
    </div>
  )
}
