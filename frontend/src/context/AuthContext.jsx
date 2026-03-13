import { createContext, useContext, useState, useEffect } from 'react'
import { api } from '../utils/api'

const AuthContext = createContext(null)

/* ── Hardcoded demo accounts (fallback when backend is offline) ── */
const HARDCODED_DEMOS = [
  { email: 'admin@kavachx.ai',      password: 'Admin@123',   name: 'Admin User',   role: 'super_admin',        role_label: 'Super Admin',        avatar: 'AU', permissions: ['*'] },
  { email: 'compliance@kavachx.ai', password: 'Comply@123',  name: 'Priya Sharma', role: 'compliance_officer', role_label: 'Compliance Officer', avatar: 'PS', permissions: ['dashboard:read','policies:read','policies:write','policies:delete','audit:read','audit:export','models:read','governance:read','reports:read','alerts:read','alerts:manage'] },
  { email: 'engineer@kavachx.ai',   password: 'Eng@12345',   name: 'Arjun Dev',    role: 'ml_engineer',        role_label: 'ML Engineer',        avatar: 'AD', permissions: ['dashboard:read','models:read','models:write','models:register','governance:read','governance:evaluate','audit:read','policies:read','simulate:run','alerts:read'] },
  { email: 'exec@kavachx.ai',       password: 'Exec@1234',   name: 'Kavita Menon', role: 'executive',          role_label: 'Executive',          avatar: 'KM', permissions: ['dashboard:read','reports:read','audit:read','models:read','policies:read','alerts:read'] },
  { email: 'auditor@kavachx.ai',    password: 'Audit@123',   name: 'Raj Verma',    role: 'auditor',            role_label: 'External Auditor',   avatar: 'RV', permissions: ['audit:read','audit:export','policies:read','models:read','reports:read','dashboard:read'] },
]

/* ── Registered users store (in-memory + localStorage) ── */
function getRegisteredUsers() {
  try { return JSON.parse(localStorage.getItem('kavachx_registered') || '[]') } catch { return [] }
}
function saveRegisteredUsers(users) {
  localStorage.setItem('kavachx_registered', JSON.stringify(users))
}

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    try { return JSON.parse(localStorage.getItem('kavachx_user')) } catch { return null }
  })
  const [demoAccounts, setDemoAccounts] = useState(HARDCODED_DEMOS)

  /* Try fetching live demo accounts from backend, fall back silently */
  useEffect(() => {
    api.get('/auth/demo-accounts')
      .then(r => { if (r.data?.demo_accounts?.length) setDemoAccounts(r.data.demo_accounts) })
      .catch(() => { /* use hardcoded fallback */ })
  }, [])

  /* ── Login: try backend, fall back to local credential check ── */
  const login = async (email, password) => {
    // 1. Try real backend
    try {
      const r = await api.post('/auth/login', { email, password })
      const { access_token, user: u } = r.data
      localStorage.setItem('kavachx_token', access_token)
      localStorage.setItem('kavachx_user', JSON.stringify(u))
      setUser(u)
      return u
    } catch (backendErr) {
      // If it's a 401, backend is up but creds are wrong — re-throw
      if (backendErr.response?.status === 401) throw backendErr
    }

    // 2. Fall back to hardcoded demos + registered users
    const allLocal = [...HARDCODED_DEMOS, ...getRegisteredUsers()]
    const match = allLocal.find(a => a.email?.toLowerCase() === email.toLowerCase() && a.password === password)
    if (!match) {
      const err = new Error('Invalid email or password')
      err.response = { status: 401, data: { detail: 'Invalid email or password' } }
      throw err
    }
    const u = {
      id: match.id || `user-local-${Date.now()}`,
      name: match.name,
      email: match.email,
      role: match.role,
      role_label: match.role_label,
      permissions: match.permissions || [],
      avatar: match.avatar || match.name?.[0]?.toUpperCase() || '?',
    }
    localStorage.setItem('kavachx_user', JSON.stringify(u))
    // No real token needed for local auth
    localStorage.setItem('kavachx_token', 'local-session-' + Date.now())
    setUser(u)
    return u
  }

  /* ── Quick login (demo card click) ── */
  const quickLogin = async (acc) => {
    return login(acc.email, acc.password)
  }

  /* ── Register new user (always local, no backend needed) ── */
  const register = async ({ name, email, password, role = 'ml_engineer' }) => {
    const allLocal = [...HARDCODED_DEMOS, ...getRegisteredUsers()]
    if (allLocal.find(a => a.email?.toLowerCase() === email.toLowerCase())) {
      throw new Error('An account with this email already exists.')
    }
    const ROLE_PERMS = {
      ml_engineer:        ['dashboard:read','models:read','models:write','models:register','governance:read','governance:evaluate','audit:read','policies:read','simulate:run','alerts:read'],
      compliance_officer: ['dashboard:read','policies:read','policies:write','policies:delete','audit:read','audit:export','models:read','governance:read','reports:read','alerts:read'],
      executive:          ['dashboard:read','reports:read','audit:read','models:read','policies:read','alerts:read'],
      auditor:            ['audit:read','audit:export','policies:read','models:read','reports:read','dashboard:read'],
    }
    const ROLE_LABELS = {
      ml_engineer: 'ML Engineer', compliance_officer: 'Compliance Officer',
      executive: 'Executive', auditor: 'External Auditor',
    }
    const newUser = {
      id: `user-reg-${Date.now()}`,
      name, email, password, role,
      role_label: ROLE_LABELS[role] || role,
      permissions: ROLE_PERMS[role] || [],
      avatar: name?.[0]?.toUpperCase() || '?',
    }
    const existing = getRegisteredUsers()
    saveRegisteredUsers([...existing, newUser])
    return login(email, password)
  }

  const logout = () => {
    localStorage.removeItem('kavachx_token')
    localStorage.removeItem('kavachx_user')
    setUser(null)
  }

  const hasPermission = (perm) => {
    if (!user) return false
    const perms = user.permissions || []
    return perms.includes('*') || perms.includes(perm)
  }

  return (
    <AuthContext.Provider value={{ user, login, quickLogin, logout, register, hasPermission, demoAccounts }}>
      {children}
    </AuthContext.Provider>
  )
}

export const useAuth = () => useContext(AuthContext)
