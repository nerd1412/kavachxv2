import { createContext, useContext, useState, useEffect, useCallback } from 'react'
import { api } from '../utils/api'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    try { return JSON.parse(localStorage.getItem('kavachx_user')) } catch { return null }
  })
  const [setupStatus, setSetupStatus] = useState(null)  // null=loading, {setup_required, bootstrap_token_active}

  // Check setup status on mount
  useEffect(() => {
    api.get('/auth/setup-status')
      .then(r => setSetupStatus(r.data))
      .catch(() => setSetupStatus({ setup_required: false, bootstrap_token_active: false }))
  }, [])

  const login = async (email, password) => {
    const r = await api.post('/auth/login', { email, password })
    const { access_token, user: u } = r.data
    localStorage.setItem('kavachx_token', access_token)
    localStorage.setItem('kavachx_user', JSON.stringify(u))
    setUser(u)
    setSetupStatus(prev => ({ ...prev, setup_required: false }))
    return u
  }

  const bootstrap = async ({ name, email, password, bootstrap_token }) => {
    const r = await api.post('/auth/bootstrap', { name, email, password, bootstrap_token })
    const { access_token, user: u } = r.data
    localStorage.setItem('kavachx_token', access_token)
    localStorage.setItem('kavachx_user', JSON.stringify(u))
    setUser(u)
    setSetupStatus({ setup_required: false, bootstrap_token_active: false })
    return u
  }

  const logout = useCallback(() => {
    localStorage.removeItem('kavachx_token')
    localStorage.removeItem('kavachx_user')
    setUser(null)
  }, [])

  const hasPermission = useCallback((perm) => {
    if (!user) return false
    const perms = user.permissions || []
    return perms.includes('*') || perms.includes(perm)
  }, [user])

  return (
    <AuthContext.Provider value={{ user, setupStatus, login, bootstrap, logout, hasPermission }}>
      {children}
    </AuthContext.Provider>
  )
}

export const useAuth = () => useContext(AuthContext)
