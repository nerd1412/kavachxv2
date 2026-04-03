import { useEffect, useState, useCallback } from 'react'
import { api } from '../utils/api'
import { useAuth } from '../context/AuthContext'
import {
  UserPlus, Search, RefreshCw, Edit2, KeyRound, UserX, UserCheck,
  ChevronLeft, ChevronRight, X, Eye, EyeOff, Check, Shield,
  Users as UsersIcon,
} from 'lucide-react'

const ROLES = [
  { value: 'super_admin',         label: 'Super Admin',        color: 'var(--accent)' },
  { value: 'compliance_officer',  label: 'Compliance Officer', color: 'var(--amber)' },
  { value: 'ml_engineer',         label: 'ML Engineer',        color: 'var(--green)' },
  { value: 'executive',           label: 'Executive',          color: 'var(--text-dim)' },
  { value: 'auditor',             label: 'External Auditor',   color: '#a78bfa' },
]

const PAGE_SIZE = 15

function RoleBadge({ role }) {
  const r = ROLES.find(x => x.value === role) || { label: role, color: 'var(--text-muted)' }
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 4,
      padding: '2px 8px', borderRadius: 4,
      fontSize: 11, fontWeight: 600, fontFamily: 'var(--font-mono)',
      background: r.color + '18', color: r.color,
      border: `1px solid ${r.color}33`,
    }}>
      {r.label}
    </span>
  )
}

function StatusBadge({ active }) {
  return (
    <span className={active ? 'badge-pass' : 'badge-block'} style={{ fontSize: 11 }}>
      {active ? 'Active' : 'Inactive'}
    </span>
  )
}

function PasswordInput({ value, onChange, placeholder }) {
  const [show, setShow] = useState(false)
  return (
    <div style={{ position: 'relative' }}>
      <input className="form-input" type={show ? 'text' : 'password'}
        placeholder={placeholder || '••••••••••••'}
        value={value} onChange={e => onChange(e.target.value)}
        style={{ paddingRight: 38 }} />
      <button type="button" onClick={() => setShow(s => !s)} style={{
        position: 'absolute', right: 10, top: '50%', transform: 'translateY(-50%)',
        color: 'var(--text-muted)', background: 'none', border: 'none', cursor: 'pointer',
      }}>
        {show ? <EyeOff size={14} /> : <Eye size={14} />}
      </button>
    </div>
  )
}

function Pagination({ page, total, pageSize, onChange }) {
  const totalPages = Math.max(1, Math.ceil(total / pageSize))
  if (totalPages <= 1) return null
  const pages = []
  const start = Math.max(1, page - 2), end = Math.min(totalPages, page + 2)
  for (let i = start; i <= end; i++) pages.push(i)
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 0 2px', borderTop: '1px solid var(--border)' }}>
      <span style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>
        Showing {Math.min((page-1)*pageSize+1, total)}–{Math.min(page*pageSize, total)} of {total}
      </span>
      <div style={{ display: 'flex', gap: 4 }}>
        <button className="btn btn-secondary btn-xs" onClick={() => onChange(page-1)} disabled={page===1}><ChevronLeft size={13}/></button>
        {start > 1 && <button className="btn btn-secondary btn-xs" onClick={() => onChange(1)}>1</button>}
        {pages.map(p => <button key={p} className={`btn btn-xs ${p===page?'btn-primary':'btn-secondary'}`} onClick={() => onChange(p)}>{p}</button>)}
        {end < totalPages && <button className="btn btn-secondary btn-xs" onClick={() => onChange(totalPages)}>{totalPages}</button>}
        <button className="btn btn-secondary btn-xs" onClick={() => onChange(page+1)} disabled={page===totalPages}><ChevronRight size={13}/></button>
      </div>
    </div>
  )
}

// ── Create / Edit User Modal ──────────────────────────────────────────────────

function UserModal({ mode, user, onClose, onSaved }) {
  // mode: 'create' | 'edit' | 'reset-password'
  const [name,     setName]     = useState(user?.name     || '')
  const [email,    setEmail]    = useState(user?.email    || '')
  const [role,     setRole]     = useState(user?.role     || 'ml_engineer')
  const [password, setPassword] = useState('')
  const [loading,  setLoading]  = useState(false)
  const [error,    setError]    = useState('')

  const title = mode === 'create' ? 'Create User'
    : mode === 'edit' ? 'Edit User'
    : 'Reset Password'

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      if (mode === 'create') {
        await api.post('/users', { name: name.trim(), email: email.trim().toLowerCase(), password, role })
      } else if (mode === 'edit') {
        await api.put(`/users/${user.id}`, { name: name.trim(), role })
      } else {
        await api.post(`/users/${user.id}/reset-password`, { new_password: password })
      }
      onSaved()
    } catch (err) {
      const detail = err.response?.data?.detail
      if (detail?.password_errors) {
        setError(detail.password_errors.join(' · '))
      } else {
        setError(typeof detail === 'string' ? detail : err.message || 'Operation failed')
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 200,
      background: 'rgba(0,0,0,0.5)', backdropFilter: 'blur(4px)',
      display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16,
    }} onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="card" style={{ width: '100%', maxWidth: 420, padding: 24 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
          <div style={{ fontSize: 15, fontWeight: 700 }}>{title}</div>
          <button className="topbar-btn" onClick={onClose}><X size={14}/></button>
        </div>

        {error && (
          <div className="alert alert-error" style={{ marginBottom: 14, fontSize: 12.5 }}>{error}</div>
        )}

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 13 }}>
          {mode !== 'reset-password' && (
            <>
              <div className="form-group">
                <label className="form-label">Full Name</label>
                <input className="form-input" type="text" placeholder="User's full name"
                  value={name} onChange={e => setName(e.target.value)} required />
              </div>
              {mode === 'create' && (
                <div className="form-group">
                  <label className="form-label">Email</label>
                  <input className="form-input" type="email" placeholder="user@organization.com"
                    value={email} onChange={e => setEmail(e.target.value)} required autoComplete="off" />
                </div>
              )}
              <div className="form-group">
                <label className="form-label">Role</label>
                <select className="form-input" value={role} onChange={e => setRole(e.target.value)}>
                  {ROLES.map(r => <option key={r.value} value={r.value}>{r.label}</option>)}
                </select>
              </div>
            </>
          )}

          {(mode === 'create' || mode === 'reset-password') && (
            <div className="form-group">
              <label className="form-label">
                {mode === 'create' ? 'Password' : 'New Password'}
              </label>
              <PasswordInput value={password} onChange={setPassword}
                placeholder="Min 12 chars, uppercase, digit, special" />
              <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginTop: 4 }}>
                Min 12 chars · uppercase · lowercase · digit · special character
              </div>
            </div>
          )}

          <button type="submit" className="btn btn-primary w-full"
            style={{ justifyContent: 'center', padding: '10px 16px', marginTop: 4 }}
            disabled={loading}>
            {loading
              ? <><span className="spinner" style={{ width: 14, height: 14, borderWidth: 2 }} /> Working…</>
              : <><Check size={14} /><span>{mode === 'create' ? 'Create User' : mode === 'edit' ? 'Save Changes' : 'Reset Password'}</span></>
            }
          </button>
        </form>
      </div>
    </div>
  )
}

// ── Main Users Page ───────────────────────────────────────────────────────────

export default function UsersPage() {
  const { user: me } = useAuth()
  const [users,   setUsers]   = useState([])
  const [total,   setTotal]   = useState(0)
  const [loading, setLoading] = useState(true)
  const [search,  setSearch]  = useState('')
  const [roleFilter, setRoleFilter] = useState('')
  const [page,    setPage]    = useState(1)
  const [modal,   setModal]   = useState(null)   // {mode, user?}
  const [toast,   setToast]   = useState('')

  const showToast = (msg) => {
    setToast(msg)
    setTimeout(() => setToast(''), 3500)
  }

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const params = { limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE }
      if (roleFilter) params.role = roleFilter
      const r = await api.get('/users', { params })
      setUsers(r.data.users || [])
      setTotal(r.data.total || 0)
    } catch { setUsers([]) }
    finally { setLoading(false) }
  }, [page, roleFilter])

  useEffect(() => { load() }, [load])
  useEffect(() => { setPage(1) }, [roleFilter, search])

  const filtered = search
    ? users.filter(u =>
        u.name?.toLowerCase().includes(search.toLowerCase()) ||
        u.email?.toLowerCase().includes(search.toLowerCase()) ||
        u.role?.toLowerCase().includes(search.toLowerCase())
      )
    : users

  const handleToggleActive = async (user) => {
    try {
      if (!user.is_active) {
        await api.put(`/users/${user.id}`, { is_active: true })
      } else {
        await api.delete(`/users/${user.id}`)
      }
      showToast(user.is_active ? `${user.name} deactivated` : `${user.name} reactivated`)
      load()
    } catch (err) {
      showToast(err.response?.data?.detail || 'Operation failed')
    }
  }

  const onModalSaved = () => {
    setModal(null)
    showToast(
      modal?.mode === 'create' ? 'User created successfully' :
      modal?.mode === 'edit'   ? 'User updated' :
      'Password reset successfully'
    )
    load()
  }

  return (
    <div style={{ padding: '24px 0' }}>
      {/* Toast */}
      {toast && (
        <div style={{
          position: 'fixed', bottom: 24, right: 24, zIndex: 300,
          background: 'var(--bg-card)', border: '1px solid var(--border)',
          borderRadius: 8, padding: '10px 16px', fontSize: 13,
          boxShadow: 'var(--shadow-md)', color: 'var(--text)',
          display: 'flex', alignItems: 'center', gap: 8,
        }}>
          <Check size={14} style={{ color: 'var(--green)' }} /> {toast}
        </div>
      )}

      {/* Modal */}
      {modal && (
        <UserModal
          mode={modal.mode}
          user={modal.user}
          onClose={() => setModal(null)}
          onSaved={onModalSaved}
        />
      )}

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12, marginBottom: 20, flexWrap: 'wrap' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 3 }}>
            <Shield size={18} style={{ color: 'var(--accent)' }} />
            <h1 style={{ fontSize: 20, fontWeight: 800, letterSpacing: '-.03em', margin: 0 }}>User Management</h1>
          </div>
          <p style={{ fontSize: 12.5, color: 'var(--text-muted)', margin: 0 }}>
            Manage platform users, roles, and access — Super Admin only
          </p>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn btn-secondary btn-sm" onClick={load} disabled={loading}>
            <RefreshCw size={13} className={loading ? 'spinning' : ''} />
          </button>
          <button className="btn btn-primary btn-sm" onClick={() => setModal({ mode: 'create' })}>
            <UserPlus size={13} /> Add User
          </button>
        </div>
      </div>

      {/* Stats row */}
      <div className="users-stats-row">
        {[
          { label: 'Total Users',    value: total },
          { label: 'Active',         value: users.filter(u => u.is_active).length },
          { label: 'Inactive',       value: users.filter(u => !u.is_active).length },
          { label: 'Roles in use',   value: new Set(users.map(u => u.role)).size },
        ].map(s => (
          <div key={s.label} className="card" style={{ padding: '12px 18px' }}>
            <div style={{ fontSize: 20, fontWeight: 800, letterSpacing: '-.02em' }}>{s.value}</div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 1 }}>{s.label}</div>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="card" style={{ marginBottom: 16 }}>
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', padding: '14px 16px' }}>
          <div style={{ position: 'relative', flex: 1, minWidth: 180 }}>
            <Search size={13} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
            <input className="form-input" placeholder="Search name, email, role…"
              value={search} onChange={e => setSearch(e.target.value)}
              style={{ paddingLeft: 30, fontSize: 12.5 }} />
          </div>
          <select className="form-input" value={roleFilter} onChange={e => setRoleFilter(e.target.value)}
            style={{ width: 'auto', fontSize: 12.5 }}>
            <option value="">All Roles</option>
            {ROLES.map(r => <option key={r.value} value={r.value}>{r.label}</option>)}
          </select>
        </div>
      </div>

      {/* Users Table */}
      <div className="card" style={{ overflow: 'hidden' }}>
        {loading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 40, color: 'var(--text-muted)' }}>
            <RefreshCw size={20} className="spinning" />
          </div>
        ) : filtered.length === 0 ? (
          <div style={{ textAlign: 'center', padding: 40, color: 'var(--text-muted)' }}>
            <UsersIcon size={28} style={{ margin: '0 auto 8px', opacity: .35 }} />
            <div style={{ fontSize: 13 }}>No users found</div>
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12.5 }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)' }}>
                  {[
                    { label: 'User', hide: false },
                    { label: 'Role', hide: false },
                    { label: 'Status', hide: false },
                    { label: 'Last Login', hide: true },
                    { label: 'Created', hide: true },
                    { label: 'Actions', hide: false },
                  ].map(h => (
                    <th key={h.label} className={h.hide ? 'users-col-hide-mobile' : ''} style={{
                      padding: '10px 14px', textAlign: 'left',
                      fontSize: 11, fontWeight: 600, color: 'var(--text-muted)',
                      letterSpacing: '.04em', textTransform: 'uppercase',
                    }}>{h.label}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filtered.map((u, i) => (
                  <tr key={u.id} style={{
                    borderBottom: i < filtered.length-1 ? '1px solid var(--border)' : 'none',
                    opacity: u.is_active ? 1 : 0.6,
                  }}>
                    <td style={{ padding: '11px 14px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
                        <div style={{
                          width: 30, height: 30, borderRadius: '50%',
                          background: 'var(--accent-10)', border: '1px solid var(--accent-30)',
                          display: 'flex', alignItems: 'center', justifyContent: 'center',
                          fontSize: 12, fontWeight: 700, color: 'var(--accent)', flexShrink: 0,
                        }}>
                          {(u.name?.[0] || '?').toUpperCase()}
                        </div>
                        <div>
                          <div style={{ fontWeight: 600, color: 'var(--text)' }}>
                            {u.name}
                            {u.id === me?.id && (
                              <span style={{ marginLeft: 6, fontSize: 10, color: 'var(--accent)', fontFamily: 'var(--font-mono)' }}>you</span>
                            )}
                          </div>
                          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 1 }}>{u.email}</div>
                        </div>
                      </div>
                    </td>
                    <td style={{ padding: '11px 14px' }}><RoleBadge role={u.role} /></td>
                    <td style={{ padding: '11px 14px' }}><StatusBadge active={u.is_active} /></td>
                    <td className="users-col-hide-mobile" style={{ padding: '11px 14px', color: 'var(--text-muted)', fontSize: 11.5 }}>
                      {u.last_login_at
                        ? new Date(u.last_login_at).toLocaleDateString('en-IN', { day:'2-digit', month:'short', year:'2-digit', hour:'2-digit', minute:'2-digit' })
                        : <span style={{ color: 'var(--border)' }}>Never</span>}
                    </td>
                    <td className="users-col-hide-mobile" style={{ padding: '11px 14px', color: 'var(--text-muted)', fontSize: 11.5 }}>
                      {u.created_at
                        ? new Date(u.created_at).toLocaleDateString('en-IN', { day:'2-digit', month:'short', year:'2-digit' })
                        : '—'}
                    </td>
                    <td style={{ padding: '11px 14px' }}>
                      <div style={{ display: 'flex', gap: 5 }}>
                        <button
                          className="btn btn-secondary btn-xs"
                          title="Edit user"
                          onClick={() => setModal({ mode: 'edit', user: u })}
                        >
                          <Edit2 size={11} />
                        </button>
                        <button
                          className="btn btn-secondary btn-xs"
                          title="Reset password"
                          onClick={() => setModal({ mode: 'reset-password', user: u })}
                        >
                          <KeyRound size={11} />
                        </button>
                        {u.id !== me?.id && (
                          <button
                            className="btn btn-secondary btn-xs"
                            title={u.is_active ? 'Deactivate user' : 'Reactivate user'}
                            style={{ color: u.is_active ? 'var(--red)' : 'var(--green)' }}
                            onClick={() => handleToggleActive(u)}
                          >
                            {u.is_active ? <UserX size={11} /> : <UserCheck size={11} />}
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {!loading && (
          <div style={{ padding: '0 16px 12px' }}>
            <Pagination page={page} total={total} pageSize={PAGE_SIZE} onChange={setPage} />
          </div>
        )}
      </div>

      <style>{`
        .spinning { animation: spin 0.8s linear infinite; }
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
      `}</style>
    </div>
  )
}
