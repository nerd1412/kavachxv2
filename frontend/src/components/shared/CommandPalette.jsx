import { useState, useEffect, useRef, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../../context/AuthContext'
import { useTheme } from '../../context/ThemeContext'
import {
  LayoutDashboard, Code2, ClipboardList, FileText, Database,
  Activity, PlayCircle, GitBranch, FlaskConical, Bell, Settings,
  Terminal, Sun, Moon, LogOut, Search, ArrowRight, ScanEye
} from 'lucide-react'

const COMMANDS = [
  /* ── Pages ── */
  { id: 'exec-dash',  label: 'Executive Dashboard',   hint: 'overview',       section: 'Pages', path: '/executive',  icon: LayoutDashboard, roles: ['super_admin','executive'] },
  { id: 'eng-dash',   label: 'ML Engineer Dashboard', hint: 'models',         section: 'Pages', path: '/engineer',   icon: Code2,           roles: ['super_admin','ml_engineer'] },
  { id: 'comp-dash',  label: 'Compliance Dashboard',  hint: 'auditor',        section: 'Pages', path: '/compliance', icon: ClipboardList,   roles: ['super_admin','compliance_officer','auditor'] },
  { id: 'policies',   label: 'Policies',              hint: 'rules governance', section: 'Pages', path: '/policies', icon: FileText,        roles: ['super_admin','compliance_officer','auditor'] },
  { id: 'models',     label: 'Model Registry',        hint: 'registered AI',  section: 'Pages', path: '/models',    icon: Database,        roles: ['super_admin','ml_engineer','compliance_officer','auditor'] },
  { id: 'audit',      label: 'Audit Logs',            hint: 'events history', section: 'Pages', path: '/audit',     icon: Activity,        roles: ['super_admin','compliance_officer','auditor'] },
  { id: 'simulate',   label: 'Batch Simulate',        hint: 'run test',       section: 'Pages', path: '/simulate',  icon: PlayCircle,      roles: ['super_admin','ml_engineer'] },
  { id: 'playground',      label: 'Kavach Playground',      hint: 'live test',    section: 'Pages', path: '/playground',      icon: Terminal },
  { id: 'synthetic-media', label: 'Deepfake Verifier',      hint: 'OCR deepfake', section: 'Pages', path: '/synthetic-media', icon: ScanEye },
  { id: 'lineage',    label: 'Data Lineage',          hint: 'provenance',     section: 'Pages', path: '/lineage',   icon: GitBranch,       roles: ['super_admin','ml_engineer'] },
  { id: 'adversarial',label: 'Adversarial Tests',     hint: 'red team',       section: 'Pages', path: '/adversarial', icon: FlaskConical,  roles: ['super_admin','ml_engineer'] },
  { id: 'alerts',     label: 'Alerts',                hint: 'notifications',  section: 'Pages', path: '/alerts',    icon: Bell,            roles: ['super_admin','ml_engineer','compliance_officer'] },
  { id: 'settings',   label: 'Settings & API Keys',   hint: 'config',         section: 'Pages', path: '/settings',  icon: Settings,        roles: ['super_admin','ml_engineer','compliance_officer'] },
  /* ── Actions ── */
  { id: 'toggle-theme', label: 'Toggle Dark / Light Mode', hint: 'theme', section: 'Actions', action: 'toggle-theme', icon: Sun },
  { id: 'logout',       label: 'Sign Out',                 hint: '',      section: 'Actions', action: 'logout',       icon: LogOut },
]

export default function CommandPalette({ open, onClose }) {
  const [query, setQuery] = useState('')
  const [selectedIdx, setSelectedIdx] = useState(0)
  const { user, logout } = useAuth()
  const { toggle } = useTheme()
  const nav = useNavigate()
  const inputRef = useRef(null)
  const listRef = useRef(null)

  const role = user?.role || ''

  const canSee = useCallback((cmd) => {
    if (!cmd.roles) return true
    return cmd.roles.includes(role)
  }, [role])

  const filtered = COMMANDS.filter(cmd => {
    if (!canSee(cmd)) return false
    if (!query) return true
    const q = query.toLowerCase()
    return (
      cmd.label.toLowerCase().includes(q) ||
      cmd.hint?.toLowerCase().includes(q) ||
      cmd.section.toLowerCase().includes(q)
    )
  })

  // Reset on open
  useEffect(() => {
    if (open) {
      setQuery('')
      setSelectedIdx(0)
      setTimeout(() => inputRef.current?.focus(), 40)
    }
  }, [open])

  useEffect(() => { setSelectedIdx(0) }, [query])

  const execute = useCallback((cmd) => {
    if (cmd.path)                        nav(cmd.path)
    else if (cmd.action === 'toggle-theme') toggle()
    else if (cmd.action === 'logout')       logout()
    onClose()
  }, [nav, toggle, logout, onClose])

  // Keyboard navigation
  useEffect(() => {
    if (!open) return
    const handler = (e) => {
      if (e.key === 'Escape')     { onClose(); return }
      if (e.key === 'ArrowDown')  { e.preventDefault(); setSelectedIdx(i => Math.min(i + 1, filtered.length - 1)) }
      if (e.key === 'ArrowUp')    { e.preventDefault(); setSelectedIdx(i => Math.max(i - 1, 0)) }
      if (e.key === 'Enter' && filtered[selectedIdx]) execute(filtered[selectedIdx])
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [open, filtered, selectedIdx, execute, onClose])

  // Scroll selected item into view
  useEffect(() => {
    if (listRef.current) {
      listRef.current.querySelectorAll('[data-cmd]')[selectedIdx]?.scrollIntoView({ block: 'nearest' })
    }
  }, [selectedIdx])

  if (!open) return null

  // Build section groups while tracking a flat index
  const sections = {}
  filtered.forEach(cmd => {
    if (!sections[cmd.section]) sections[cmd.section] = []
    sections[cmd.section].push(cmd)
  })

  let flatIdx = 0

  return (
    <>
      {/* Backdrop */}
      <div
        style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.58)', zIndex: 900, backdropFilter: 'blur(6px)' }}
        onClick={onClose}
      />

      {/* Palette */}
      <div style={{
        position: 'fixed', top: '16vh', left: '50%',
        transform: 'translateX(-50%)',
        width: '100%', maxWidth: 560,
        zIndex: 901,
        background: 'var(--bg-card)',
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius-xl)',
        boxShadow: 'var(--shadow-lg)',
        overflow: 'hidden',
        animation: 'cmdDrop 0.16s cubic-bezier(0.34,1.4,0.64,1)',
      }}>
        {/* Search row */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 10,
          padding: '13px 16px',
          borderBottom: '1px solid var(--border)',
        }}>
          <Search size={15} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
          <input
            ref={inputRef}
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder="Search pages, actions…"
            style={{
              flex: 1, background: 'none', border: 'none', outline: 'none',
              fontFamily: 'var(--font)', fontSize: 14, color: 'var(--text)',
            }}
          />
          {query && (
            <button onClick={() => setQuery('')} style={{ color: 'var(--text-muted)', padding: 0, lineHeight: 1, fontSize: 11 }}>✕</button>
          )}
        </div>

        {/* Results */}
        <div ref={listRef} style={{ maxHeight: 380, overflowY: 'auto', padding: '5px 5px' }}>
          {filtered.length === 0 ? (
            <div style={{ padding: '36px 0', textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
              No results for <strong style={{ color: 'var(--text-dim)' }}>"{query}"</strong>
            </div>
          ) : (
            Object.entries(sections).map(([section, cmds]) => (
              <div key={section}>
                <div style={{
                  padding: '8px 10px 4px',
                  fontSize: 9, fontWeight: 700, letterSpacing: '.12em',
                  textTransform: 'uppercase', color: 'var(--text-muted)', opacity: .65,
                }}>
                  {section}
                </div>
                {cmds.map(cmd => {
                  const idx = flatIdx++
                  const sel = idx === selectedIdx
                  return (
                    <div
                      key={cmd.id}
                      data-cmd
                      onClick={() => execute(cmd)}
                      onMouseEnter={() => setSelectedIdx(idx)}
                      style={{
                        display: 'flex', alignItems: 'center', gap: 10,
                        padding: '9px 10px', borderRadius: 'var(--radius-sm)',
                        background: sel ? 'var(--accent-light)' : 'transparent',
                        color: sel ? 'var(--accent)' : 'var(--text-dim)',
                        cursor: 'pointer', transition: 'background 0.08s',
                        fontSize: 13, fontWeight: sel ? 600 : 400,
                      }}
                    >
                      <cmd.icon size={15} style={{ flexShrink: 0, opacity: sel ? 1 : 0.55 }} />
                      <span style={{ flex: 1 }}>{cmd.label}</span>
                      {cmd.hint && (
                        <span style={{ fontSize: 10.5, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', opacity: .7 }}>
                          {cmd.hint}
                        </span>
                      )}
                      {sel && <ArrowRight size={12} style={{ opacity: 0.5 }} />}
                    </div>
                  )
                })}
              </div>
            ))
          )}
        </div>

        {/* Keyboard hint footer */}
        <div style={{
          padding: '7px 14px', borderTop: '1px solid var(--border)',
          display: 'flex', gap: 14, alignItems: 'center',
        }}>
          {[['↑↓', 'navigate'], ['↵', 'select'], ['esc', 'close']].map(([key, label]) => (
            <span key={key} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 10.5, color: 'var(--text-muted)' }}>
              <kbd style={{
                padding: '1px 5px', background: 'var(--bg-elevated)',
                border: '1px solid var(--border)', borderRadius: 3,
                fontFamily: 'var(--font-mono)', fontSize: 10, lineHeight: 1.6,
              }}>{key}</kbd>
              {label}
            </span>
          ))}
          <span style={{ marginLeft: 'auto', fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', opacity: .7 }}>
            {filtered.length} result{filtered.length !== 1 ? 's' : ''}
          </span>
        </div>
      </div>

      <style>{`
        @keyframes cmdDrop {
          from { opacity: 0; transform: translateX(-50%) translateY(-14px) scale(0.97); }
          to   { opacity: 1; transform: translateX(-50%) translateY(0)     scale(1);    }
        }
      `}</style>
    </>
  )
}
