import { useState } from 'react'
import { Outlet } from 'react-router-dom'
import Sidebar from '../shared/Sidebar'
import Topbar from '../shared/Topbar'

export default function AppShell() {
  const [sidebarOpen, setSidebarOpen] = useState(false)

  return (
    <div className="app-shell">
      {/* Sidebar Overlay (mobile) */}
      <div
        className={`sidebar-overlay ${sidebarOpen ? 'visible' : ''}`}
        onClick={() => setSidebarOpen(false)}
      />
      <Sidebar isOpen={sidebarOpen} onClose={() => setSidebarOpen(false)} />
      <div className="main-content">
        <Topbar onMenuClick={() => setSidebarOpen(o => !o)} />
        <div className="page-body">
          <Outlet />
        </div>
      </div>
    </div>
  )
}
