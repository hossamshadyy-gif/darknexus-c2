import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import { useWebSocket } from '../hooks/useWebSocket'
import { clearToken } from '../lib/api'
import {
  LayoutDashboard,
  Monitor,
  Radio,
  FolderKey,
  ScrollText,
  Users,
  LogOut,
  Wifi,
  WifiOff,
  Hexagon,
} from 'lucide-react'

const navItems = [
  { to: '/',          icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/implants',  icon: Monitor,         label: 'Implants' },
  { to: '/listeners', icon: Radio,           label: 'Listeners' },
  { to: '/loot',      icon: FolderKey,       label: 'Loot' },
  { to: '/events',    icon: ScrollText,      label: 'Event Log' },
  { to: '/operators', icon: Users,           label: 'Operators' },
]

export default function Layout() {
  const navigate = useNavigate()
  const { connected } = useWebSocket()

  const handleLogout = () => {
    clearToken()
    navigate('/login')
  }

  return (
    <div className="flex h-screen overflow-hidden">
      {/* Sidebar */}
      <aside className="w-56 flex flex-col bg-surface-1 border-r border-zinc-800">
        {/* Logo */}
        <div className="p-4 border-b border-zinc-800">
          <div className="flex items-center gap-2">
            <Hexagon className="w-7 h-7 text-nexus-500" />
            <div>
              <h1 className="text-sm font-bold text-zinc-100 tracking-wide">DARK NEXUS</h1>
              <span className="text-[10px] text-zinc-500 font-mono">v0.1.0</span>
            </div>
          </div>
        </div>

        {/* Nav Links */}
        <nav className="flex-1 p-3 space-y-1">
          {navItems.map(({ to, icon: Icon, label }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) =>
                `nav-link ${isActive ? 'nav-link-active' : ''}`
              }
            >
              <Icon className="w-4 h-4" />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>

        {/* Footer */}
        <div className="p-3 border-t border-zinc-800 space-y-2">
          {/* Connection Status */}
          <div className="flex items-center gap-2 px-3 py-1.5 text-xs">
            {connected ? (
              <>
                <Wifi className="w-3 h-3 text-accent-green" />
                <span className="text-accent-green">Connected</span>
              </>
            ) : (
              <>
                <WifiOff className="w-3 h-3 text-zinc-500" />
                <span className="text-zinc-500">Disconnected</span>
              </>
            )}
          </div>

          {/* Logout */}
          <button onClick={handleLogout} className="nav-link w-full text-red-400 hover:text-red-300">
            <LogOut className="w-4 h-4" />
            <span>Logout</span>
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-auto">
        <div className="p-6">
          <Outlet />
        </div>
      </main>
    </div>
  )
}
