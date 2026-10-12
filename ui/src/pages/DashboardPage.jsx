import { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { getDashboard, getEvents } from '../lib/api'
import { useEvent } from '../hooks/useWebSocket'
import {
  Monitor,
  Skull,
  Radio,
  Activity,
  Clock,
  AlertTriangle,
  CheckCircle,
  Zap,
} from 'lucide-react'

function StatCard({ icon: Icon, label, value, color }) {
  const colorMap = {
    green:  'text-accent-green bg-accent-green/10 border-accent-green/20',
    red:    'text-accent-red bg-accent-red/10 border-accent-red/20',
    cyan:   'text-accent-cyan bg-accent-cyan/10 border-accent-cyan/20',
    purple: 'text-accent-purple bg-accent-purple/10 border-accent-purple/20',
    amber:  'text-accent-amber bg-accent-amber/10 border-accent-amber/20',
  }

  return (
    <div className="glass-panel p-4">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs text-zinc-500 uppercase tracking-wider">{label}</p>
          <p className="text-2xl font-bold text-zinc-100 mt-1">{value}</p>
        </div>
        <div className={`p-2.5 rounded-lg border ${colorMap[color]}`}>
          <Icon className="w-5 h-5" />
        </div>
      </div>
    </div>
  )
}

function EventItem({ event }) {
  const iconMap = {
    'implant.new':      { icon: Zap, color: 'text-accent-green' },
    'implant.checkin':   { icon: Activity, color: 'text-accent-cyan' },
    'implant.dead':      { icon: Skull, color: 'text-accent-red' },
    'task.created':      { icon: Clock, color: 'text-accent-amber' },
    'task.completed':    { icon: CheckCircle, color: 'text-accent-green' },
    'listener.started':  { icon: Radio, color: 'text-accent-purple' },
    'operator.login':    { icon: Monitor, color: 'text-nexus-400' },
  }

  const config = iconMap[event.type] || { icon: AlertTriangle, color: 'text-zinc-500' }
  const Icon = config.icon

  const timeStr = new Date(event.timestamp).toLocaleTimeString()

  return (
    <div className="flex items-start gap-3 py-2">
      <Icon className={`w-4 h-4 mt-0.5 ${config.color} shrink-0`} />
      <div className="flex-1 min-w-0">
        <p className="text-sm text-zinc-300 truncate">{event.message}</p>
        <p className="text-xs text-zinc-600 font-mono">{timeStr}</p>
      </div>
    </div>
  )
}

export default function DashboardPage() {
  const navigate = useNavigate()
  const [stats, setStats] = useState({ alive: 0, dead: 0, listeners: 0 })
  const [events, setEvents] = useState([])

  const fetchData = useCallback(async () => {
    try {
      const [dash, evts] = await Promise.all([getDashboard(), getEvents()])
      setStats({
        alive: dash.alive_implants ?? 0,
        dead: dash.dead_implants ?? 0,
        total: dash.total_implants ?? 0,
        listeners: dash.active_listeners ?? 0,
      })
      setEvents((evts || []).slice(0, 20))
    } catch {
      // ignore
    }
  }, [])

  useEffect(() => { fetchData() }, [fetchData])

  // refresh on events
  useEvent('*', useCallback(() => { fetchData() }, [fetchData]))

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold text-zinc-100">Dashboard</h1>
        <span className="text-xs text-zinc-600 font-mono">
          {new Date().toLocaleDateString()}
        </span>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="cursor-pointer" onClick={() => navigate('/implants')}>
          <StatCard icon={Monitor} label="Active Implants" value={stats.alive} color="green" />
        </div>
        <StatCard icon={Skull} label="Dead Implants" value={stats.dead} color="red" />
        <div className="cursor-pointer" onClick={() => navigate('/listeners')}>
          <StatCard icon={Radio} label="Listeners" value={stats.listeners} color="cyan" />
        </div>
        <StatCard icon={Activity} label="Total Events" value={events.length} color="purple" />
      </div>

      {/* Recent Events */}
      <div className="glass-panel p-4">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-zinc-300">Recent Activity</h2>
          <button
            onClick={() => navigate('/events')}
            className="text-xs text-nexus-400 hover:text-nexus-300"
          >
            View All
          </button>
        </div>

        <div className="divide-y divide-zinc-800/50">
          {events.length === 0 ? (
            <p className="text-sm text-zinc-600 py-4 text-center">No events yet</p>
          ) : (
            events.map((evt, i) => <EventItem key={i} event={evt} />)
          )}
        </div>
      </div>
    </div>
  )
}
