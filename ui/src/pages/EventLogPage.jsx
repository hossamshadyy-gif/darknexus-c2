import { useState, useEffect, useCallback } from 'react'
import { getEvents } from '../lib/api'
import { useEvent } from '../hooks/useWebSocket'
import {
  ScrollText,
  Zap,
  Activity,
  Skull,
  CheckCircle,
  Clock,
  Radio,
  Monitor,
  AlertTriangle,
  Filter,
} from 'lucide-react'

const EVENT_TYPES = [
  'all',
  'implant.new',
  'implant.checkin',
  'implant.dead',
  'task.created',
  'task.completed',
  'listener.started',
  'operator.login',
]

const iconMap = {
  'implant.new':      { icon: Zap,          color: 'text-accent-green',  bg: 'bg-accent-green/10' },
  'implant.checkin':   { icon: Activity,     color: 'text-accent-cyan',   bg: 'bg-accent-cyan/10' },
  'implant.dead':      { icon: Skull,        color: 'text-accent-red',    bg: 'bg-accent-red/10' },
  'implant.removed':   { icon: Skull,        color: 'text-zinc-500',      bg: 'bg-zinc-500/10' },
  'task.created':      { icon: Clock,        color: 'text-accent-amber',  bg: 'bg-accent-amber/10' },
  'task.completed':    { icon: CheckCircle,  color: 'text-accent-green',  bg: 'bg-accent-green/10' },
  'listener.started':  { icon: Radio,        color: 'text-accent-purple', bg: 'bg-accent-purple/10' },
  'listener.stopped':  { icon: Radio,        color: 'text-zinc-500',      bg: 'bg-zinc-500/10' },
  'operator.login':    { icon: Monitor,      color: 'text-nexus-400',     bg: 'bg-nexus-400/10' },
}

export default function EventLogPage() {
  const [events, setEvents] = useState([])
  const [filter, setFilter] = useState('all')

  const fetchEvents = useCallback(async () => {
    try {
      const data = await getEvents()
      setEvents(data || [])
    } catch { /* ignore */ }
  }, [])

  useEffect(() => { fetchEvents() }, [fetchEvents])
  useEvent('*', useCallback(() => fetchEvents(), [fetchEvents]))

  const filtered = filter === 'all'
    ? events
    : events.filter(e => e.type === filter)

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold text-zinc-100">Event Log</h1>
        <span className="text-xs text-zinc-500">{events.length} events</span>
      </div>

      {/* Filter */}
      <div className="flex items-center gap-2 flex-wrap">
        <Filter className="w-3.5 h-3.5 text-zinc-500" />
        {EVENT_TYPES.map(t => (
          <button
            key={t}
            onClick={() => setFilter(t)}
            className={`px-2 py-1 text-[11px] rounded font-mono transition-colors
              ${filter === t
                ? 'bg-nexus-600/20 text-nexus-400 border border-nexus-600/30'
                : 'text-zinc-600 hover:text-zinc-400 hover:bg-surface-3'
              }`}
          >
            {t}
          </button>
        ))}
      </div>

      {/* Event List */}
      <div className="glass-panel divide-y divide-zinc-800/50">
        {filtered.length === 0 ? (
          <div className="p-8 text-center">
            <ScrollText className="w-8 h-8 mx-auto mb-2 text-zinc-700" />
            <p className="text-sm text-zinc-600">No events</p>
          </div>
        ) : (
          filtered.map((evt, i) => {
            const config = iconMap[evt.type] || { icon: AlertTriangle, color: 'text-zinc-500', bg: 'bg-zinc-500/10' }
            const Icon = config.icon
            const time = new Date(evt.timestamp).toLocaleString()

            return (
              <div key={i} className="flex items-start gap-3 p-3 hover:bg-surface-3/30 transition-colors">
                <div className={`p-1.5 rounded ${config.bg} mt-0.5`}>
                  <Icon className={`w-3.5 h-3.5 ${config.color}`} />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-[11px] text-zinc-500">{evt.type}</span>
                  </div>
                  <p className="text-sm text-zinc-300 mt-0.5">{evt.message}</p>
                </div>
                <span className="text-[10px] text-zinc-600 font-mono whitespace-nowrap">{time}</span>
              </div>
            )
          })
        )}
      </div>
    </div>
  )
}
