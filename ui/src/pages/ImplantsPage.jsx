import { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { getImplants, killImplant, deleteImplant } from '../lib/api'
import { useEvent } from '../hooks/useWebSocket'
import {
  Monitor,
  Terminal,
  Trash2,
  Power,
  Globe,
  Clock,
  Cpu,
  User,
} from 'lucide-react'

function timeSince(dateStr) {
  const seconds = Math.floor((Date.now() - new Date(dateStr).getTime()) / 1000)
  if (seconds < 60)   return `${seconds}s ago`
  if (seconds < 3600)  return `${Math.floor(seconds / 60)}m ago`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`
  return `${Math.floor(seconds / 86400)}d ago`
}

export default function ImplantsPage() {
  const navigate = useNavigate()
  const [implants, setImplants] = useState([])
  const [filter, setFilter] = useState('all') // all, alive, dead

  const fetchImplants = useCallback(async () => {
    try {
      const data = await getImplants()
      setImplants(data || [])
    } catch {
      // ignore
    }
  }, [])

  useEffect(() => { fetchImplants() }, [fetchImplants])
  useEvent('implant.new', useCallback(() => fetchImplants(), [fetchImplants]))
  useEvent('implant.checkin', useCallback(() => fetchImplants(), [fetchImplants]))
  useEvent('implant.dead', useCallback(() => fetchImplants(), [fetchImplants]))

  const handleKill = async (e, id) => {
    e.stopPropagation()
    if (!confirm('Kill this implant?')) return
    try {
      await killImplant(id)
      fetchImplants()
    } catch { /* ignore */ }
  }

  const handleDelete = async (e, id) => {
    e.stopPropagation()
    if (!confirm('Remove this implant from the database?')) return
    try {
      await deleteImplant(id)
      fetchImplants()
    } catch { /* ignore */ }
  }

  const filtered = implants.filter(imp => {
    if (filter === 'alive') return imp.alive
    if (filter === 'dead') return !imp.alive
    return true
  })

  const alive = implants.filter(i => i.alive).length
  const dead = implants.length - alive

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold text-zinc-100">Implants</h1>
        <div className="flex gap-2">
          {['all', 'alive', 'dead'].map(f => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`px-3 py-1 text-xs rounded-md font-medium transition-colors
                ${filter === f
                  ? 'bg-nexus-600/20 text-nexus-400 border border-nexus-600/30'
                  : 'text-zinc-500 hover:text-zinc-300 hover:bg-surface-3'
                }`}
            >
              {f === 'all' ? `All (${implants.length})` :
               f === 'alive' ? `Alive (${alive})` : `Dead (${dead})`}
            </button>
          ))}
        </div>
      </div>

      {/* Table */}
      <div className="glass-panel overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-zinc-800 text-xs text-zinc-500 uppercase tracking-wider">
              <th className="text-left p-3">Status</th>
              <th className="text-left p-3">ID</th>
              <th className="text-left p-3">
                <User className="w-3.5 h-3.5 inline mr-1" />
                User@Host
              </th>
              <th className="text-left p-3">
                <Globe className="w-3.5 h-3.5 inline mr-1" />
                IP
              </th>
              <th className="text-left p-3">
                <Cpu className="w-3.5 h-3.5 inline mr-1" />
                OS / Arch
              </th>
              <th className="text-left p-3">
                <Clock className="w-3.5 h-3.5 inline mr-1" />
                Last Seen
              </th>
              <th className="text-left p-3">Actions</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={7} className="p-8 text-center text-zinc-600">
                  <Monitor className="w-8 h-8 mx-auto mb-2 opacity-30" />
                  No implants {filter !== 'all' ? `(${filter})` : ''}
                </td>
              </tr>
            ) : (
              filtered.map(imp => (
                <tr
                  key={imp.id}
                  onClick={() => navigate(`/implants/${imp.id}`)}
                  className="table-row cursor-pointer"
                >
                  <td className="p-3">
                    <span className={`status-dot ${imp.alive ? 'status-alive' : 'status-dead'}`} />
                  </td>
                  <td className="p-3 font-mono text-xs text-zinc-400">
                    {imp.id.slice(0, 8)}
                  </td>
                  <td className="p-3 text-zinc-200">
                    {imp.username}@{imp.hostname}
                  </td>
                  <td className="p-3 font-mono text-xs text-zinc-400">
                    {imp.internal_ip}
                  </td>
                  <td className="p-3 text-xs text-zinc-400">
                    {imp.os} ({imp.arch})
                  </td>
                  <td className="p-3 text-xs text-zinc-500">
                    {imp.last_seen ? timeSince(imp.last_seen) : 'never'}
                  </td>
                  <td className="p-3">
                    <div className="flex gap-1">
                      <button
                        onClick={(e) => { e.stopPropagation(); navigate(`/implants/${imp.id}`) }}
                        className="p-1.5 text-zinc-500 hover:text-accent-cyan hover:bg-surface-4 rounded"
                        title="Interact"
                      >
                        <Terminal className="w-3.5 h-3.5" />
                      </button>
                      {imp.alive && (
                        <button
                          onClick={(e) => handleKill(e, imp.id)}
                          className="p-1.5 text-zinc-500 hover:text-accent-amber hover:bg-surface-4 rounded"
                          title="Kill"
                        >
                          <Power className="w-3.5 h-3.5" />
                        </button>
                      )}
                      <button
                        onClick={(e) => handleDelete(e, imp.id)}
                        className="p-1.5 text-zinc-500 hover:text-accent-red hover:bg-surface-4 rounded"
                        title="Remove"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
