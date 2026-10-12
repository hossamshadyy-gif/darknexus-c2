import { useState, useEffect, useCallback } from 'react'
import { getLoot } from '../lib/api'
import {
  FolderKey,
  Key,
  FileText,
  Download,
  Search,
} from 'lucide-react'

export default function LootPage() {
  const [loot, setLoot] = useState([])
  const [search, setSearch] = useState('')

  const fetchLoot = useCallback(async () => {
    try {
      const data = await getLoot()
      setLoot(data || [])
    } catch { /* ignore */ }
  }, [])

  useEffect(() => { fetchLoot() }, [fetchLoot])

  const filtered = loot.filter(item => {
    if (!search) return true
    const q = search.toLowerCase()
    return (
      (item.type || '').toLowerCase().includes(q) ||
      (item.source || '').toLowerCase().includes(q) ||
      (item.data || '').toLowerCase().includes(q)
    )
  })

  const typeIcon = (type) => {
    if (type === 'credential') return <Key className="w-4 h-4 text-accent-amber" />
    if (type === 'file') return <FileText className="w-4 h-4 text-accent-cyan" />
    return <FolderKey className="w-4 h-4 text-accent-purple" />
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold text-zinc-100">Loot</h1>
        <span className="text-xs text-zinc-500">{loot.length} items</span>
      </div>

      {/* Search */}
      <div className="relative">
        <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500" />
        <input
          type="text"
          value={search}
          onChange={e => setSearch(e.target.value)}
          className="input-field pl-9"
          placeholder="Search loot..."
        />
      </div>

      {/* Loot Table */}
      <div className="glass-panel overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-zinc-800 text-xs text-zinc-500 uppercase tracking-wider">
              <th className="text-left p-3">Type</th>
              <th className="text-left p-3">Source</th>
              <th className="text-left p-3">Data</th>
              <th className="text-left p-3">Collected</th>
              <th className="text-left p-3">Actions</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={5} className="p-8 text-center text-zinc-600">
                  <FolderKey className="w-8 h-8 mx-auto mb-2 opacity-30" />
                  No loot collected yet
                </td>
              </tr>
            ) : (
              filtered.map((item, i) => (
                <tr key={item.id || i} className="table-row">
                  <td className="p-3">
                    <div className="flex items-center gap-2">
                      {typeIcon(item.type)}
                      <span className="text-xs text-zinc-400 capitalize">{item.type}</span>
                    </div>
                  </td>
                  <td className="p-3 font-mono text-xs text-zinc-400">
                    {item.source || 'unknown'}
                  </td>
                  <td className="p-3 text-xs text-zinc-300 max-w-md truncate">
                    {item.data}
                  </td>
                  <td className="p-3 text-xs text-zinc-500">
                    {item.created_at ? new Date(item.created_at).toLocaleString() : ''}
                  </td>
                  <td className="p-3">
                    <button className="p-1.5 text-zinc-500 hover:text-accent-cyan hover:bg-surface-4 rounded">
                      <Download className="w-3.5 h-3.5" />
                    </button>
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
