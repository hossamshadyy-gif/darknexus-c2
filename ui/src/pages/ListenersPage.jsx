import { useState, useEffect, useCallback } from 'react'
import { getListeners, createListener } from '../lib/api'
import {
  Radio,
  Plus,
  Shield,
  Globe,
  X,
} from 'lucide-react'

export default function ListenersPage() {
  const [listeners, setListeners] = useState([])
  const [showCreate, setShowCreate] = useState(false)
  const [form, setForm] = useState({
    name: '',
    bind_addr: '0.0.0.0',
    port: '443',
    type: 'https',
  })

  const fetchListeners = useCallback(async () => {
    try {
      const data = await getListeners()
      setListeners(data || [])
    } catch { /* ignore */ }
  }, [])

  useEffect(() => { fetchListeners() }, [fetchListeners])

  const handleCreate = async (e) => {
    e.preventDefault()
    try {
      await createListener({
        ...form,
        port: parseInt(form.port, 10),
      })
      setShowCreate(false)
      setForm({ name: '', bind_addr: '0.0.0.0', port: '443', type: 'https' })
      fetchListeners()
    } catch { /* ignore */ }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold text-zinc-100">Listeners</h1>
        <button
          onClick={() => setShowCreate(!showCreate)}
          className="btn-primary flex items-center gap-2"
        >
          {showCreate ? <X className="w-4 h-4" /> : <Plus className="w-4 h-4" />}
          {showCreate ? 'Cancel' : 'New Listener'}
        </button>
      </div>

      {/* Create Form */}
      {showCreate && (
        <form onSubmit={handleCreate} className="glass-panel p-4 space-y-3">
          <h3 className="text-sm font-semibold text-zinc-300">Create Listener</h3>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-zinc-500 mb-1">Name</label>
              <input
                type="text"
                value={form.name}
                onChange={e => setForm({...form, name: e.target.value})}
                className="input-field"
                placeholder="https-main"
                required
              />
            </div>
            <div>
              <label className="block text-xs text-zinc-500 mb-1">Protocol</label>
              <select
                value={form.type}
                onChange={e => setForm({...form, type: e.target.value})}
                className="input-field"
              >
                <option value="https">HTTPS</option>
                <option value="dns" disabled>DNS (coming soon)</option>
                <option value="smb" disabled>SMB (coming soon)</option>
              </select>
            </div>
            <div>
              <label className="block text-xs text-zinc-500 mb-1">Bind Host</label>
              <input
                type="text"
                value={form.bind_addr}
                onChange={e => setForm({...form, bind_addr: e.target.value})}
                className="input-field font-mono"
                placeholder="0.0.0.0"
              />
            </div>
            <div>
              <label className="block text-xs text-zinc-500 mb-1">Port</label>
              <input
                type="number"
                value={form.port}
                onChange={e => setForm({...form, port: e.target.value})}
                className="input-field font-mono"
                placeholder="443"
              />
            </div>
          </div>

          <button type="submit" className="btn-primary">
            Start Listener
          </button>
        </form>
      )}

      {/* Listeners Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {listeners.length === 0 ? (
          <div className="glass-panel p-8 col-span-full text-center">
            <Radio className="w-8 h-8 mx-auto mb-2 text-zinc-700" />
            <p className="text-sm text-zinc-600">No listeners running</p>
          </div>
        ) : (
          listeners.map(l => (
            <div key={l.id || l.name} className="glass-panel p-4">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <span className={`status-dot ${l.status === 'running' ? 'status-alive' : 'status-dead'}`} />
                  <span className="text-sm font-medium text-zinc-200">{l.name}</span>
                </div>
                <Shield className="w-4 h-4 text-accent-cyan" />
              </div>

              <div className="space-y-1.5">
                <div className="flex items-center gap-2 text-xs">
                  <Globe className="w-3 h-3 text-zinc-500" />
                  <span className="text-zinc-400 font-mono">{l.bind_addr || l.host}:{l.port}</span>
                </div>
                <div className="flex items-center gap-2 text-xs">
                  <Radio className="w-3 h-3 text-zinc-500" />
                  <span className="text-zinc-400 uppercase">{l.type || l.protocol || 'https'}</span>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  )
}
