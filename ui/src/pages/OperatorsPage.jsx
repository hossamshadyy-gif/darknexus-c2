import { useState, useEffect, useCallback } from 'react'
import {
  getOperators,
  createOperator,
  deleteOperator,
  changeOperatorPassword,
  changeOperatorRole,
} from '../lib/api'
import {
  Users,
  Plus,
  Trash2,
  Key,
  Shield,
  ShieldAlert,
  Eye,
  X,
} from 'lucide-react'

const roleBadge = {
  admin:    'bg-accent-red/10 text-accent-red border border-accent-red/20',
  operator: 'bg-accent-cyan/10 text-accent-cyan border border-accent-cyan/20',
  viewer:   'bg-zinc-700/50 text-zinc-400 border border-zinc-600/30',
}

const roleIcon = {
  admin:    ShieldAlert,
  operator: Shield,
  viewer:   Eye,
}

export default function OperatorsPage() {
  const [operators, setOperators] = useState([])
  const [showCreate, setShowCreate] = useState(false)
  const [form, setForm] = useState({ username: '', password: '', role: 'operator' })
  const [error, setError] = useState('')
  const [pwModal, setPwModal] = useState(null) // operator id for password change
  const [newPassword, setNewPassword] = useState('')

  const fetchOperators = useCallback(async () => {
    try {
      const ops = await getOperators()
      setOperators(ops || [])
    } catch {
      // ignore
    }
  }, [])

  useEffect(() => { fetchOperators() }, [fetchOperators])

  const handleCreate = async (e) => {
    e.preventDefault()
    setError('')
    try {
      await createOperator(form.username, form.password, form.role)
      setForm({ username: '', password: '', role: 'operator' })
      setShowCreate(false)
      fetchOperators()
    } catch (err) {
      setError(err.message || 'Failed to create operator')
    }
  }

  const handleDelete = async (id, username) => {
    if (!confirm(`Remove operator "${username}"? This cannot be undone.`)) return
    try {
      await deleteOperator(id)
      fetchOperators()
    } catch (err) {
      setError(err.message || 'Failed to delete operator')
    }
  }

  const handlePasswordChange = async (e) => {
    e.preventDefault()
    setError('')
    try {
      await changeOperatorPassword(pwModal, newPassword)
      setPwModal(null)
      setNewPassword('')
    } catch (err) {
      setError(err.message || 'Failed to change password')
    }
  }

  const handleRoleChange = async (id, newRole) => {
    try {
      await changeOperatorRole(id, newRole)
      fetchOperators()
    } catch (err) {
      setError(err.message || 'Failed to change role')
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Users className="w-5 h-5 text-nexus-400" />
          <h1 className="text-lg font-semibold text-zinc-100">Operators</h1>
          <span className="text-xs text-zinc-500 font-mono">({operators.length})</span>
        </div>
        <button
          onClick={() => setShowCreate(!showCreate)}
          className="btn-primary text-sm flex items-center gap-1.5"
        >
          <Plus className="w-4 h-4" />
          New Operator
        </button>
      </div>

      {error && (
        <div className="glass-panel p-3 border-accent-red/30 text-accent-red text-sm">
          {error}
        </div>
      )}

      {/* Create form */}
      {showCreate && (
        <form onSubmit={handleCreate} className="glass-panel p-4 space-y-3">
          <h2 className="text-sm font-semibold text-zinc-300">Create Operator</h2>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <input
              className="input-field"
              placeholder="Username (3+ chars)"
              value={form.username}
              onChange={(e) => setForm({ ...form, username: e.target.value })}
              required
              minLength={3}
            />
            <input
              className="input-field"
              type="password"
              placeholder="Password (8+ chars)"
              value={form.password}
              onChange={(e) => setForm({ ...form, password: e.target.value })}
              required
              minLength={8}
            />
            <select
              className="input-field"
              value={form.role}
              onChange={(e) => setForm({ ...form, role: e.target.value })}
            >
              <option value="operator">Operator</option>
              <option value="admin">Admin</option>
              <option value="viewer">Viewer</option>
            </select>
          </div>
          <div className="flex gap-2">
            <button type="submit" className="btn-primary text-sm">Create</button>
            <button
              type="button"
              onClick={() => setShowCreate(false)}
              className="px-3 py-1.5 text-sm text-zinc-400 hover:text-zinc-200"
            >
              Cancel
            </button>
          </div>
        </form>
      )}

      {/* Password change modal */}
      {pwModal && (
        <form onSubmit={handlePasswordChange} className="glass-panel p-4 space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-zinc-300">Change Password</h2>
            <button type="button" onClick={() => setPwModal(null)}>
              <X className="w-4 h-4 text-zinc-500 hover:text-zinc-300" />
            </button>
          </div>
          <input
            className="input-field w-full sm:w-1/2"
            type="password"
            placeholder="New password (8+ chars)"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            required
            minLength={8}
          />
          <button type="submit" className="btn-primary text-sm">Update Password</button>
        </form>
      )}

      {/* Operators table */}
      <div className="glass-panel overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-zinc-800 text-left text-xs text-zinc-500 uppercase tracking-wider">
              <th className="px-4 py-3">Username</th>
              <th className="px-4 py-3">Role</th>
              <th className="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800/50">
            {operators.length === 0 ? (
              <tr>
                <td colSpan="3" className="px-4 py-6 text-center text-zinc-600">
                  No operators
                </td>
              </tr>
            ) : (
              operators.map((op) => {
                const RoleIcon = roleIcon[op.role] || Shield
                return (
                  <tr key={op.id} className="hover:bg-surface-2/50">
                    <td className="px-4 py-3 text-zinc-200 font-mono">{op.username}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs ${roleBadge[op.role] || roleBadge.viewer}`}>
                          <RoleIcon className="w-3 h-3" />
                          {op.role}
                        </span>
                        <select
                          className="bg-transparent text-xs text-zinc-500 hover:text-zinc-300 cursor-pointer border-none outline-none"
                          value=""
                          onChange={(e) => {
                            if (e.target.value) handleRoleChange(op.id, e.target.value)
                          }}
                        >
                          <option value="" disabled>change...</option>
                          {['admin', 'operator', 'viewer']
                            .filter(r => r !== op.role)
                            .map(r => <option key={r} value={r}>{r}</option>)
                          }
                        </select>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-right">
                      <div className="flex items-center justify-end gap-1">
                        <button
                          onClick={() => { setPwModal(op.id); setNewPassword('') }}
                          className="p-1.5 text-zinc-500 hover:text-accent-amber rounded hover:bg-accent-amber/10"
                          title="Change password"
                        >
                          <Key className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => handleDelete(op.id, op.username)}
                          className="p-1.5 text-zinc-500 hover:text-accent-red rounded hover:bg-accent-red/10"
                          title="Delete operator"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                )
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
