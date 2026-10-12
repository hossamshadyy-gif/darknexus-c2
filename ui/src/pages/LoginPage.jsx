import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { login, setup, setToken, isAuthenticated } from '../lib/api'
import { Hexagon, Eye, EyeOff } from 'lucide-react'

export default function LoginPage() {
  const navigate = useNavigate()
  const [isSetup, setIsSetup] = useState(false)
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPass, setShowPass] = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  // redirect if already logged in
  if (isAuthenticated()) {
    navigate('/', { replace: true })
    return null
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)

    try {
      const fn = isSetup ? setup : login
      const data = await fn(username, password)
      setToken(data.token)
      navigate('/')
    } catch (err) {
      setError(err.message || 'Authentication failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-surface-0 p-4">
      <div className="w-full max-w-sm">
        {/* Logo */}
        <div className="text-center mb-8">
          <Hexagon className="w-12 h-12 text-nexus-500 mx-auto mb-3" />
          <h1 className="text-xl font-bold text-zinc-100 tracking-widest">DARK NEXUS</h1>
          <p className="text-xs text-zinc-500 mt-1 font-mono">Command & Control</p>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="glass-panel p-6 space-y-4">
          <h2 className="text-sm font-semibold text-zinc-300 text-center">
            {isSetup ? 'Create Admin Account' : 'Operator Login'}
          </h2>

          {error && (
            <div className="px-3 py-2 bg-red-600/10 border border-red-600/20 rounded-md text-xs text-red-400">
              {error}
            </div>
          )}

          <div>
            <label className="block text-xs text-zinc-500 mb-1">Username</label>
            <input
              type="text"
              value={username}
              onChange={e => setUsername(e.target.value)}
              className="input-field"
              placeholder="operator"
              autoFocus
              required
            />
          </div>

          <div>
            <label className="block text-xs text-zinc-500 mb-1">Password</label>
            <div className="relative">
              <input
                type={showPass ? 'text' : 'password'}
                value={password}
                onChange={e => setPassword(e.target.value)}
                className="input-field pr-10"
                placeholder="password"
                required
              />
              <button
                type="button"
                onClick={() => setShowPass(!showPass)}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300"
              >
                {showPass ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="btn-primary w-full disabled:opacity-50"
          >
            {loading ? 'Authenticating...' : isSetup ? 'Create Account' : 'Login'}
          </button>

          <button
            type="button"
            onClick={() => { setIsSetup(!isSetup); setError('') }}
            className="text-xs text-zinc-500 hover:text-zinc-300 w-full text-center"
          >
            {isSetup ? 'Already have an account? Login' : 'First time? Create admin account'}
          </button>
        </form>
      </div>
    </div>
  )
}
