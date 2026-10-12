import { useState, useEffect, useCallback, useRef } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { getImplantTasks, createTask } from '../lib/api'
import { useEvent } from '../hooks/useWebSocket'
import {
  ArrowLeft,
  Send,
  Terminal,
  Clock,
  CheckCircle,
  XCircle,
  Loader2,
} from 'lucide-react'

const COMMANDS = [
  { name: 'shell',    desc: 'Execute shell command via cmd.exe',  args: '<command>' },
  { name: 'exec',     desc: 'Run program directly',              args: '<path> [args]' },
  { name: 'pwd',      desc: 'Print working directory',           args: '' },
  { name: 'cd',       desc: 'Change directory',                  args: '<path>' },
  { name: 'whoami',   desc: 'Current user',                      args: '' },
  { name: 'hostname', desc: 'Machine hostname',                  args: '' },
  { name: 'ps',       desc: 'List processes',                    args: '' },
  { name: 'ls',       desc: 'List directory',                    args: '[path]' },
  { name: 'cat',      desc: 'Read file',                         args: '<path>' },
  { name: 'sleep',    desc: 'Change beacon interval',            args: '<sec> [jitter%]' },
  { name: 'exit',     desc: 'Kill the implant',                  args: '' },
]

function TaskItem({ task }) {
  const statusConfig = {
    pending:   { icon: Clock,       color: 'text-accent-amber', label: 'Pending' },
    sent:      { icon: Loader2,     color: 'text-accent-cyan',  label: 'Sent' },
    completed: { icon: CheckCircle, color: 'text-accent-green', label: 'Done' },
    failed:    { icon: XCircle,     color: 'text-accent-red',   label: 'Failed' },
  }

  const config = statusConfig[task.status] || statusConfig.pending
  const Icon = config.icon
  const time = new Date(task.created_at).toLocaleTimeString()

  return (
    <div className="border-b border-zinc-800/50 py-3">
      <div className="flex items-center gap-2 mb-1">
        <Icon className={`w-3.5 h-3.5 ${config.color}`} />
        <span className="font-mono text-xs text-nexus-400">{task.command}</span>
        {task.args && <span className="font-mono text-xs text-zinc-500">{task.args}</span>}
        <span className="text-[10px] text-zinc-600 ml-auto">{time}</span>
      </div>

      {task.result && (
        <div className="terminal-output mt-2">
          {task.result}
        </div>
      )}
    </div>
  )
}

export default function InteractPage() {
  const { id } = useParams()
  const navigate = useNavigate()
  const [tasks, setTasks] = useState([])
  const [input, setInput] = useState('')
  const [sending, setSending] = useState(false)
  const [showHelp, setShowHelp] = useState(false)
  const inputRef = useRef(null)
  const bottomRef = useRef(null)

  const fetchTasks = useCallback(async () => {
    try {
      const data = await getImplantTasks(id)
      setTasks((data || []).reverse()) // newest last
    } catch { /* ignore */ }
  }, [id])

  useEffect(() => { fetchTasks() }, [fetchTasks])
  useEffect(() => { inputRef.current?.focus() }, [])
  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: 'smooth' }) }, [tasks])

  // refresh on task events
  useEvent('task.completed', useCallback(() => fetchTasks(), [fetchTasks]))

  const handleSubmit = async (e) => {
    e.preventDefault()
    const trimmed = input.trim()
    if (!trimmed) return

    // parse command and args
    const parts = trimmed.split(/\s+/)
    const command = parts[0]
    const args = parts.slice(1).join(' ')

    // local help
    if (command === 'help') {
      setShowHelp(!showHelp)
      setInput('')
      return
    }

    if (command === 'clear') {
      setTasks([])
      setInput('')
      return
    }

    setSending(true)
    try {
      await createTask(id, command, args)
      setInput('')
      fetchTasks()
    } catch {
      // ignore
    } finally {
      setSending(false)
    }
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center gap-3">
        <button
          onClick={() => navigate('/implants')}
          className="p-1.5 text-zinc-500 hover:text-zinc-300 hover:bg-surface-3 rounded"
        >
          <ArrowLeft className="w-4 h-4" />
        </button>
        <Terminal className="w-5 h-5 text-nexus-400" />
        <div>
          <h1 className="text-sm font-semibold text-zinc-100">
            Interact: <span className="font-mono text-nexus-400">{id.slice(0, 8)}</span>
          </h1>
          <p className="text-xs text-zinc-500">
            Type <span className="text-zinc-400">help</span> for available commands
          </p>
        </div>
      </div>

      {/* Help Panel */}
      {showHelp && (
        <div className="glass-panel p-4">
          <h3 className="text-xs font-semibold text-zinc-400 uppercase mb-2">Available Commands</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-1">
            {COMMANDS.map(cmd => (
              <div key={cmd.name} className="flex items-baseline gap-2 py-0.5">
                <span className="font-mono text-xs text-nexus-400 w-20">{cmd.name}</span>
                <span className="text-xs text-zinc-500">{cmd.args}</span>
                <span className="text-xs text-zinc-600 ml-auto">{cmd.desc}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Task History */}
      <div className="glass-panel p-4 min-h-[400px] max-h-[600px] overflow-auto">
        {tasks.length === 0 ? (
          <div className="text-center text-zinc-600 py-12">
            <Terminal className="w-8 h-8 mx-auto mb-2 opacity-30" />
            <p className="text-sm">No tasks yet. Send a command below.</p>
          </div>
        ) : (
          tasks.map((task, i) => <TaskItem key={task.id || i} task={task} />)
        )}
        <div ref={bottomRef} />
      </div>

      {/* Input */}
      <form onSubmit={handleSubmit} className="flex gap-2">
        <div className="flex-1 relative">
          <span className="absolute left-3 top-1/2 -translate-y-1/2 text-nexus-500 font-mono text-sm">
            $
          </span>
          <input
            ref={inputRef}
            type="text"
            value={input}
            onChange={e => setInput(e.target.value)}
            className="input-field pl-7 font-mono text-sm"
            placeholder="shell whoami"
            disabled={sending}
          />
        </div>
        <button
          type="submit"
          disabled={sending || !input.trim()}
          className="btn-primary flex items-center gap-2 disabled:opacity-50"
        >
          {sending ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : (
            <Send className="w-4 h-4" />
          )}
          Send
        </button>
      </form>
    </div>
  )
}
