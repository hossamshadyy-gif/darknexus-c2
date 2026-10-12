/*
 * WebSocket event bus client
 * Auto-reconnects, dispatches events to subscribers
 * Sends JWT token as query param for authentication
 */

import { getToken } from './api'

class EventBus {
  constructor() {
    this.ws = null
    this.listeners = new Map()
    this.reconnectInterval = 3000
    this.reconnectTimer = null
  }

  connect() {
    const token = getToken()
    if (!token) {
      // no token yet, retry after delay
      this.scheduleReconnect()
      return
    }

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const wsUrl = `${protocol}//${window.location.host}/api/ws?token=${encodeURIComponent(token)}`

    try {
      this.ws = new WebSocket(wsUrl)
    } catch {
      this.scheduleReconnect()
      return
    }

    this.ws.onopen = () => {
      console.log('[DN] websocket connected')
      this.emit('_connected', {})
    }

    this.ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data)
        this.emit(msg.type, msg.data)
        // also emit wildcard
        this.emit('*', msg)
      } catch {
        // ignore malformed messages
      }
    }

    this.ws.onclose = () => {
      console.log('[DN] websocket disconnected')
      this.emit('_disconnected', {})
      this.scheduleReconnect()
    }

    this.ws.onerror = () => {
      this.ws.close()
    }
  }

  disconnect() {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer)
      this.reconnectTimer = null
    }
    if (this.ws) {
      this.ws.close()
      this.ws = null
    }
  }

  scheduleReconnect() {
    if (this.reconnectTimer) return
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null
      this.connect()
    }, this.reconnectInterval)
  }

  on(eventType, callback) {
    if (!this.listeners.has(eventType)) {
      this.listeners.set(eventType, new Set())
    }
    this.listeners.get(eventType).add(callback)

    // return unsubscribe function
    return () => {
      const set = this.listeners.get(eventType)
      if (set) set.delete(callback)
    }
  }

  emit(eventType, data) {
    const set = this.listeners.get(eventType)
    if (set) {
      set.forEach(cb => {
        try { cb(data) } catch (e) { console.error('[DN] event handler error:', e) }
      })
    }
  }
}

// singleton
const eventBus = new EventBus()
export default eventBus
