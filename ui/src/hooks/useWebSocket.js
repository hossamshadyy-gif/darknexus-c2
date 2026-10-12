import { useEffect, useState } from 'react'
import eventBus from '../lib/websocket'

export function useWebSocket() {
  const [connected, setConnected] = useState(false)

  useEffect(() => {
    eventBus.connect()

    const unsub1 = eventBus.on('_connected', () => setConnected(true))
    const unsub2 = eventBus.on('_disconnected', () => setConnected(false))

    return () => {
      unsub1()
      unsub2()
      eventBus.disconnect()
    }
  }, [])

  return { connected, eventBus }
}

export function useEvent(eventType, callback) {
  useEffect(() => {
    const unsub = eventBus.on(eventType, callback)
    return unsub
  }, [eventType, callback])
}
