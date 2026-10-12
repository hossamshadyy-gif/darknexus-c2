/*
 * Dark Nexus API client
 * Handles JWT auth and REST calls to the teamserver
 */

// In production, set VITE_API_URL to the teamserver address (e.g. https://your-server:8443/api)
// For local dev, the Vite proxy forwards /api to the teamserver
const API_BASE = import.meta.env.VITE_API_URL || '/api'

let authToken = localStorage.getItem('dn_token') || null

export function setToken(token) {
  authToken = token
  localStorage.setItem('dn_token', token)
}

export function getToken() {
  return authToken
}

export function clearToken() {
  authToken = null
  localStorage.removeItem('dn_token')
}

export function isAuthenticated() {
  return authToken !== null
}

async function request(method, path, body = null) {
  const headers = {
    'Content-Type': 'application/json',
  }

  if (authToken) {
    headers['Authorization'] = `Bearer ${authToken}`
  }

  const opts = { method, headers }
  if (body) {
    opts.body = JSON.stringify(body)
  }

  const res = await fetch(`${API_BASE}${path}`, opts)

  if (res.status === 401) {
    clearToken()
    window.location.href = '/login'
    throw new Error('unauthorized')
  }

  if (!res.ok) {
    const text = await res.text()
    throw new Error(text || `HTTP ${res.status}`)
  }

  // some endpoints return no body
  const contentType = res.headers.get('content-type')
  if (contentType && contentType.includes('application/json')) {
    return res.json()
  }
  return null
}

// Auth
export const login = (username, password) =>
  request('POST', '/auth/login', { username, password })

export const setup = (username, password) =>
  request('POST', '/auth/setup', { username, password })

// Dashboard
export const getDashboard = () =>
  request('GET', '/dashboard')

// Implants
export const getImplants = () =>
  request('GET', '/implants')

export const deleteImplant = (id) =>
  request('DELETE', `/implants/${id}`)

export const killImplant = (id) =>
  request('POST', `/implants/${id}/kill`)

// Tasks
export const getImplantTasks = (implantId) =>
  request('GET', `/implants/${implantId}/tasks`)

export const createTask = (implantId, command, args = '') =>
  request('POST', `/implants/${implantId}/tasks`, { command, args })

// Listeners
export const getListeners = () =>
  request('GET', '/listeners')

export const createListener = (listener) =>
  request('POST', '/listeners', listener)

// Loot
export const getLoot = () =>
  request('GET', '/loot')

// Operators
export const getOperators = () =>
  request('GET', '/operators')

export const createOperator = (username, password, role) =>
  request('POST', '/operators', { username, password, role })

export const deleteOperator = (id) =>
  request('DELETE', `/operators/${id}`)

export const changeOperatorPassword = (id, password) =>
  request('PUT', `/operators/${id}/password`, { password })

export const changeOperatorRole = (id, role) =>
  request('PUT', `/operators/${id}/role`, { role })

// Events
export const getEvents = () =>
  request('GET', '/events')
