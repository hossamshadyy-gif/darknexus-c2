import { Routes, Route, Navigate } from 'react-router-dom'
import { isAuthenticated } from './lib/api'
import Layout from './components/Layout'
import LoginPage from './pages/LoginPage'
import DashboardPage from './pages/DashboardPage'
import ImplantsPage from './pages/ImplantsPage'
import InteractPage from './pages/InteractPage'
import ListenersPage from './pages/ListenersPage'
import LootPage from './pages/LootPage'
import EventLogPage from './pages/EventLogPage'
import OperatorsPage from './pages/OperatorsPage'

function ProtectedRoute({ children }) {
  if (!isAuthenticated()) {
    return <Navigate to="/login" replace />
  }
  return children
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        path="/"
        element={
          <ProtectedRoute>
            <Layout />
          </ProtectedRoute>
        }
      >
        <Route index element={<DashboardPage />} />
        <Route path="implants" element={<ImplantsPage />} />
        <Route path="implants/:id" element={<InteractPage />} />
        <Route path="listeners" element={<ListenersPage />} />
        <Route path="loot" element={<LootPage />} />
        <Route path="events" element={<EventLogPage />} />
        <Route path="operators" element={<OperatorsPage />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
