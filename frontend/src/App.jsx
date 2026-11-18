
import { useEffect, useMemo, useState } from 'react'
import {
  BarChart, Bar, LineChart, Line,
  XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer
} from 'recharts'
import './App.css'

function App() {
  const [stats, setStats] = useState(null)
  const [attacks, setAttacks] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')
  const [eventFilter, setEventFilter] = useState('all')

  async function loadData() {
    setLoading(true)
    setError('')

    try {
      const [statsRes, attacksRes] = await Promise.all([
        fetch('/api/stats'),
        fetch('/api/attacks?limit=500')
      ])

      if (!statsRes.ok || !attacksRes.ok) {
        throw new Error('Unable to fetch security data')
      }

      setStats(await statsRes.json())
      setAttacks(await attacksRes.json())
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadData()
  }, [])

  const eventTypes = useMemo(() => {
    return [...new Set(
      attacks.map(a => a.event_type).filter(Boolean)
    )].sort()
  }, [attacks])

  const filteredAttacks = useMemo(() => {
    const query = search.toLowerCase().trim()

    return attacks.filter(attack => {
      const matchesType =
        eventFilter === 'all' ||
        attack.event_type === eventFilter

      const searchable = [
        attack.source_ip,
        attack.username,
        attack.command,
        attack.event_type,
        attack.session_id
      ].filter(Boolean).join(' ').toLowerCase()

      return matchesType && searchable.includes(query)
    })
  }, [attacks, search, eventFilter])

  const eventChartData = useMemo(() => {
    const counts = {}

    attacks.forEach(attack => {
      const type = attack.event_type || 'unknown'
      const name = type.replace('cowrie.', '')
      counts[name] = (counts[name] || 0) + 1
    })

    return Object.entries(counts)
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count)
  }, [attacks])

  const timelineData = useMemo(() => {
    const counts = {}

    attacks.forEach(attack => {
      if (!attack.timestamp) return

      // Group ISO timestamps by hour.
      const hour = attack.timestamp.slice(0, 13)
      counts[hour] = (counts[hour] || 0) + 1
    })

    return Object.entries(counts)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([hour, count]) => ({
        hour,
        label: hour.replace('T', ' ') + ':00',
        count
      }))
  }, [attacks])

  return (
    <div className="dashboard">
      <header>
        <div>
          <h1>🛡️ CyberTrap</h1>
          <p>SSH Honeypot Threat Intelligence Dashboard</p>
        </div>

        <button onClick={loadData} disabled={loading}>
          {loading ? 'Loading...' : 'Refresh Data'}
        </button>
      </header>

      {error && <p className="error">{error}</p>}

      {stats && (
        <section className="stats">
          {[
            ['Total Events', stats.total_events],
            ['Successful Logins', stats.successful_logins],
            ['Failed Logins', stats.failed_logins],
            ['Commands Executed', stats.commands_executed]
          ].map(([label, value]) => (
            <div className="stat-card" key={label}>
              <span>{label}</span>
              <h2>{value}</h2>
            </div>
          ))}
        </section>
      )}

      <section className="charts">
        <div className="panel">
          <h2>Attack Activity Over Time</h2>
          <p className="panel-subtitle">
            Recorded events grouped by hour (UTC)
          </p>

          <div className="chart-container">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={timelineData}>
                <CartesianGrid
                  stroke="#334155"
                  strokeDasharray="3 3"
                />
                <XAxis
                  dataKey="label"
                  stroke="#94a3b8"
                  tick={{ fontSize: 10 }}
                />
                <YAxis
                  stroke="#94a3b8"
                  allowDecimals={false}
                />
                <Tooltip
                  contentStyle={{
                    background: '#172338',
                    border: '1px solid #334155',
                    color: '#fff'
                  }}
                />
                <Line
                  type="monotone"
                  dataKey="count"
                  name="Events"
                  stroke="#38bdf8"
                  strokeWidth={3}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="panel">
          <h2>Security Event Distribution</h2>
          <p className="panel-subtitle">
            Number of events by type
          </p>

          <div className="chart-container">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={eventChartData}>
                <CartesianGrid
                  stroke="#334155"
                  strokeDasharray="3 3"
                />
                <XAxis
                  dataKey="name"
                  stroke="#94a3b8"
                  tick={{ fontSize: 10 }}
                  angle={-35}
                  textAnchor="end"
                  height={90}
                  interval={0}
                />
                <YAxis
                  stroke="#94a3b8"
                  allowDecimals={false}
                />
                <Tooltip
                  contentStyle={{
                    background: '#172338',
                    border: '1px solid #334155'
                  }}
                />
                <Bar
                  dataKey="count"
                  name="Events"
                  fill="#38bdf8"
                  radius={[5, 5, 0, 0]}
                />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </section>

      <section className="panel">
        <h2>Recent Honeypot Activity</h2>

        <div className="filters">
          <input
            type="text"
            placeholder="Search IP, username, command..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />

          <select
            value={eventFilter}
            onChange={e => setEventFilter(e.target.value)}
          >
            <option value="all">All Event Types</option>
            {eventTypes.map(type => (
              <option key={type} value={type}>
                {type}
              </option>
            ))}
          </select>
        </div>

        <p className="panel-subtitle">
          Showing {filteredAttacks.length} of {attacks.length}
          {' '}loaded events
        </p>

        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Event Type</th>
                <th>Source IP</th>
                <th>Username</th>
                <th>Command</th>
              </tr>
            </thead>

            <tbody>
              {filteredAttacks.map(attack => (
                <tr key={attack.id}>
                  <td>{attack.timestamp || '-'}</td>
                  <td>{attack.event_type || '-'}</td>
                  <td>{attack.source_ip || '-'}</td>
                  <td>{attack.username || '-'}</td>
                  <td>{attack.command || '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {filteredAttacks.length === 0 && !loading && (
          <p>No matching security events found.</p>
        )}
      </section>

      <footer>
        CyberTrap Security Monitoring Platform
      </footer>
    </div>
  )
}

export default App
