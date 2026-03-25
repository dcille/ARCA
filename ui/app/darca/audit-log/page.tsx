'use client'

import { useEffect, useState } from 'react'
import Header from '@/components/layout/Header'
import { api } from '@/lib/api'
import {
  ClipboardDocumentListIcon,
  FunnelIcon,
  ArrowPathIcon,
} from '@heroicons/react/24/outline'

interface AuditEntry {
  id: string
  user_id: string
  action: string
  resource_type: string
  resource_id: string | null
  detail: string | null
  ip_address: string | null
  created_at: string
}

interface AuditStats {
  total_events: number
  by_action: Record<string, number>
  by_resource: Record<string, number>
  days: number
}

const ACTION_COLORS: Record<string, string> = {
  create: 'bg-green-100 text-green-700',
  update: 'bg-blue-100 text-blue-700',
  delete: 'bg-red-100 text-red-700',
  login: 'bg-purple-100 text-purple-700',
  logout: 'bg-purple-50 text-purple-600',
  scan: 'bg-amber-100 text-amber-700',
  export: 'bg-cyan-100 text-cyan-700',
  download: 'bg-indigo-100 text-indigo-700',
  view: 'bg-gray-100 text-gray-700',
}

export default function AuditLogPage() {
  const [logs, setLogs] = useState<AuditEntry[]>([])
  const [stats, setStats] = useState<AuditStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [actionFilter, setActionFilter] = useState('')
  const [resourceFilter, setResourceFilter] = useState('')
  const [daysFilter, setDaysFilter] = useState(30)

  const load = async () => {
    setLoading(true)
    try {
      const params: Record<string, string> = { days: String(daysFilter) }
      if (actionFilter) params.action = actionFilter
      if (resourceFilter) params.resource_type = resourceFilter

      const [logsData, statsData] = await Promise.all([
        api.getAuditLogs(params),
        api.getAuditLogStats(daysFilter),
      ])
      setLogs(logsData)
      setStats(statsData)
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [actionFilter, resourceFilter, daysFilter])

  const timeAgo = (dateStr: string) => {
    const diff = Date.now() - new Date(dateStr).getTime()
    const mins = Math.floor(diff / 60000)
    if (mins < 1) return 'Just now'
    if (mins < 60) return `${mins}m ago`
    const hours = Math.floor(mins / 60)
    if (hours < 24) return `${hours}h ago`
    const days = Math.floor(hours / 24)
    return `${days}d ago`
  }

  return (
    <div>
      <Header title="Audit Log" subtitle="Track all platform activity and user actions" />

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
          <div className="card text-center">
            <p className="text-2xl font-bold text-brand-navy">{stats.total_events}</p>
            <p className="text-xs text-brand-gray-400 uppercase font-semibold mt-1">Total Events</p>
          </div>
          <div className="card text-center">
            <p className="text-2xl font-bold text-green-600">{stats.by_action?.create || 0}</p>
            <p className="text-xs text-brand-gray-400 uppercase font-semibold mt-1">Created</p>
          </div>
          <div className="card text-center">
            <p className="text-2xl font-bold text-blue-600">{stats.by_action?.update || 0}</p>
            <p className="text-xs text-brand-gray-400 uppercase font-semibold mt-1">Updated</p>
          </div>
          <div className="card text-center">
            <p className="text-2xl font-bold text-red-600">{stats.by_action?.delete || 0}</p>
            <p className="text-xs text-brand-gray-400 uppercase font-semibold mt-1">Deleted</p>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="card mb-6">
        <div className="flex items-center gap-2 mb-4">
          <FunnelIcon className="w-5 h-5 text-brand-gray-400" />
          <h3 className="text-sm font-semibold text-brand-navy">Filters</h3>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div>
            <label className="block text-xs font-medium text-brand-gray-500 mb-1">Action</label>
            <select
              value={actionFilter}
              onChange={(e) => setActionFilter(e.target.value)}
              className="w-full select-field"
            >
              <option value="">All Actions</option>
              <option value="create">Create</option>
              <option value="update">Update</option>
              <option value="delete">Delete</option>
              <option value="login">Login</option>
              <option value="scan">Scan</option>
              <option value="export">Export</option>
              <option value="download">Download</option>
            </select>
          </div>
          <div>
            <label className="block text-xs font-medium text-brand-gray-500 mb-1">Resource Type</label>
            <select
              value={resourceFilter}
              onChange={(e) => setResourceFilter(e.target.value)}
              className="w-full select-field"
            >
              <option value="">All Resources</option>
              <option value="provider">Provider</option>
              <option value="scan">Scan</option>
              <option value="schedule">Schedule</option>
              <option value="integration">Integration</option>
              <option value="finding">Finding</option>
              <option value="report">Report</option>
              <option value="organization">Organization</option>
              <option value="saas_connection">SaaS Connection</option>
            </select>
          </div>
          <div>
            <label className="block text-xs font-medium text-brand-gray-500 mb-1">Time Period</label>
            <select
              value={daysFilter}
              onChange={(e) => setDaysFilter(Number(e.target.value))}
              className="w-full select-field"
            >
              <option value={7}>Last 7 days</option>
              <option value={14}>Last 14 days</option>
              <option value={30}>Last 30 days</option>
              <option value={60}>Last 60 days</option>
              <option value={90}>Last 90 days</option>
            </select>
          </div>
          <div className="flex items-end">
            <button onClick={load} className="flex items-center gap-2 px-4 py-2 text-sm text-brand-gray-500 hover:text-brand-navy border border-brand-gray-300 rounded-lg hover:bg-brand-gray-50 transition-colors">
              <ArrowPathIcon className="w-4 h-4" />
              Refresh
            </button>
          </div>
        </div>
      </div>

      {/* Log entries */}
      {loading ? (
        <div className="card animate-pulse"><div className="h-48 bg-brand-gray-100 rounded" /></div>
      ) : logs.length === 0 ? (
        <div className="card text-center py-16">
          <ClipboardDocumentListIcon className="w-12 h-12 text-brand-gray-300 mx-auto mb-4" />
          <h3 className="text-lg font-semibold text-brand-navy mb-2">No Activity Found</h3>
          <p className="text-brand-gray-400">
            Audit log entries will appear here as you interact with the platform.
          </p>
        </div>
      ) : (
        <div className="card overflow-hidden p-0">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-brand-gray-200 bg-brand-gray-50">
                <th className="text-left py-3 px-4 text-xs font-semibold text-brand-gray-500 uppercase">Time</th>
                <th className="text-left py-3 px-4 text-xs font-semibold text-brand-gray-500 uppercase">Action</th>
                <th className="text-left py-3 px-4 text-xs font-semibold text-brand-gray-500 uppercase">Resource</th>
                <th className="text-left py-3 px-4 text-xs font-semibold text-brand-gray-500 uppercase">Resource ID</th>
                <th className="text-left py-3 px-4 text-xs font-semibold text-brand-gray-500 uppercase">Details</th>
                <th className="text-left py-3 px-4 text-xs font-semibold text-brand-gray-500 uppercase">IP</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((log) => (
                <tr key={log.id} className="border-b border-brand-gray-100 hover:bg-brand-gray-50/50">
                  <td className="py-3 px-4">
                    <span className="text-xs text-brand-gray-500" title={new Date(log.created_at).toLocaleString()}>
                      {timeAgo(log.created_at)}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold ${ACTION_COLORS[log.action] || 'bg-gray-100 text-gray-600'}`}>
                      {log.action}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <span className="text-xs text-brand-gray-600 font-medium">{log.resource_type}</span>
                  </td>
                  <td className="py-3 px-4">
                    <span className="text-xs text-brand-gray-400 font-mono truncate max-w-[120px] block">
                      {log.resource_id || '-'}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <span className="text-xs text-brand-gray-500 truncate max-w-[200px] block">
                      {log.detail || '-'}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <span className="text-xs text-brand-gray-400 font-mono">{log.ip_address || '-'}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
