'use client'

import { useEffect, useState } from 'react'
import Header from '@/components/layout/Header'
import DataTable from '@/components/ui/DataTable'
import Badge from '@/components/ui/Badge'
import { api } from '@/lib/api'
import { formatDate } from '@/lib/utils'

export default function FindingsPage() {
  const [findings, setFindings] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [filters, setFilters] = useState({ severity: '', status: '', service: '' })

  const loadFindings = async () => {
    setLoading(true)
    try {
      const params: Record<string, string> = {}
      if (filters.severity) params.severity = filters.severity
      if (filters.status) params.status = filters.status
      if (filters.service) params.service = filters.service
      const data = await api.getFindings(params)
      setFindings(data)
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { loadFindings() }, [filters])

  const columns = [
    {
      key: 'severity',
      header: 'Severity',
      render: (item: any) => <Badge type="severity" value={item.severity} />,
      className: 'w-28',
    },
    {
      key: 'status',
      header: 'Status',
      render: (item: any) => <Badge type="status" value={item.status} />,
      className: 'w-20',
    },
    { key: 'check_title', header: 'Check', className: 'max-w-md' },
    { key: 'service', header: 'Service' },
    { key: 'resource_name', header: 'Resource', render: (item: any) => (
      <span className="text-brand-gray-600 truncate block max-w-48">{item.resource_name || item.resource_id || '-'}</span>
    )},
    { key: 'region', header: 'Region', render: (item: any) => item.region || '-' },
    {
      key: 'created_at',
      header: 'Date',
      render: (item: any) => <span className="text-brand-gray-400">{formatDate(item.created_at)}</span>,
    },
  ]

  return (
    <div>
      <Header title="Cloud Findings" subtitle="Security findings from cloud provider scans" />

      {/* Filters */}
      <div className="flex gap-4 mb-6">
        <select
          value={filters.severity}
          onChange={(e) => setFilters({ ...filters, severity: e.target.value })}
          className="px-3 py-2 border border-brand-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-brand-green outline-none"
        >
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="informational">Informational</option>
        </select>

        <select
          value={filters.status}
          onChange={(e) => setFilters({ ...filters, status: e.target.value })}
          className="px-3 py-2 border border-brand-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-brand-green outline-none"
        >
          <option value="">All Statuses</option>
          <option value="PASS">PASS</option>
          <option value="FAIL">FAIL</option>
        </select>

        <input
          type="text"
          placeholder="Filter by service..."
          value={filters.service}
          onChange={(e) => setFilters({ ...filters, service: e.target.value })}
          className="px-3 py-2 border border-brand-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-brand-green outline-none"
        />
      </div>

      <DataTable
        columns={columns}
        data={findings}
        loading={loading}
        emptyMessage="No findings yet. Run a cloud scan to generate findings."
      />
    </div>
  )
}
