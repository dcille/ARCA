'use client'

import { useEffect, useState } from 'react'
import Header from '@/components/layout/Header'
import StatCard from '@/components/ui/StatCard'
import Badge from '@/components/ui/Badge'
import { api } from '@/lib/api'
import { cn } from '@/lib/utils'
import {
  ServerStackIcon,
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  MagnifyingGlassIcon,
  FunnelIcon,
  ChartPieIcon,
} from '@heroicons/react/24/outline'

export default function InventoryPage() {
  const [resources, setResources] = useState<any[]>([])
  const [summary, setSummary] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [filters, setFilters] = useState({
    provider_type: '',
    service: '',
    region: '',
    status: '',
    search: '',
  })

  const loadData = async () => {
    setLoading(true)
    try {
      const params: Record<string, string> = {}
      if (filters.provider_type) params.provider_type = filters.provider_type
      if (filters.service) params.service = filters.service
      if (filters.region) params.region = filters.region
      if (filters.status) params.status = filters.status
      if (filters.search) params.search = filters.search

      const [resourcesData, summaryData] = await Promise.all([
        api.getInventoryResources(params),
        api.getInventorySummary(filters.provider_type ? { provider_type: filters.provider_type } : undefined),
      ])
      setResources(resourcesData)
      setSummary(summaryData)
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { loadData() }, [filters])

  const severityColor: Record<string, string> = {
    critical: 'text-severity-critical',
    high: 'text-severity-high',
    medium: 'text-severity-medium',
    low: 'text-severity-low',
  }

  return (
    <div>
      <Header title="Asset Inventory" subtitle="Discovered cloud resources and their security posture" />

      {/* Summary Stats */}
      {summary && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
          <StatCard
            title="Total Resources"
            value={summary.total_resources}
            icon={<ServerStackIcon className="w-5 h-5" />}
          />
          <StatCard
            title="At Risk"
            value={summary.at_risk}
            icon={<ExclamationTriangleIcon className="w-5 h-5" />}
            valueColor="text-severity-high"
          />
          <StatCard
            title="Compliant"
            value={summary.compliant}
            icon={<ShieldCheckIcon className="w-5 h-5" />}
            valueColor="text-brand-green"
          />
          <StatCard
            title="Compliance Rate"
            value={`${summary.compliance_rate}%`}
            icon={<ChartPieIcon className="w-5 h-5" />}
            valueColor={summary.compliance_rate >= 70 ? 'text-brand-green' : 'text-severity-high'}
          />
        </div>
      )}

      {/* Filters */}
      <div className="card mb-6">
        <div className="flex items-center gap-2 mb-4">
          <FunnelIcon className="w-4 h-4 text-brand-gray-400" />
          <span className="text-sm font-semibold text-brand-navy">Filters</span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-3">
          <div className="relative lg:col-span-2">
            <MagnifyingGlassIcon className="w-4 h-4 absolute left-3 top-2.5 text-brand-gray-400" />
            <input
              type="text"
              placeholder="Search resources..."
              value={filters.search}
              onChange={(e) => setFilters({ ...filters, search: e.target.value })}
              className="w-full pl-9 pr-3 py-2 border border-brand-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-brand-green outline-none"
            />
          </div>
          <select
            value={filters.provider_type}
            onChange={(e) => setFilters({ ...filters, provider_type: e.target.value })}
            className="px-3 py-2 border border-brand-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-brand-green outline-none"
          >
            <option value="">All Providers</option>
            <option value="aws">AWS</option>
            <option value="azure">Azure</option>
            <option value="gcp">GCP</option>
            <option value="oci">OCI</option>
            <option value="kubernetes">Kubernetes</option>
          </select>
          <input
            type="text"
            placeholder="Service filter"
            value={filters.service}
            onChange={(e) => setFilters({ ...filters, service: e.target.value })}
            className="px-3 py-2 border border-brand-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-brand-green outline-none"
          />
          <select
            value={filters.status}
            onChange={(e) => setFilters({ ...filters, status: e.target.value })}
            className="px-3 py-2 border border-brand-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-brand-green outline-none"
          >
            <option value="">All Status</option>
            <option value="at_risk">At Risk</option>
            <option value="compliant">Compliant</option>
          </select>
        </div>
      </div>

      {/* Service Distribution */}
      {summary?.by_service && Object.keys(summary.by_service).length > 0 && (
        <div className="card mb-6">
          <h3 className="text-sm font-semibold text-brand-navy mb-3">Resources by Service</h3>
          <div className="flex flex-wrap gap-2">
            {Object.entries(summary.by_service as Record<string, number>).slice(0, 12).map(([svc, count]) => (
              <button
                key={svc}
                onClick={() => setFilters({ ...filters, service: filters.service === svc ? '' : svc })}
                className={cn(
                  'px-3 py-1.5 rounded-full text-xs font-medium transition-colors border',
                  filters.service === svc
                    ? 'bg-brand-green text-white border-brand-green'
                    : 'bg-brand-gray-50 text-brand-gray-600 border-brand-gray-200 hover:border-brand-green'
                )}
              >
                {svc} ({count})
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Resources Table */}
      {loading ? (
        <div className="card animate-pulse">
          <div className="space-y-3">
            {[...Array(5)].map((_, i) => (
              <div key={i} className="h-12 bg-brand-gray-100 rounded" />
            ))}
          </div>
        </div>
      ) : resources.length === 0 ? (
        <div className="card text-center py-16">
          <ServerStackIcon className="w-16 h-16 mx-auto text-brand-gray-300 mb-4" />
          <h3 className="text-lg font-semibold text-brand-navy mb-2">No Resources Found</h3>
          <p className="text-sm text-brand-gray-400">
            Run a cloud scan to discover resources in your environment.
          </p>
        </div>
      ) : (
        <div className="card overflow-hidden p-0">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="bg-brand-gray-50 border-b border-brand-gray-200">
                  <th className="text-left text-xs font-semibold text-brand-gray-500 uppercase px-4 py-3">Resource</th>
                  <th className="text-left text-xs font-semibold text-brand-gray-500 uppercase px-4 py-3">Service</th>
                  <th className="text-left text-xs font-semibold text-brand-gray-500 uppercase px-4 py-3">Provider</th>
                  <th className="text-left text-xs font-semibold text-brand-gray-500 uppercase px-4 py-3">Region</th>
                  <th className="text-center text-xs font-semibold text-brand-gray-500 uppercase px-4 py-3">Status</th>
                  <th className="text-center text-xs font-semibold text-brand-gray-500 uppercase px-4 py-3">Findings</th>
                  <th className="text-center text-xs font-semibold text-brand-gray-500 uppercase px-4 py-3">Severity</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-brand-gray-100">
                {resources.map((r, i) => (
                  <tr key={i} className="hover:bg-brand-gray-50 transition-colors">
                    <td className="px-4 py-3">
                      <p className="text-sm font-medium text-brand-navy truncate max-w-xs">
                        {r.resource_name || r.resource_id}
                      </p>
                      {r.resource_name && r.resource_id && r.resource_name !== r.resource_id && (
                        <p className="text-xs text-brand-gray-400 truncate max-w-xs">{r.resource_id}</p>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-xs font-medium text-brand-gray-600 bg-brand-gray-100 px-2 py-1 rounded">
                        {r.service}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-xs text-brand-gray-600">{r.provider_type?.toUpperCase()}</span>
                      {r.account_id && (
                        <p className="text-[10px] text-brand-gray-400">{r.account_id}</p>
                      )}
                    </td>
                    <td className="px-4 py-3 text-xs text-brand-gray-500">{r.region || '-'}</td>
                    <td className="px-4 py-3 text-center">
                      <span className={cn(
                        'inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium',
                        r.status === 'at_risk'
                          ? 'bg-red-50 text-red-700'
                          : 'bg-green-50 text-green-700'
                      )}>
                        {r.status === 'at_risk' ? 'At Risk' : 'Compliant'}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-center">
                      <span className="text-xs text-brand-gray-600">
                        <span className="text-red-600 font-medium">{r.failed_findings}</span>
                        {' / '}
                        <span className="text-green-600">{r.passed_findings}</span>
                      </span>
                    </td>
                    <td className="px-4 py-3 text-center">
                      {r.failed_findings > 0 && <Badge type="severity" value={r.max_severity} />}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
