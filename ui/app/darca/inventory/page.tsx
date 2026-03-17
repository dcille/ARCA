'use client'

import { Fragment, useEffect, useState } from 'react'
import Link from 'next/link'
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
  ChevronDownIcon,
  ArrowTopRightOnSquareIcon,
} from '@heroicons/react/24/outline'

function parseEvidenceLog(raw?: string | null): { api_call?: string; response?: string } | null {
  if (!raw) return null
  try {
    return JSON.parse(raw)
  } catch {
    return null
  }
}

function ResourceExpandedRow({
  resource,
  findings,
  loadingFindings,
}: {
  resource: any
  findings: any[]
  loadingFindings: boolean
}) {
  return (
    <tr>
      <td colSpan={9} className="px-0 py-0">
        <div className="px-6 py-5 bg-brand-gray-50 border-t border-brand-gray-200">
          {/* Resource Details */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-5">
            <div>
              <h4 className="text-xs font-semibold text-brand-gray-500 uppercase tracking-wider mb-2">
                Resource Details
              </h4>
              <dl className="space-y-1 text-sm">
                <div className="flex gap-2">
                  <dt className="text-brand-gray-400 font-medium min-w-[90px]">ID</dt>
                  <dd className="text-brand-gray-700 break-all font-mono text-xs">{resource.resource_id}</dd>
                </div>
                {resource.resource_name && resource.resource_name !== resource.resource_id && (
                  <div className="flex gap-2">
                    <dt className="text-brand-gray-400 font-medium min-w-[90px]">Name</dt>
                    <dd className="text-brand-gray-700">{resource.resource_name}</dd>
                  </div>
                )}
                <div className="flex gap-2">
                  <dt className="text-brand-gray-400 font-medium min-w-[90px]">Service</dt>
                  <dd className="text-brand-gray-700">{resource.service}</dd>
                </div>
                <div className="flex gap-2">
                  <dt className="text-brand-gray-400 font-medium min-w-[90px]">Region</dt>
                  <dd className="text-brand-gray-700">{resource.region || '-'}</dd>
                </div>
              </dl>
            </div>
            <div>
              <h4 className="text-xs font-semibold text-brand-gray-500 uppercase tracking-wider mb-2">
                Account
              </h4>
              <dl className="space-y-1 text-sm">
                <div className="flex gap-2">
                  <dt className="text-brand-gray-400 font-medium min-w-[90px]">Provider</dt>
                  <dd className="text-brand-gray-700">{resource.provider_type?.toUpperCase()}</dd>
                </div>
                <div className="flex gap-2">
                  <dt className="text-brand-gray-400 font-medium min-w-[90px]">Alias</dt>
                  <dd className="text-brand-gray-700">{resource.provider_alias || '-'}</dd>
                </div>
                {resource.account_id && (
                  <div className="flex gap-2">
                    <dt className="text-brand-gray-400 font-medium min-w-[90px]">Account ID</dt>
                    <dd className="text-brand-gray-700 font-mono text-xs">{resource.account_id}</dd>
                  </div>
                )}
              </dl>
            </div>
            <div>
              <h4 className="text-xs font-semibold text-brand-gray-500 uppercase tracking-wider mb-2">
                Security Summary
              </h4>
              <div className="flex items-center gap-3">
                <div className={cn(
                  'px-3 py-1.5 rounded-lg text-center',
                  resource.status === 'at_risk' ? 'bg-red-50' : 'bg-green-50'
                )}>
                  <p className={cn(
                    'text-sm font-bold',
                    resource.status === 'at_risk' ? 'text-red-700' : 'text-green-700'
                  )}>
                    {resource.status === 'at_risk' ? 'At Risk' : 'Compliant'}
                  </p>
                </div>
                <div className="text-sm">
                  <span className="text-red-600 font-semibold">{resource.failed_findings}</span>
                  <span className="text-brand-gray-400"> failed / </span>
                  <span className="text-green-600 font-semibold">{resource.passed_findings}</span>
                  <span className="text-brand-gray-400"> passed</span>
                </div>
              </div>
            </div>
          </div>

          {/* Findings List */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <h4 className="text-xs font-semibold text-brand-gray-500 uppercase tracking-wider">
                Findings ({findings.length})
              </h4>
              {findings.length > 0 && (
                <Link
                  href={`/darca/findings?search=${encodeURIComponent(resource.resource_id)}`}
                  className="inline-flex items-center gap-1 text-xs text-brand-green hover:underline font-medium"
                >
                  View all in Findings
                  <ArrowTopRightOnSquareIcon className="w-3.5 h-3.5" />
                </Link>
              )}
            </div>

            {loadingFindings ? (
              <div className="space-y-2">
                {[...Array(3)].map((_, i) => (
                  <div key={i} className="h-12 bg-brand-gray-100 rounded animate-pulse" />
                ))}
              </div>
            ) : findings.length === 0 ? (
              <p className="text-sm text-brand-gray-400 italic py-4">No findings for this resource.</p>
            ) : (
              <div className="space-y-2">
                {findings.map((f: any) => {
                  const evidence = parseEvidenceLog(f.evidence_log)
                  return (
                    <Link
                      key={f.id}
                      href={`/darca/findings?search=${encodeURIComponent(f.check_id)}`}
                      className={cn(
                        'block rounded-lg border p-3 transition-colors hover:shadow-sm',
                        f.status === 'FAIL'
                          ? 'border-red-200 bg-white hover:bg-red-50/30'
                          : 'border-green-200 bg-white hover:bg-green-50/30'
                      )}
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1">
                            <span className="text-[10px] font-mono text-brand-gray-400">{f.check_id}</span>
                            <Badge type="severity" value={f.severity} />
                            <span className={cn(
                              'px-1.5 py-0.5 rounded text-[10px] font-medium',
                              f.status === 'FAIL' ? 'bg-red-100 text-red-700' : 'bg-green-100 text-green-700'
                            )}>
                              {f.status}
                            </span>
                          </div>
                          <p className="text-sm font-medium text-brand-navy">{f.check_title}</p>
                          {f.status_extended && (
                            <p className="text-xs text-brand-gray-500 mt-1 line-clamp-2">{f.status_extended}</p>
                          )}
                        </div>
                        <ArrowTopRightOnSquareIcon className="w-4 h-4 text-brand-gray-300 flex-shrink-0 mt-1" />
                      </div>

                      {/* Compact evidence */}
                      {evidence?.api_call && (
                        <div className="mt-2 bg-brand-navy rounded px-2.5 py-1.5 font-mono text-[10px] text-gray-300 truncate">
                          <span className="text-brand-green">$ </span>
                          {evidence.api_call}
                        </div>
                      )}
                    </Link>
                  )
                })}
              </div>
            )}
          </div>
        </div>
      </td>
    </tr>
  )
}

export default function InventoryPage() {
  const [resources, setResources] = useState<any[]>([])
  const [summary, setSummary] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set())
  const [resourceFindings, setResourceFindings] = useState<Record<string, any[]>>({})
  const [loadingFindings, setLoadingFindings] = useState<Set<string>>(new Set())
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

  const toggleRow = async (resourceId: string) => {
    const next = new Set(expandedRows)
    if (next.has(resourceId)) {
      next.delete(resourceId)
      setExpandedRows(next)
      return
    }
    next.add(resourceId)
    setExpandedRows(next)

    // Load findings if not already loaded
    if (!resourceFindings[resourceId]) {
      setLoadingFindings((prev) => new Set(prev).add(resourceId))
      try {
        const findings = await api.getResourceFindings(resourceId)
        setResourceFindings((prev) => ({ ...prev, [resourceId]: findings }))
      } catch (err) {
        console.error(err)
        setResourceFindings((prev) => ({ ...prev, [resourceId]: [] }))
      } finally {
        setLoadingFindings((prev) => {
          const n = new Set(prev)
          n.delete(resourceId)
          return n
        })
      }
    }
  }

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
            <option value="alibaba">Alibaba Cloud</option>
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
                  <th className="w-8 px-2 py-3" />
                  <th className="text-left text-xs font-semibold text-brand-gray-500 uppercase px-4 py-3">Resource</th>
                  <th className="text-left text-xs font-semibold text-brand-gray-500 uppercase px-4 py-3">Service</th>
                  <th className="text-left text-xs font-semibold text-brand-gray-500 uppercase px-4 py-3">Provider</th>
                  <th className="text-left text-xs font-semibold text-brand-gray-500 uppercase px-4 py-3">Account</th>
                  <th className="text-left text-xs font-semibold text-brand-gray-500 uppercase px-4 py-3">Region</th>
                  <th className="text-center text-xs font-semibold text-brand-gray-500 uppercase px-4 py-3">Status</th>
                  <th className="text-center text-xs font-semibold text-brand-gray-500 uppercase px-4 py-3">Findings</th>
                  <th className="text-center text-xs font-semibold text-brand-gray-500 uppercase px-4 py-3">Severity</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-brand-gray-100">
                {resources.map((r, i) => {
                  const isExpanded = expandedRows.has(r.resource_id)
                  return (
                    <Fragment key={r.resource_id || i}>
                      <tr
                        onClick={() => toggleRow(r.resource_id)}
                        className={cn(
                          'cursor-pointer transition-colors',
                          isExpanded ? 'bg-brand-gray-50' : 'hover:bg-brand-gray-50'
                        )}
                      >
                        <td className="px-2 py-3 text-center">
                          <ChevronDownIcon
                            className={cn(
                              'w-4 h-4 text-brand-gray-400 transition-transform duration-200 mx-auto',
                              isExpanded && 'rotate-180'
                            )}
                          />
                        </td>
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
                        </td>
                        <td className="px-4 py-3">
                          <span className="text-xs font-medium text-brand-navy">{r.provider_alias || '-'}</span>
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
                      {isExpanded && (
                        <ResourceExpandedRow
                          resource={r}
                          findings={resourceFindings[r.resource_id] || []}
                          loadingFindings={loadingFindings.has(r.resource_id)}
                        />
                      )}
                    </Fragment>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
