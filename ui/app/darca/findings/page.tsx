'use client'

import { useEffect, useState, useMemo } from 'react'
import Header from '@/components/layout/Header'
import Badge from '@/components/ui/Badge'
import { api } from '@/lib/api'
import { formatDate } from '@/lib/utils'

const PROVIDER_LABELS: Record<string, { label: string; color: string }> = {
  aws: { label: 'AWS', color: 'bg-amber-100 text-amber-800' },
  azure: { label: 'Azure', color: 'bg-blue-100 text-blue-800' },
  gcp: { label: 'GCP', color: 'bg-red-100 text-red-800' },
  kubernetes: { label: 'K8s', color: 'bg-purple-100 text-purple-800' },
}

function ProviderBadge({ provider }: { provider?: string | null }) {
  if (!provider) return <span className="text-brand-gray-400">-</span>
  const cfg = PROVIDER_LABELS[provider.toLowerCase()] ?? {
    label: provider,
    color: 'bg-brand-gray-100 text-brand-gray-600',
  }
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${cfg.color}`}>
      {cfg.label}
    </span>
  )
}

function ChevronDownIcon({ className }: { className?: string }) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 20 20"
      fill="currentColor"
      className={className ?? 'w-5 h-5'}
    >
      <path
        fillRule="evenodd"
        d="M5.22 8.22a.75.75 0 0 1 1.06 0L10 11.94l3.72-3.72a.75.75 0 1 1 1.06 1.06l-4.25 4.25a.75.75 0 0 1-1.06 0L5.22 9.28a.75.75 0 0 1 0-1.06Z"
        clipRule="evenodd"
      />
    </svg>
  )
}

function parseComplianceFrameworks(raw?: string | null): string[] {
  if (!raw) return []
  try {
    const parsed = JSON.parse(raw)
    if (Array.isArray(parsed)) return parsed
    if (typeof parsed === 'object') return Object.keys(parsed)
    return [String(parsed)]
  } catch {
    return raw.split(',').map((s) => s.trim()).filter(Boolean)
  }
}

function ExpandedRow({ item }: { item: any }) {
  const frameworks = useMemo(() => parseComplianceFrameworks(item.compliance_frameworks), [item.compliance_frameworks])

  return (
    <tr>
      <td colSpan={9} className="px-0 py-0">
        <div className="overflow-hidden transition-all duration-300 ease-in-out">
          <div className="px-8 py-6 bg-brand-gray-50 border-t border-brand-gray-200 grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Risk description */}
            <div>
              <h4 className="text-xs font-semibold text-brand-gray-500 uppercase tracking-wider mb-2">
                Risk Description
              </h4>
              <p className="text-sm text-brand-gray-700 font-medium">{item.check_title}</p>
              <div className="mt-1 flex items-center gap-2">
                <Badge type="severity" value={item.severity} />
                <Badge type="status" value={item.status} />
              </div>
            </div>

            {/* Evidence */}
            <div>
              <h4 className="text-xs font-semibold text-brand-gray-500 uppercase tracking-wider mb-2">
                Evidence
              </h4>
              <p className="text-sm text-brand-gray-600">
                {item.status_extended || 'No additional evidence available.'}
              </p>
            </div>

            {/* Resource details */}
            <div>
              <h4 className="text-xs font-semibold text-brand-gray-500 uppercase tracking-wider mb-2">
                Resource Details
              </h4>
              <dl className="space-y-1 text-sm">
                <div className="flex gap-2">
                  <dt className="text-brand-gray-400 font-medium min-w-[100px]">Resource ID</dt>
                  <dd className="text-brand-gray-700 break-all">{item.resource_id || '-'}</dd>
                </div>
                <div className="flex gap-2">
                  <dt className="text-brand-gray-400 font-medium min-w-[100px]">Resource Name</dt>
                  <dd className="text-brand-gray-700 break-all">{item.resource_name || '-'}</dd>
                </div>
                <div className="flex gap-2">
                  <dt className="text-brand-gray-400 font-medium min-w-[100px]">Region</dt>
                  <dd className="text-brand-gray-700">{item.region || '-'}</dd>
                </div>
                <div className="flex gap-2">
                  <dt className="text-brand-gray-400 font-medium min-w-[100px]">Service</dt>
                  <dd className="text-brand-gray-700">{item.service}</dd>
                </div>
              </dl>
            </div>

            {/* Remediation */}
            <div>
              <h4 className="text-xs font-semibold text-brand-gray-500 uppercase tracking-wider mb-2">
                Remediation
              </h4>
              {item.remediation ? (
                <p className="text-sm text-brand-gray-600">{item.remediation}</p>
              ) : (
                <p className="text-sm text-brand-gray-400 italic">No remediation steps available.</p>
              )}
              {item.remediation_url && (
                <a
                  href={item.remediation_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 mt-2 text-sm text-brand-green hover:underline"
                >
                  View remediation guide &rarr;
                </a>
              )}
            </div>

            {/* Compliance frameworks */}
            {frameworks.length > 0 && (
              <div className="md:col-span-2">
                <h4 className="text-xs font-semibold text-brand-gray-500 uppercase tracking-wider mb-2">
                  Compliance Frameworks
                </h4>
                <div className="flex flex-wrap gap-2">
                  {frameworks.map((fw) => (
                    <span
                      key={fw}
                      className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-brand-gray-100 text-brand-gray-700"
                    >
                      {fw}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </td>
    </tr>
  )
}

export default function FindingsPage() {
  const [findings, setFindings] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [filters, setFilters] = useState({ severity: '', status: '', service: '' })
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set())

  const toggleRow = (id: string) => {
    setExpandedRows((prev) => {
      const next = new Set(prev)
      if (next.has(id)) {
        next.delete(id)
      } else {
        next.add(id)
      }
      return next
    })
  }

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

      {/* Findings Table */}
      {loading ? (
        <div className="card">
          <div className="animate-pulse space-y-4">
            <div className="h-10 bg-brand-gray-100 rounded" />
            {[...Array(5)].map((_, i) => (
              <div key={i} className="h-12 bg-brand-gray-50 rounded" />
            ))}
          </div>
        </div>
      ) : (
        <div className="card overflow-hidden p-0">
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-brand-gray-200">
              <thead>
                <tr className="bg-brand-gray-50">
                  <th className="w-10 px-3 py-3" />
                  <th className="px-6 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase tracking-wider w-28">
                    Severity
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase tracking-wider w-20">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase tracking-wider w-24">
                    Source
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase tracking-wider max-w-md">
                    Check
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase tracking-wider">
                    Service
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase tracking-wider">
                    Resource
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase tracking-wider">
                    Region
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase tracking-wider">
                    Date
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-brand-gray-100">
                {findings.length === 0 ? (
                  <tr>
                    <td colSpan={9} className="px-6 py-12 text-center text-brand-gray-400">
                      No findings yet. Run a cloud scan to generate findings.
                    </td>
                  </tr>
                ) : (
                  findings.map((item) => {
                    const isExpanded = expandedRows.has(item.id)
                    return (
                      <>
                        <tr
                          key={item.id}
                          onClick={() => toggleRow(item.id)}
                          className="hover:bg-brand-gray-50 transition-colors cursor-pointer select-none"
                        >
                          <td className="px-3 py-4 text-brand-gray-400">
                            <ChevronDownIcon
                              className={`w-5 h-5 transition-transform duration-200 ${
                                isExpanded ? 'rotate-180' : ''
                              }`}
                            />
                          </td>
                          <td className="px-6 py-4 text-sm w-28">
                            <Badge type="severity" value={item.severity} />
                          </td>
                          <td className="px-6 py-4 text-sm w-20">
                            <Badge type="status" value={item.status} />
                          </td>
                          <td className="px-6 py-4 text-sm w-24">
                            <ProviderBadge provider={item.provider_type} />
                          </td>
                          <td className="px-6 py-4 text-sm max-w-md">{item.check_title}</td>
                          <td className="px-6 py-4 text-sm">{item.service}</td>
                          <td className="px-6 py-4 text-sm">
                            <span className="text-brand-gray-600 truncate block max-w-48">
                              {item.resource_name || item.resource_id || '-'}
                            </span>
                          </td>
                          <td className="px-6 py-4 text-sm">{item.region || '-'}</td>
                          <td className="px-6 py-4 text-sm">
                            <span className="text-brand-gray-400">{formatDate(item.created_at)}</span>
                          </td>
                        </tr>
                        {isExpanded && <ExpandedRow key={`${item.id}-detail`} item={item} />}
                      </>
                    )
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
