'use client'

import { useEffect, useState } from 'react'
import Header from '@/components/layout/Header'
import { api } from '@/lib/api'
import { formatPercent } from '@/lib/utils'
import { XMarkIcon, ChevronDownIcon, ChevronRightIcon, BookOpenIcon } from '@heroicons/react/24/outline'

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-100 text-red-800',
  high: 'bg-orange-100 text-orange-800',
  medium: 'bg-yellow-100 text-yellow-800',
  low: 'bg-blue-100 text-blue-800',
  informational: 'bg-gray-100 text-gray-600',
}

const STATUS_COLORS: Record<string, string> = {
  PASS: 'bg-green-100 text-green-800',
  FAIL: 'bg-red-100 text-red-800',
}

const PROVIDER_LABELS: Record<string, string> = {
  aws: 'AWS',
  azure: 'Azure',
  gcp: 'GCP',
  oci: 'OCI',
  alibaba: 'Alibaba',
  k8s: 'Kubernetes',
}

const PROVIDER_COLORS: Record<string, string> = {
  aws: 'bg-[#FF9900]/10 text-[#FF9900] border-[#FF9900]/30',
  azure: 'bg-[#0078D4]/10 text-[#0078D4] border-[#0078D4]/30',
  gcp: 'bg-[#4285F4]/10 text-[#4285F4] border-[#4285F4]/30',
  oci: 'bg-[#C74634]/10 text-[#C74634] border-[#C74634]/30',
  alibaba: 'bg-[#FF6A00]/10 text-[#FF6A00] border-[#FF6A00]/30',
  k8s: 'bg-[#326CE5]/10 text-[#326CE5] border-[#326CE5]/30',
}

export default function CompliancePage() {
  const [frameworks, setFrameworks] = useState<any[]>([])
  const [summaries, setSummaries] = useState<Record<string, any>>({})
  const [loading, setLoading] = useState(true)

  // Detail view state
  const [selectedFramework, setSelectedFramework] = useState<string | null>(null)
  const [detailData, setDetailData] = useState<any>(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [severityFilter, setSeverityFilter] = useState<string>('all')
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set())

  // Check library state
  const [showLibrary, setShowLibrary] = useState(false)
  const [libraryData, setLibraryData] = useState<any>(null)
  const [libraryLoading, setLibraryLoading] = useState(false)
  const [expandedControls, setExpandedControls] = useState<Set<string>>(new Set())

  useEffect(() => {
    const load = async () => {
      try {
        const fws = await api.getComplianceFrameworks()
        setFrameworks(fws)

        const sums: Record<string, any> = {}
        for (const fw of fws) {
          try {
            sums[fw.id] = await api.getComplianceSummary(fw.id)
          } catch {
            sums[fw.id] = { total_checks: 0, passed: 0, failed: 0, pass_rate: 0 }
          }
        }
        setSummaries(sums)
      } catch (err) {
        console.error(err)
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [])

  const loadFrameworkDetail = async (frameworkId: string, status?: string, severity?: string) => {
    setDetailLoading(true)
    try {
      const params: Record<string, string> = {}
      if (status && status !== 'all') params.status = status
      if (severity && severity !== 'all') params.severity = severity
      const data = await api.getComplianceFrameworkChecks(frameworkId, params)
      setDetailData(data)
    } catch (err) {
      console.error(err)
    } finally {
      setDetailLoading(false)
    }
  }

  const handleFrameworkClick = (frameworkId: string) => {
    if (selectedFramework === frameworkId) {
      setSelectedFramework(null)
      setDetailData(null)
      return
    }
    setSelectedFramework(frameworkId)
    setStatusFilter('all')
    setSeverityFilter('all')
    setExpandedRows(new Set())
    setShowLibrary(false)
    setLibraryData(null)
    setExpandedControls(new Set())
    loadFrameworkDetail(frameworkId)
  }

  const handleFilterChange = (newStatus: string, newSeverity: string) => {
    setStatusFilter(newStatus)
    setSeverityFilter(newSeverity)
    if (selectedFramework) {
      loadFrameworkDetail(selectedFramework, newStatus, newSeverity)
    }
  }

  const toggleRow = (findingId: string) => {
    setExpandedRows((prev) => {
      const next = new Set(prev)
      if (next.has(findingId)) next.delete(findingId)
      else next.add(findingId)
      return next
    })
  }

  const toggleControl = (controlId: string) => {
    setExpandedControls((prev) => {
      const next = new Set(prev)
      if (next.has(controlId)) next.delete(controlId)
      else next.add(controlId)
      return next
    })
  }

  const loadCheckLibrary = async (frameworkId: string) => {
    setLibraryLoading(true)
    try {
      const data = await api.getComplianceFrameworkLibrary(frameworkId)
      setLibraryData(data)
    } catch (err) {
      console.error(err)
    } finally {
      setLibraryLoading(false)
    }
  }

  const toggleLibrary = () => {
    if (showLibrary) {
      setShowLibrary(false)
      return
    }
    setShowLibrary(true)
    if (selectedFramework && !libraryData) {
      loadCheckLibrary(selectedFramework)
    }
  }

  const closeDetail = () => {
    setSelectedFramework(null)
    setDetailData(null)
    setExpandedRows(new Set())
    setShowLibrary(false)
    setLibraryData(null)
    setExpandedControls(new Set())
  }

  return (
    <div>
      <Header title="Compliance" subtitle="Compliance framework assessment results" />

      {loading ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {[...Array(6)].map((_, i) => (
            <div key={i} className="card animate-pulse">
              <div className="h-32 bg-brand-gray-100 rounded" />
            </div>
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {frameworks.map((fw) => {
            const summary = summaries[fw.id] || {}
            const passRate = summary.pass_rate || 0
            const isSelected = selectedFramework === fw.id

            return (
              <div
                key={fw.id}
                onClick={() => handleFrameworkClick(fw.id)}
                className={`card hover:shadow-md transition-shadow cursor-pointer ${isSelected ? 'ring-2 ring-brand-green shadow-md' : ''}`}
              >
                <div className="flex items-start justify-between mb-4">
                  <div>
                    <h3 className="font-semibold text-brand-navy text-sm">{fw.name}</h3>
                    <p className="text-xs text-brand-gray-400 mt-1">{fw.description}</p>
                    {fw.total_controls > 0 && (
                      <p className="text-[10px] text-brand-gray-400 mt-1">
                        {fw.total_controls} controls &middot; {fw.total_checks} checks
                      </p>
                    )}
                  </div>
                </div>

                <div className="flex items-center gap-4 mb-4">
                  <div className="relative w-16 h-16">
                    <svg className="w-16 h-16 transform -rotate-90" viewBox="0 0 36 36">
                      <path
                        d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                        fill="none"
                        stroke="#E6E6E6"
                        strokeWidth="3"
                      />
                      <path
                        d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                        fill="none"
                        stroke={passRate >= 80 ? '#86BC25' : passRate >= 50 ? '#D97706' : '#DC2626'}
                        strokeWidth="3"
                        strokeDasharray={`${passRate}, 100`}
                        strokeLinecap="round"
                      />
                    </svg>
                    <div className="absolute inset-0 flex items-center justify-center">
                      <span className="text-xs font-bold text-brand-navy">
                        {formatPercent(passRate)}
                      </span>
                    </div>
                  </div>
                  <div className="flex-1">
                    <div className="flex justify-between text-sm mb-1">
                      <span className="text-brand-gray-500">Total Checks</span>
                      <span className="font-medium text-brand-navy">{summary.total_checks || 0}</span>
                    </div>
                    <div className="flex justify-between text-sm mb-1">
                      <span className="text-status-pass">Passed</span>
                      <span className="font-medium text-status-pass">{summary.passed || 0}</span>
                    </div>
                    <div className="flex justify-between text-sm mb-1">
                      <span className="text-status-fail">Failed</span>
                      <span className="font-medium text-status-fail">{summary.failed || 0}</span>
                    </div>
                    {(summary.not_evaluated || 0) > 0 && (
                      <div className="flex justify-between text-sm">
                        <span className="text-brand-gray-400">Not Evaluated</span>
                        <span className="font-medium text-brand-gray-400">{summary.not_evaluated}</span>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* Framework Detail Panel */}
      {selectedFramework && (
        <div className="mt-8 card">
          {/* Header */}
          <div className="flex items-start justify-between mb-6">
            <div>
              <h2 className="text-lg font-semibold text-brand-navy">
                {detailData?.framework?.name || 'Loading...'}
              </h2>
              <p className="text-sm text-brand-gray-400 mt-1">
                {detailData?.framework?.description || ''}
              </p>
            </div>
            <button
              onClick={closeDetail}
              className="p-1.5 rounded-lg hover:bg-brand-gray-100 text-brand-gray-400 hover:text-brand-navy"
            >
              <XMarkIcon className="w-5 h-5" />
            </button>
          </div>

          {/* Summary Stats Bar */}
          {detailData?.summary && (
            <div className="grid grid-cols-5 gap-4 mb-6">
              <div className="bg-brand-gray-50 rounded-lg p-3 text-center">
                <p className="text-2xl font-bold text-brand-navy">{detailData.summary.total_checks}</p>
                <p className="text-xs text-brand-gray-400">Total Checks</p>
              </div>
              <div className="bg-green-50 rounded-lg p-3 text-center">
                <p className="text-2xl font-bold text-green-700">{detailData.summary.passed}</p>
                <p className="text-xs text-green-600">Passed</p>
              </div>
              <div className="bg-red-50 rounded-lg p-3 text-center">
                <p className="text-2xl font-bold text-red-700">{detailData.summary.failed}</p>
                <p className="text-xs text-red-600">Failed</p>
              </div>
              <div className="bg-gray-50 rounded-lg p-3 text-center">
                <p className="text-2xl font-bold text-gray-400">{detailData.summary.not_evaluated || 0}</p>
                <p className="text-xs text-gray-400">Not Evaluated</p>
              </div>
              <div className="bg-blue-50 rounded-lg p-3 text-center">
                <p className="text-2xl font-bold text-blue-700">{detailData.summary.pass_rate}%</p>
                <p className="text-xs text-blue-600">Pass Rate</p>
              </div>
            </div>
          )}

          {/* Filter Controls */}
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <label className="text-sm font-medium text-brand-gray-700">Status:</label>
                <select
                  value={statusFilter}
                  onChange={(e) => handleFilterChange(e.target.value, severityFilter)}
                  className="px-3 py-1.5 border border-brand-gray-300 rounded-lg text-sm"
                >
                  <option value="all">All</option>
                  <option value="PASS">Pass</option>
                  <option value="FAIL">Fail</option>
                </select>
              </div>
              <div className="flex items-center gap-2">
                <label className="text-sm font-medium text-brand-gray-700">Severity:</label>
                <select
                  value={severityFilter}
                  onChange={(e) => handleFilterChange(statusFilter, e.target.value)}
                  className="px-3 py-1.5 border border-brand-gray-300 rounded-lg text-sm"
                >
                  <option value="all">All</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>
            </div>
            <button
              onClick={toggleLibrary}
              className={`inline-flex items-center gap-2 px-4 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                showLibrary
                  ? 'bg-brand-green text-white'
                  : 'border border-brand-gray-300 text-brand-gray-700 hover:bg-brand-gray-50'
              }`}
            >
              <BookOpenIcon className="w-4 h-4" />
              Check Library
            </button>
          </div>

          {/* Check Library Panel — Control-Level */}
          {showLibrary && (
            <div className="mb-6 border border-brand-gray-200 rounded-lg overflow-hidden">
              <div className="bg-brand-gray-50 px-4 py-3 border-b border-brand-gray-200">
                <h3 className="text-sm font-semibold text-brand-navy">
                  Check Library
                  {libraryData && (
                    <span className="text-brand-gray-400 font-normal ml-2">
                      ({libraryData.total_controls} controls, {libraryData.total_checks} checks)
                    </span>
                  )}
                </h3>
                <p className="text-xs text-brand-gray-400 mt-0.5">
                  Framework controls with mapped security checks per cloud provider.
                </p>
              </div>
              {libraryLoading ? (
                <div className="p-4 animate-pulse space-y-2">
                  {[...Array(5)].map((_, i) => (
                    <div key={i} className="h-12 bg-brand-gray-100 rounded" />
                  ))}
                </div>
              ) : libraryData?.controls?.length > 0 ? (
                <div className="max-h-[600px] overflow-y-auto divide-y divide-brand-gray-100">
                  {libraryData.controls.map((ctrl: any) => {
                    const isExpanded = expandedControls.has(ctrl.id)
                    const providerKeys = Object.keys(ctrl.checks || {})
                    const totalChecks = providerKeys.reduce(
                      (sum: number, k: string) => sum + (ctrl.checks[k]?.length || 0), 0
                    )

                    return (
                      <div key={ctrl.id}>
                        <button
                          onClick={() => toggleControl(ctrl.id)}
                          className="w-full text-left px-4 py-3 hover:bg-brand-gray-50 flex items-start gap-3"
                        >
                          <div className="mt-0.5">
                            {isExpanded ? (
                              <ChevronDownIcon className="w-4 h-4 text-brand-gray-400" />
                            ) : (
                              <ChevronRightIcon className="w-4 h-4 text-brand-gray-400" />
                            )}
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 mb-1">
                              <span className="text-xs font-mono font-semibold text-brand-green bg-brand-green/10 px-1.5 py-0.5 rounded">
                                {ctrl.id}
                              </span>
                              <span className="text-xs text-brand-gray-400">{totalChecks} checks</span>
                              <div className="flex gap-1 ml-auto">
                                {providerKeys.map((p: string) => (
                                  <span
                                    key={p}
                                    className={`text-[9px] font-bold px-1.5 py-0.5 rounded border ${
                                      PROVIDER_COLORS[p] || 'bg-gray-100 text-gray-500 border-gray-200'
                                    }`}
                                  >
                                    {PROVIDER_LABELS[p] || p.toUpperCase()}
                                  </span>
                                ))}
                              </div>
                            </div>
                            <p className="text-sm font-medium text-brand-navy">{ctrl.title}</p>
                            <p className="text-xs text-brand-gray-500 mt-0.5 line-clamp-2">{ctrl.description}</p>
                          </div>
                        </button>

                        {isExpanded && (
                          <div className="px-4 pb-4 ml-7">
                            {/* Full description */}
                            <div className="bg-brand-gray-50 rounded-lg p-3 mb-3">
                              <p className="text-xs text-brand-gray-600">{ctrl.description}</p>
                            </div>

                            {/* Checks per provider */}
                            {providerKeys.map((provider: string) => (
                              <div key={provider} className="mb-3">
                                <div className="flex items-center gap-2 mb-2">
                                  <span
                                    className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
                                      PROVIDER_COLORS[provider] || 'bg-gray-100 text-gray-500 border-gray-200'
                                    }`}
                                  >
                                    {PROVIDER_LABELS[provider] || provider.toUpperCase()}
                                  </span>
                                  <span className="text-xs text-brand-gray-400">
                                    {ctrl.checks[provider]?.length || 0} checks
                                  </span>
                                </div>
                                <div className="space-y-1.5 ml-2">
                                  {(ctrl.checks[provider] || []).map((check: any) => (
                                    <div
                                      key={check.check_id}
                                      className="border border-brand-gray-200 rounded-lg px-3 py-2 bg-white"
                                    >
                                      <div className="flex items-start gap-2">
                                        <span className="text-[10px] font-mono text-brand-gray-400 bg-brand-gray-100 px-1.5 py-0.5 rounded whitespace-nowrap mt-0.5">
                                          {check.check_id}
                                        </span>
                                        <div className="flex-1 min-w-0">
                                          <p className="text-xs text-brand-gray-700">{check.description}</p>
                                          {check.evidence_method && (
                                            <p className="text-[10px] text-brand-gray-400 mt-1">
                                              <span className="font-medium">Evidence: </span>
                                              {check.evidence_method}
                                            </p>
                                          )}
                                        </div>
                                      </div>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    )
                  })}
                </div>
              ) : (
                <div className="p-6 text-center text-sm text-brand-gray-400">
                  No control definitions available for this framework.
                </div>
              )}
            </div>
          )}

          {/* Checks Table */}
          {detailLoading ? (
            <div className="animate-pulse space-y-3">
              {[...Array(5)].map((_, i) => (
                <div key={i} className="h-10 bg-brand-gray-100 rounded" />
              ))}
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-brand-gray-200">
                    <th className="text-left py-3 px-2 text-brand-gray-500 font-medium w-8"></th>
                    <th className="text-left py-3 px-2 text-brand-gray-500 font-medium">Check ID</th>
                    <th className="text-left py-3 px-2 text-brand-gray-500 font-medium">Check Title</th>
                    <th className="text-left py-3 px-2 text-brand-gray-500 font-medium">Service</th>
                    <th className="text-left py-3 px-2 text-brand-gray-500 font-medium">Severity</th>
                    <th className="text-left py-3 px-2 text-brand-gray-500 font-medium">Status</th>
                    <th className="text-left py-3 px-2 text-brand-gray-500 font-medium">Region</th>
                    <th className="text-left py-3 px-2 text-brand-gray-500 font-medium">Resource</th>
                  </tr>
                </thead>
                <tbody>
                  {detailData?.findings?.length === 0 && (
                    <tr>
                      <td colSpan={8} className="text-center py-8 text-brand-gray-400">
                        No checks found for the selected filters.
                      </td>
                    </tr>
                  )}
                  {detailData?.findings?.map((f: any) => (
                    <>
                      <tr
                        key={f.id}
                        onClick={() => toggleRow(f.id)}
                        className="border-b border-brand-gray-100 hover:bg-brand-gray-50 cursor-pointer"
                      >
                        <td className="py-2.5 px-2">
                          {expandedRows.has(f.id) ? (
                            <ChevronDownIcon className="w-4 h-4 text-brand-gray-400" />
                          ) : (
                            <ChevronRightIcon className="w-4 h-4 text-brand-gray-400" />
                          )}
                        </td>
                        <td className="py-2.5 px-2 font-mono text-xs text-brand-gray-600 max-w-[140px] truncate">
                          {f.check_id}
                        </td>
                        <td className="py-2.5 px-2 text-brand-navy max-w-[250px] truncate">
                          {f.check_title}
                        </td>
                        <td className="py-2.5 px-2 text-brand-gray-600">{f.service}</td>
                        <td className="py-2.5 px-2">
                          <span className={`inline-block px-2 py-0.5 rounded-full text-xs font-medium capitalize ${SEVERITY_COLORS[f.severity] || 'bg-gray-100 text-gray-600'}`}>
                            {f.severity}
                          </span>
                        </td>
                        <td className="py-2.5 px-2">
                          <span className={`inline-block px-2 py-0.5 rounded-full text-xs font-medium ${STATUS_COLORS[f.status] || 'bg-gray-100 text-gray-600'}`}>
                            {f.status}
                          </span>
                        </td>
                        <td className="py-2.5 px-2 text-brand-gray-600 text-xs">{f.region || '-'}</td>
                        <td className="py-2.5 px-2 text-brand-gray-600 text-xs max-w-[180px] truncate">
                          {f.resource_name || f.resource_id || '-'}
                        </td>
                      </tr>
                      {expandedRows.has(f.id) && (
                        <tr key={`${f.id}-detail`} className="bg-brand-gray-50">
                          <td colSpan={8} className="px-6 py-4">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                              {f.check_description && (
                                <div>
                                  <p className="text-xs font-semibold text-brand-gray-500 uppercase tracking-wider mb-1">Security Impact</p>
                                  <p className="text-sm text-brand-gray-700">{f.check_description}</p>
                                </div>
                              )}
                              {f.status_extended && (
                                <div>
                                  <p className="text-xs font-semibold text-brand-gray-500 uppercase tracking-wider mb-1">Status Detail</p>
                                  <p className="text-sm text-brand-gray-700">{f.status_extended}</p>
                                </div>
                              )}
                              {f.resource_id && (
                                <div>
                                  <p className="text-xs font-semibold text-brand-gray-500 uppercase tracking-wider mb-1">Resource ID</p>
                                  <p className="text-sm text-brand-gray-700 font-mono">{f.resource_id}</p>
                                </div>
                              )}
                              {f.remediation && (
                                <div>
                                  <p className="text-xs font-semibold text-brand-gray-500 uppercase tracking-wider mb-1">Remediation</p>
                                  <p className="text-sm text-brand-gray-700">{f.remediation}</p>
                                  {f.remediation_url && (
                                    <a
                                      href={f.remediation_url}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      className="text-sm text-blue-600 hover:underline mt-1 inline-block"
                                      onClick={(e) => e.stopPropagation()}
                                    >
                                      View guide &rarr;
                                    </a>
                                  )}
                                </div>
                              )}
                              {f.evidence_log && (() => {
                                let ev: any = null
                                try { ev = JSON.parse(f.evidence_log) } catch {}
                                return (
                                  <div className="md:col-span-2">
                                    <p className="text-xs font-semibold text-brand-gray-500 uppercase tracking-wider mb-1">API Evidence Log</p>
                                    <div className="bg-brand-navy rounded-lg p-3 font-mono text-xs space-y-2 overflow-x-auto">
                                      {ev?.api_call ? (
                                        <>
                                          <div>
                                            <span className="text-brand-green font-semibold">$ API Call:</span>
                                            <pre className="text-gray-300 mt-0.5 whitespace-pre-wrap">{ev.api_call}</pre>
                                          </div>
                                          {ev.response && (
                                            <div>
                                              <span className="text-amber-400 font-semibold">Response:</span>
                                              <pre className="text-gray-300 mt-0.5 whitespace-pre-wrap">{ev.response}</pre>
                                            </div>
                                          )}
                                        </>
                                      ) : (
                                        <div>
                                          <span className="text-brand-green font-semibold">$ Method:</span>
                                          <pre className="text-gray-300 mt-0.5 whitespace-pre-wrap">{f.evidence_log}</pre>
                                        </div>
                                      )}
                                    </div>
                                  </div>
                                )
                              })()}
                              {!f.status_extended && !f.remediation && !f.check_description && (
                                <p className="text-sm text-brand-gray-400 italic">No additional details available.</p>
                              )}
                            </div>
                          </td>
                        </tr>
                      )}
                    </>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
