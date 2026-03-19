'use client'

import { useEffect, useState } from 'react'
import Header from '@/components/layout/Header'
import { api } from '@/lib/api'
import { formatPercent } from '@/lib/utils'
import { XMarkIcon, ChevronDownIcon, ChevronRightIcon, BookOpenIcon, FunnelIcon, CheckIcon } from '@heroicons/react/24/outline'

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
  NOT_EVALUATED: 'bg-gray-100 text-gray-500',
}

const STATUS_DOT: Record<string, string> = {
  PASS: 'bg-green-500',
  FAIL: 'bg-red-500',
  NOT_EVALUATED: 'bg-gray-300',
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

  // Framework filter state
  const [selectedFrameworkIds, setSelectedFrameworkIds] = useState<Set<string>>(new Set())
  const [showFilterDropdown, setShowFilterDropdown] = useState(false)

  // Detail view state
  const [selectedFramework, setSelectedFramework] = useState<string | null>(null)
  const [controlsData, setControlsData] = useState<any>(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [controlStatusFilter, setControlStatusFilter] = useState<string>('all')
  const [expandedControls, setExpandedControls] = useState<Set<string>>(new Set())

  // Check library state
  const [showLibrary, setShowLibrary] = useState(false)
  const [libraryData, setLibraryData] = useState<any>(null)
  const [libraryLoading, setLibraryLoading] = useState(false)

  useEffect(() => {
    const load = async () => {
      try {
        const fws = await api.getComplianceFrameworks()
        setFrameworks(fws)
        // All frameworks selected by default
        setSelectedFrameworkIds(new Set(fws.map((fw: any) => fw.id)))

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

  const loadFrameworkControls = async (frameworkId: string) => {
    setDetailLoading(true)
    try {
      const data = await api.getComplianceFrameworkControls(frameworkId)
      setControlsData(data)
    } catch (err) {
      console.error(err)
    } finally {
      setDetailLoading(false)
    }
  }

  const handleFrameworkClick = (frameworkId: string) => {
    if (selectedFramework === frameworkId) {
      setSelectedFramework(null)
      setControlsData(null)
      return
    }
    setSelectedFramework(frameworkId)
    setControlStatusFilter('all')
    setExpandedControls(new Set())
    setShowLibrary(false)
    setLibraryData(null)
    loadFrameworkControls(frameworkId)
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
    setControlsData(null)
    setExpandedControls(new Set())
    setShowLibrary(false)
    setLibraryData(null)
  }

  const toggleFrameworkFilter = (fwId: string) => {
    setSelectedFrameworkIds((prev) => {
      const next = new Set(prev)
      if (next.has(fwId)) next.delete(fwId)
      else next.add(fwId)
      return next
    })
  }

  const selectAllFrameworks = () => setSelectedFrameworkIds(new Set(frameworks.map((fw) => fw.id)))
  const clearAllFrameworks = () => setSelectedFrameworkIds(new Set())

  const visibleFrameworks = frameworks.filter((fw) => selectedFrameworkIds.has(fw.id))

  // Filter controls by status
  const filteredControls = controlsData?.controls?.filter((ctrl: any) => {
    if (controlStatusFilter === 'all') return true
    return ctrl.status === controlStatusFilter
  }) || []

  return (
    <div>
      <Header title="Compliance" subtitle="Compliance framework assessment results" />

      {/* Framework Filter Bar */}
      {!loading && frameworks.length > 0 && (
        <div className="mb-6 flex items-center gap-3">
          <div className="relative">
            <button
              onClick={() => setShowFilterDropdown(!showFilterDropdown)}
              className="inline-flex items-center gap-2 px-3 py-2 border border-brand-gray-300 rounded-lg text-sm font-medium text-brand-gray-700 hover:bg-brand-gray-50"
            >
              <FunnelIcon className="w-4 h-4" />
              Frameworks ({selectedFrameworkIds.size}/{frameworks.length})
              <ChevronDownIcon className="w-3 h-3" />
            </button>

            {showFilterDropdown && (
              <div className="absolute z-50 mt-1 w-80 bg-white border border-brand-gray-200 rounded-lg shadow-lg max-h-96 overflow-y-auto">
                <div className="sticky top-0 bg-white border-b border-brand-gray-200 px-3 py-2 flex items-center justify-between">
                  <span className="text-xs font-medium text-brand-gray-500">Select frameworks to display</span>
                  <div className="flex gap-2">
                    <button onClick={selectAllFrameworks} className="text-xs text-brand-green hover:underline">All</button>
                    <button onClick={clearAllFrameworks} className="text-xs text-red-500 hover:underline">None</button>
                  </div>
                </div>
                {frameworks.map((fw) => (
                  <label
                    key={fw.id}
                    className="flex items-center gap-3 px-3 py-2.5 hover:bg-brand-gray-50 cursor-pointer border-b border-brand-gray-100 last:border-b-0"
                  >
                    <div
                      className={`w-4 h-4 rounded border flex items-center justify-center flex-shrink-0 ${
                        selectedFrameworkIds.has(fw.id)
                          ? 'bg-brand-green border-brand-green'
                          : 'border-brand-gray-300'
                      }`}
                      onClick={(e) => { e.preventDefault(); toggleFrameworkFilter(fw.id) }}
                    >
                      {selectedFrameworkIds.has(fw.id) && <CheckIcon className="w-3 h-3 text-white" />}
                    </div>
                    <div className="flex-1 min-w-0" onClick={() => toggleFrameworkFilter(fw.id)}>
                      <p className="text-sm font-medium text-brand-navy truncate">{fw.name}</p>
                      <p className="text-[10px] text-brand-gray-400 truncate">{fw.description}</p>
                    </div>
                  </label>
                ))}
              </div>
            )}
          </div>

          {selectedFrameworkIds.size < frameworks.length && (
            <span className="text-xs text-brand-gray-400">
              Showing {selectedFrameworkIds.size} of {frameworks.length} frameworks
            </span>
          )}
        </div>
      )}

      {/* Close dropdown when clicking outside */}
      {showFilterDropdown && (
        <div className="fixed inset-0 z-40" onClick={() => setShowFilterDropdown(false)} />
      )}

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
          {visibleFrameworks.map((fw) => {
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

      {/* Framework Detail Panel — Control-Level View */}
      {selectedFramework && (
        <div className="mt-8 card">
          {/* Header */}
          <div className="flex items-start justify-between mb-6">
            <div>
              <h2 className="text-lg font-semibold text-brand-navy">
                {controlsData?.framework?.name || 'Loading...'}
              </h2>
              <p className="text-sm text-brand-gray-400 mt-1">
                {controlsData?.framework?.description || ''}
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
          {controlsData?.summary && (
            <div className="grid grid-cols-5 gap-4 mb-6">
              <div className="bg-brand-gray-50 rounded-lg p-3 text-center">
                <p className="text-2xl font-bold text-brand-navy">{controlsData.summary.total_checks}</p>
                <p className="text-xs text-brand-gray-400">Total Checks</p>
              </div>
              <div className="bg-green-50 rounded-lg p-3 text-center">
                <p className="text-2xl font-bold text-green-700">{controlsData.summary.passed}</p>
                <p className="text-xs text-green-600">Passed</p>
              </div>
              <div className="bg-red-50 rounded-lg p-3 text-center">
                <p className="text-2xl font-bold text-red-700">{controlsData.summary.failed}</p>
                <p className="text-xs text-red-600">Failed</p>
              </div>
              <div className="bg-gray-50 rounded-lg p-3 text-center">
                <p className="text-2xl font-bold text-gray-400">{controlsData.summary.not_evaluated || 0}</p>
                <p className="text-xs text-gray-400">Not Evaluated</p>
              </div>
              <div className="bg-blue-50 rounded-lg p-3 text-center">
                <p className="text-2xl font-bold text-blue-700">{controlsData.summary.pass_rate}%</p>
                <p className="text-xs text-blue-600">Pass Rate</p>
              </div>
            </div>
          )}

          {/* Filter Controls */}
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-2">
              <label className="text-sm font-medium text-brand-gray-700">Filter:</label>
              {['all', 'PASS', 'FAIL', 'NOT_EVALUATED'].map((s) => (
                <button
                  key={s}
                  onClick={() => setControlStatusFilter(s)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                    controlStatusFilter === s
                      ? s === 'PASS' ? 'bg-green-100 text-green-800'
                      : s === 'FAIL' ? 'bg-red-100 text-red-800'
                      : s === 'NOT_EVALUATED' ? 'bg-gray-200 text-gray-600'
                      : 'bg-brand-green text-white'
                      : 'border border-brand-gray-300 text-brand-gray-500 hover:bg-brand-gray-50'
                  }`}
                >
                  {s === 'all' ? 'All' : s === 'NOT_EVALUATED' ? 'Not Evaluated' : s === 'PASS' ? 'Passed' : 'Failed'}
                  {controlsData?.controls && (
                    <span className="ml-1.5 opacity-70">
                      ({s === 'all'
                        ? controlsData.controls.length
                        : controlsData.controls.filter((c: any) => c.status === s).length
                      })
                    </span>
                  )}
                </button>
              ))}
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

          {/* Check Library Panel */}
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
                    const isExpanded = expandedControls.has(`lib-${ctrl.id}`)
                    const providerKeys = Object.keys(ctrl.checks || {})
                    const totalChecks = providerKeys.reduce(
                      (sum: number, k: string) => sum + (ctrl.checks[k]?.length || 0), 0
                    )

                    return (
                      <div key={ctrl.id}>
                        <button
                          onClick={() => toggleControl(`lib-${ctrl.id}`)}
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
                            <div className="bg-brand-gray-50 rounded-lg p-3 mb-3">
                              <p className="text-xs text-brand-gray-600">{ctrl.description}</p>
                            </div>
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
                                        <p className="text-xs text-brand-gray-700 flex-1">{check.description}</p>
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

          {/* Controls List — Check-Library style with evaluation results */}
          {detailLoading ? (
            <div className="animate-pulse space-y-3">
              {[...Array(5)].map((_, i) => (
                <div key={i} className="h-16 bg-brand-gray-100 rounded" />
              ))}
            </div>
          ) : (
            <div className="border border-brand-gray-200 rounded-lg overflow-hidden">
              <div className="bg-brand-gray-50 px-4 py-3 border-b border-brand-gray-200">
                <h3 className="text-sm font-semibold text-brand-navy">
                  Controls Assessment
                  {controlsData && (
                    <span className="text-brand-gray-400 font-normal ml-2">
                      ({filteredControls.length} controls)
                    </span>
                  )}
                </h3>
              </div>

              {filteredControls.length === 0 ? (
                <div className="p-6 text-center text-sm text-brand-gray-400">
                  No controls found for the selected filter.
                </div>
              ) : (
                <div className="max-h-[700px] overflow-y-auto divide-y divide-brand-gray-100">
                  {filteredControls.map((ctrl: any) => {
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
                          {/* Status indicator */}
                          <div className="mt-1.5 flex-shrink-0">
                            <div className={`w-3 h-3 rounded-full ${STATUS_DOT[ctrl.status] || 'bg-gray-300'}`} />
                          </div>
                          <div className="mt-0.5 flex-shrink-0">
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
                              <span className={`text-[10px] font-medium px-1.5 py-0.5 rounded ${STATUS_COLORS[ctrl.status] || 'bg-gray-100 text-gray-500'}`}>
                                {ctrl.status === 'NOT_EVALUATED' ? 'NOT EVALUATED' : ctrl.status}
                              </span>
                              {ctrl.status !== 'NOT_EVALUATED' && (
                                <span className="text-[10px] text-brand-gray-400">
                                  {ctrl.passed} passed, {ctrl.failed} failed
                                  {ctrl.not_evaluated > 0 && `, ${ctrl.not_evaluated} not evaluated`}
                                </span>
                              )}
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

                            {/* Checks per provider with evaluation results */}
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
                                      className={`border rounded-lg px-3 py-2 ${
                                        check.status === 'PASS'
                                          ? 'border-green-200 bg-green-50/50'
                                          : check.status === 'FAIL'
                                          ? 'border-red-200 bg-red-50/50'
                                          : 'border-brand-gray-200 bg-white'
                                      }`}
                                    >
                                      <div className="flex items-start gap-2">
                                        <div className={`w-2 h-2 rounded-full mt-1.5 flex-shrink-0 ${STATUS_DOT[check.status] || 'bg-gray-300'}`} />
                                        <span className="text-[10px] font-mono text-brand-gray-400 bg-brand-gray-100 px-1.5 py-0.5 rounded whitespace-nowrap mt-0.5">
                                          {check.check_id}
                                        </span>
                                        <div className="flex-1 min-w-0">
                                          <p className="text-xs text-brand-gray-700">{check.description}</p>
                                          {check.status !== 'NOT_EVALUATED' && (
                                            <p className="text-[10px] mt-1">
                                              <span className={check.status === 'PASS' ? 'text-green-600' : 'text-red-600'}>
                                                {check.status}
                                              </span>
                                              <span className="text-brand-gray-400 ml-2">
                                                {check.finding_count} finding{check.finding_count !== 1 ? 's' : ''}
                                                {check.fail_count > 0 && ` (${check.fail_count} failed)`}
                                              </span>
                                            </p>
                                          )}
                                          {check.status === 'NOT_EVALUATED' && (
                                            <p className="text-[10px] text-brand-gray-400 mt-1 italic">Not evaluated — no scan data</p>
                                          )}
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
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
