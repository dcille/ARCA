'use client'

import { useState, useEffect, useCallback } from 'react'
import { useParams, useRouter } from 'next/navigation'
import Header from '@/components/layout/Header'
import {
  PlusIcon,
  CogIcon,
  EyeIcon,
  TrashIcon,
  PencilSquareIcon,
  ArrowUpTrayIcon,
  DocumentArrowDownIcon,
  ChevronDownIcon,
  ChevronUpIcon,
} from '@heroicons/react/24/outline'
import { api } from '@/lib/api'
import toast from 'react-hot-toast'
import RegistryCheckSelector from '@/components/compliance/RegistryCheckSelector'
import CreateControlWizard from '@/components/compliance/CreateControlWizard'
import ExcelImportModal from '@/components/compliance/ExcelImportModal'

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-100 text-red-700',
  high: 'bg-orange-100 text-orange-700',
  medium: 'bg-amber-100 text-amber-700',
  low: 'bg-blue-100 text-blue-700',
  informational: 'bg-gray-100 text-gray-600',
}

const SOURCE_COLORS: Record<string, string> = {
  cis: 'bg-indigo-100 text-indigo-700',
  scanner: 'bg-teal-100 text-teal-700',
  custom: 'bg-purple-100 text-purple-700',
  unknown: 'bg-gray-100 text-gray-500',
}

const STATUS_COLORS: Record<string, string> = {
  PASS: 'text-green-600',
  FAIL: 'text-red-600',
  NOT_EVALUATED: 'text-brand-gray-400',
  MANUAL_REVIEW: 'text-blue-500',
}

type Tab = 'all' | 'registry' | 'custom' | 'automated' | 'manual'

export default function CustomFrameworkDetailPage() {
  const params = useParams()
  const router = useRouter()
  const fwId = params.id as string

  const [framework, setFramework] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [activeTab, setActiveTab] = useState<Tab>('all')
  const [showAddChecks, setShowAddChecks] = useState(false)
  const [showCreateControl, setShowCreateControl] = useState(false)
  const [showExcelImport, setShowExcelImport] = useState(false)
  const [selectedCheckIds, setSelectedCheckIds] = useState<Set<string>>(new Set())
  const [addingChecks, setAddingChecks] = useState(false)
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [editingName, setEditingName] = useState(false)
  const [nameValue, setNameValue] = useState('')
  const [evaluationMap, setEvaluationMap] = useState<Record<string, { status: string; findings: number; fail_count: number }>>({})

  const fetchFramework = useCallback(async () => {
    try {
      const data = await api.getCustomFramework(fwId)
      setFramework(data)
      setNameValue(data.name)
      // Fetch per-check evaluation status
      try {
        const evalData = await api.getCustomFrameworkEvaluation(fwId)
        if (evalData?.check_statuses) {
          setEvaluationMap(evalData.check_statuses)
        }
      } catch {
        // Evaluation data not available
      }
    } catch (err: any) {
      toast.error('Failed to load framework')
      router.push('/darca/compliance/custom')
    } finally {
      setLoading(false)
    }
  }, [fwId, router])

  useEffect(() => { fetchFramework() }, [fetchFramework])

  const handleAddChecks = async () => {
    if (selectedCheckIds.size === 0) return
    setAddingChecks(true)
    try {
      const result = await api.addChecksToFramework(fwId, Array.from(selectedCheckIds))
      toast.success(`Added ${result.added} checks`)
      setShowAddChecks(false)
      setSelectedCheckIds(new Set())
      fetchFramework()
    } catch (err: any) {
      toast.error(err.message || 'Failed to add checks')
    } finally {
      setAddingChecks(false)
    }
  }

  const handleRemoveCheck = async (checkRecordId: string) => {
    try {
      await api.removeCheckFromFramework(fwId, checkRecordId)
      toast.success('Check removed')
      fetchFramework()
    } catch (err: any) {
      toast.error(err.message || 'Failed to remove check')
    }
  }

  const handleDeleteControl = async (ctrlId: string) => {
    if (!confirm('Delete this custom control?')) return
    try {
      await api.deleteCustomControl(fwId, ctrlId)
      toast.success('Control deleted')
      fetchFramework()
    } catch (err: any) {
      toast.error(err.message || 'Failed to delete control')
    }
  }

  const handleNameSave = async () => {
    if (!nameValue.trim()) return
    try {
      await api.updateCustomFramework(fwId, { name: nameValue.trim() })
      setEditingName(false)
      fetchFramework()
    } catch (err: any) {
      toast.error(err.message || 'Failed to update name')
    }
  }

  if (loading) {
    return (
      <div className="p-6 space-y-4">
        <div className="h-8 w-64 skeleton-shimmer rounded" />
        <div className="grid grid-cols-5 gap-4">
          {[...Array(5)].map((_, i) => <div key={i} className="h-20 skeleton-shimmer rounded" />)}
        </div>
        <div className="h-96 skeleton-shimmer rounded" />
      </div>
    )
  }

  if (!framework) return null

  const allItems: any[] = [
    ...(framework.selected_checks || []).map((c: any) => ({ ...c, _type: 'registry' })),
    ...(framework.custom_controls || []).map((c: any) => ({ ...c, _type: 'custom' })),
  ]

  const filteredItems = allItems.filter(item => {
    if (activeTab === 'registry') return item._type === 'registry'
    if (activeTab === 'custom') return item._type === 'custom'
    if (activeTab === 'automated') return item.assessment_type === 'automated'
    if (activeTab === 'manual') return item.assessment_type === 'manual'
    return true
  })

  const summary = framework.summary || {}
  const registryCount = framework.selected_checks?.length || 0
  const customCount = framework.custom_controls?.length || 0

  return (
    <div>
      <Header
        title=""
        breadcrumbs={[
          { label: 'Compliance', href: '/darca/compliance' },
          { label: 'Custom Frameworks', href: '/darca/compliance/custom' },
          { label: framework.name },
        ]}
      />

      <div className="p-6 animate-fade-in">
        {/* Framework header */}
        <div className="flex items-start justify-between mb-6">
          <div>
            <div className="flex items-center gap-2">
              {editingName ? (
                <div className="flex items-center gap-2">
                  <input
                    value={nameValue}
                    onChange={e => setNameValue(e.target.value)}
                    className="text-xl font-bold px-2 py-1 border border-brand-green rounded-lg focus:outline-none"
                    autoFocus
                    onKeyDown={e => { if (e.key === 'Enter') handleNameSave(); if (e.key === 'Escape') setEditingName(false) }}
                  />
                  <button onClick={handleNameSave} className="text-xs text-brand-green hover:underline">Save</button>
                  <button onClick={() => setEditingName(false)} className="text-xs text-brand-gray-500 hover:underline">Cancel</button>
                </div>
              ) : (
                <>
                  <h1 className="text-xl font-bold text-brand-gray-900">{framework.name}</h1>
                  <button onClick={() => setEditingName(true)} className="p-1 hover:bg-brand-gray-100 rounded">
                    <PencilSquareIcon className="w-4 h-4 text-brand-gray-400" />
                  </button>
                </>
              )}
              <span className="text-[10px] px-2 py-0.5 rounded bg-purple-100 text-purple-700 font-medium">CUSTOM</span>
              <span className="text-xs text-brand-gray-400">v{framework.version}</span>
            </div>
            {framework.description && (
              <p className="text-sm text-brand-gray-500 mt-1 max-w-xl">{framework.description}</p>
            )}
            <div className="flex gap-1 mt-2">
              {(framework.providers || []).map((p: string) => (
                <span key={p} className="text-[10px] px-1.5 py-0.5 bg-brand-gray-100 text-brand-gray-600 rounded">{p}</span>
              ))}
            </div>
          </div>
          <div className="flex gap-2">
            <button onClick={() => setShowAddChecks(true)} className="btn-outline px-3 py-2 text-sm flex items-center gap-1">
              <PlusIcon className="w-4 h-4" /> Add from Registry
            </button>
            <button onClick={() => setShowCreateControl(true)} className="btn-outline px-3 py-2 text-sm flex items-center gap-1">
              <PlusIcon className="w-4 h-4" /> New Control
            </button>
            <button onClick={() => setShowExcelImport(true)} className="btn-ghost px-3 py-2 text-sm flex items-center gap-1">
              <ArrowUpTrayIcon className="w-4 h-4" /> Import
            </button>
          </div>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3 mb-6">
          {[
            { label: 'Total Checks', value: summary.total_checks || 0 },
            { label: 'Automated', value: summary.automated || 0 },
            { label: 'Manual', value: summary.manual || 0 },
            { label: 'Passed', value: summary.passed || 0, color: 'text-green-600' },
            { label: 'Failed', value: summary.failed || 0, color: 'text-red-600' },
            { label: 'Not Evaluated', value: summary.not_evaluated || 0, color: 'text-brand-gray-400' },
            { label: 'Pass Rate', value: `${summary.pass_rate || 0}%`, color: (summary.pass_rate || 0) >= 80 ? 'text-green-600' : (summary.pass_rate || 0) >= 50 ? 'text-amber-600' : 'text-red-600' },
          ].map((stat, i) => (
            <div key={i} className="card-static p-3 text-center">
              <p className="text-xs text-brand-gray-500">{stat.label}</p>
              <p className={`text-lg font-bold ${stat.color || 'text-brand-gray-900'}`}>{stat.value}</p>
            </div>
          ))}
        </div>

        {/* Tabs */}
        <div className="flex gap-1 mb-4 border-b border-brand-gray-200">
          {([
            ['all', `All (${allItems.length})`],
            ['registry', `From Registry (${registryCount})`],
            ['custom', `Custom Controls (${customCount})`],
            ['automated', `Automated (${summary.automated || 0})`],
            ['manual', `Manual (${summary.manual || 0})`],
          ] as [Tab, string][]).map(([tab, label]) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors -mb-px ${
                activeTab === tab
                  ? 'border-brand-green text-brand-green'
                  : 'border-transparent text-brand-gray-500 hover:text-brand-gray-700'
              }`}
            >
              {label}
            </button>
          ))}
        </div>

        {/* Items table */}
        <div className="card-static overflow-hidden">
          {filteredItems.length === 0 ? (
            <div className="p-8 text-center text-brand-gray-400">
              No checks in this view. Add checks from the registry or create custom controls.
            </div>
          ) : (
            <div className="divide-y divide-brand-gray-100">
              {filteredItems.map(item => {
                const checkId = item.check_id || item.registry_check_id
                const isExpanded = expandedId === (item.id || checkId)
                const isCustom = item._type === 'custom'

                return (
                  <div key={item.id || checkId}>
                    <div
                      className="px-4 py-3 flex items-center gap-3 hover:bg-brand-gray-50 cursor-pointer"
                      onClick={() => setExpandedId(isExpanded ? null : (item.id || checkId))}
                    >
                      {isExpanded ? (
                        <ChevronUpIcon className="w-4 h-4 text-brand-gray-400 flex-shrink-0" />
                      ) : (
                        <ChevronDownIcon className="w-4 h-4 text-brand-gray-400 flex-shrink-0" />
                      )}

                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-mono text-brand-gray-500 truncate max-w-[220px]">
                            {checkId}
                          </span>
                          <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${
                            SOURCE_COLORS[item.source || (isCustom ? 'custom' : 'unknown')] || SOURCE_COLORS.unknown
                          }`}>
                            {(item.source || (isCustom ? 'custom' : '?')).toUpperCase()}
                          </span>
                        </div>
                        <p className="text-sm text-brand-gray-800 mt-0.5">{item.title}</p>
                      </div>

                      <span className="text-xs text-brand-gray-500">{item.provider || ''}</span>

                      <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${SEVERITY_COLORS[item.severity] || ''}`}>
                        {item.severity || ''}
                      </span>

                      {(() => {
                        const evalStatus = evaluationMap[checkId]
                        if (!evalStatus) return null
                        return (
                          <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${
                            evalStatus.status === 'PASS' ? 'bg-green-100 text-green-700' :
                            evalStatus.status === 'FAIL' ? 'bg-red-100 text-red-700' :
                            'bg-amber-100 text-amber-600'
                          }`}>
                            {evalStatus.status === 'NOT_EVALUATED' ? 'NOT EVAL' : evalStatus.status}
                          </span>
                        )
                      })()}

                      {item.assessment_type === 'automated' ? (
                        <CogIcon className="w-4 h-4 text-green-500 flex-shrink-0" title="Automated" />
                      ) : (
                        <EyeIcon className="w-4 h-4 text-blue-500 flex-shrink-0" title="Manual" />
                      )}

                      <div onClick={e => e.stopPropagation()}>
                        <button
                          onClick={() => isCustom ? handleDeleteControl(item.id) : handleRemoveCheck(item.id)}
                          className="p-1.5 hover:bg-red-50 rounded"
                          title="Remove"
                        >
                          <TrashIcon className="w-3.5 h-3.5 text-brand-gray-400 hover:text-red-500" />
                        </button>
                      </div>
                    </div>

                    {/* Expanded detail */}
                    {isExpanded && (
                      <div className="px-10 py-3 bg-brand-gray-50 border-t border-brand-gray-100">
                        <div className="grid grid-cols-2 gap-4 text-sm">
                          {item.description && (
                            <div className="col-span-2">
                              <p className="text-xs font-medium text-brand-gray-500 mb-0.5">Description</p>
                              <p className="text-brand-gray-700">{item.description}</p>
                            </div>
                          )}
                          <div>
                            <p className="text-xs font-medium text-brand-gray-500 mb-0.5">Category</p>
                            <p className="text-brand-gray-700">{item.category || 'N/A'}</p>
                          </div>
                          <div>
                            <p className="text-xs font-medium text-brand-gray-500 mb-0.5">Service</p>
                            <p className="text-brand-gray-700">{item.service || 'N/A'}</p>
                          </div>
                          {item.cis_id && (
                            <div>
                              <p className="text-xs font-medium text-brand-gray-500 mb-0.5">CIS ID</p>
                              <p className="text-brand-gray-700">{item.cis_id}</p>
                            </div>
                          )}
                          {item.has_scanner !== undefined && (
                            <div>
                              <p className="text-xs font-medium text-brand-gray-500 mb-0.5">Scanner Coverage</p>
                              <p className={item.has_scanner ? 'text-green-600' : 'text-brand-gray-400'}>
                                {item.has_scanner ? 'Has scanner implementation' : 'No scanner coverage'}
                              </p>
                            </div>
                          )}
                          {item.tags && item.tags.length > 0 && (
                            <div className="col-span-2">
                              <p className="text-xs font-medium text-brand-gray-500 mb-1">Tags</p>
                              <div className="flex flex-wrap gap-1">
                                {item.tags.map((t: string) => (
                                  <span key={t} className="text-[10px] px-1.5 py-0.5 bg-white border border-brand-gray-200 rounded text-brand-gray-600">{t}</span>
                                ))}
                              </div>
                            </div>
                          )}
                          {isCustom && item.remediation && (
                            <div className="col-span-2">
                              <p className="text-xs font-medium text-brand-gray-500 mb-0.5">Remediation</p>
                              <p className="text-brand-gray-700">{item.remediation}</p>
                            </div>
                          )}
                          {isCustom && item.risks && (
                            <div className="col-span-2">
                              <p className="text-xs font-medium text-brand-gray-500 mb-0.5">Risks</p>
                              <p className="text-brand-gray-700">{item.risks}</p>
                            </div>
                          )}
                          {isCustom && item.scanner_check_ids?.length > 0 && (
                            <div className="col-span-2">
                              <p className="text-xs font-medium text-brand-gray-500 mb-0.5">Mapped Scanner IDs</p>
                              <p className="text-brand-gray-700 font-mono text-xs">{item.scanner_check_ids.join(', ')}</p>
                            </div>
                          )}
                          {isCustom && item.cli_commands && (
                            <div className="col-span-2">
                              <p className="text-xs font-medium text-brand-gray-500 mb-0.5">Audit Command</p>
                              <div className="bg-brand-gray-900 rounded-lg p-3 mt-1">
                                <div className="flex items-center gap-2 mb-2">
                                  <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${
                                    item.cli_commands.type === 'python' ? 'bg-blue-500/20 text-blue-300' : 'bg-green-500/20 text-green-300'
                                  }`}>
                                    {item.cli_commands.type === 'python' ? 'Python' : 'CLI'}
                                  </span>
                                </div>
                                <pre className="text-xs text-brand-gray-300 font-mono whitespace-pre-wrap overflow-x-auto">{item.cli_commands.command}</pre>
                              </div>
                            </div>
                          )}
                          {(() => {
                            const evalStatus = evaluationMap[checkId]
                            if (!evalStatus) return null
                            return (
                              <div className="col-span-2 mt-2 pt-2 border-t border-brand-gray-200">
                                <p className="text-xs font-medium text-brand-gray-500 mb-1">Evaluation Result</p>
                                <div className="flex items-center gap-3">
                                  <span className={`text-sm font-bold ${
                                    evalStatus.status === 'PASS' ? 'text-green-600' :
                                    evalStatus.status === 'FAIL' ? 'text-red-600' :
                                    'text-amber-500'
                                  }`}>
                                    {evalStatus.status}
                                  </span>
                                  {evalStatus.findings > 0 && (
                                    <span className="text-xs text-brand-gray-500">
                                      {evalStatus.findings} finding{evalStatus.findings !== 1 ? 's' : ''}
                                      {evalStatus.fail_count > 0 && <span className="text-red-500 ml-1">({evalStatus.fail_count} failed)</span>}
                                    </span>
                                  )}
                                  {evalStatus.status === 'NOT_EVALUATED' && (
                                    <span className="text-xs text-amber-500 italic">
                                      No scan data available — run a scan on the corresponding cloud account to evaluate this control
                                    </span>
                                  )}
                                </div>
                              </div>
                            )
                          })()}
                        </div>
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          )}
        </div>
      </div>

      {/* Add checks modal */}
      {showAddChecks && (
        <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ background: 'rgba(0,0,0,0.4)', backdropFilter: 'blur(4px)' }}>
          <div className="bg-white rounded-2xl shadow-2xl w-full max-w-5xl max-h-[85vh] flex flex-col">
            <div className="flex items-center justify-between px-6 py-4 border-b border-brand-gray-200">
              <h2 className="text-lg font-bold text-brand-gray-900">Add Checks from Registry</h2>
              <button onClick={() => setShowAddChecks(false)} className="p-2 hover:bg-brand-gray-100 rounded-lg">
                <span className="text-brand-gray-500 text-xl">&times;</span>
              </button>
            </div>
            <div className="flex-1 overflow-hidden p-6">
              <div className="h-[500px]">
                <RegistryCheckSelector
                  selectedCheckIds={selectedCheckIds}
                  onSelectionChange={setSelectedCheckIds}
                />
              </div>
            </div>
            <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-brand-gray-200">
              <button onClick={() => setShowAddChecks(false)} className="px-4 py-2 text-sm text-brand-gray-600">Cancel</button>
              <button
                disabled={selectedCheckIds.size === 0 || addingChecks}
                onClick={handleAddChecks}
                className="btn-primary px-6 py-2 text-sm disabled:opacity-40"
              >
                {addingChecks ? 'Adding...' : `Add ${selectedCheckIds.size} Checks`}
              </button>
            </div>
          </div>
        </div>
      )}

      {showCreateControl && (
        <CreateControlWizard
          frameworkId={fwId}
          onClose={() => setShowCreateControl(false)}
          onCreated={() => {
            setShowCreateControl(false)
            fetchFramework()
          }}
        />
      )}

      {showExcelImport && (
        <ExcelImportModal
          frameworkId={fwId}
          onClose={() => setShowExcelImport(false)}
          onImported={fetchFramework}
        />
      )}
    </div>
  )
}
