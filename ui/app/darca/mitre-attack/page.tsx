'use client'

import { useEffect, useState, useRef } from 'react'
import Header from '@/components/layout/Header'
import { api } from '@/lib/api'
import {
  XMarkIcon,
  ArrowPathIcon,
  FunnelIcon,
  ShieldCheckIcon,
  ArrowDownTrayIcon,
  ExclamationTriangleIcon,
  ChartBarIcon,
} from '@heroicons/react/24/outline'

const TACTIC_COLORS: Record<string, string> = {
  'initial-access': 'border-t-red-500',
  'execution': 'border-t-orange-500',
  'persistence': 'border-t-amber-500',
  'privilege-escalation': 'border-t-yellow-500',
  'defense-evasion': 'border-t-lime-500',
  'credential-access': 'border-t-green-500',
  'discovery': 'border-t-teal-500',
  'lateral-movement': 'border-t-cyan-500',
  'collection': 'border-t-blue-500',
  'exfiltration': 'border-t-indigo-500',
  'impact': 'border-t-purple-500',
}

const ANALYSIS_PHASES = [
  'Querying security findings...',
  'Mapping findings to MITRE ATT&CK techniques...',
  'Correlating sub-techniques and tactics...',
  'Assessing protection coverage...',
  'Building attack matrix visualization...',
]

function TechniqueCell({
  technique,
  onClick,
  maxFails,
}: {
  technique: any
  onClick: () => void
  maxFails: number
}) {
  // Heatmap intensity: deeper red for more failures
  const failIntensity = maxFails > 0 ? Math.min(technique.fail_count / maxFails, 1) : 0

  let bgColor: string
  let textColor: string
  if (technique.color === 'green') {
    bgColor = 'bg-green-100 hover:bg-green-200 border-green-300'
    textColor = 'text-green-800'
  } else if (technique.color === 'red') {
    // Intensity-based red: low failures → light, high failures → deep red
    if (failIntensity > 0.7) {
      bgColor = 'bg-red-300 hover:bg-red-400 border-red-500'
      textColor = 'text-red-950'
    } else if (failIntensity > 0.4) {
      bgColor = 'bg-red-200 hover:bg-red-300 border-red-400'
      textColor = 'text-red-900'
    } else {
      bgColor = 'bg-red-100 hover:bg-red-200 border-red-300'
      textColor = 'text-red-800'
    }
  } else {
    bgColor = 'bg-gray-50 hover:bg-gray-100 border-gray-200'
    textColor = 'text-gray-500'
  }

  return (
    <button
      onClick={onClick}
      className={`w-full text-left px-2 py-1.5 rounded border text-[10px] leading-tight transition-colors ${bgColor} ${textColor}`}
      title={`${technique.name} — ${technique.pass_count} pass, ${technique.fail_count} fail`}
    >
      <span className="font-semibold block truncate">{technique.id}</span>
      <span className="block truncate opacity-80">{technique.name}</span>
      {technique.total_checks > 0 && (
        <span className="block mt-0.5 font-mono text-[9px]">
          {technique.pass_count}P / {technique.fail_count}F
        </span>
      )}
    </button>
  )
}

export default function MitreAttackPage() {
  const [matrixData, setMatrixData] = useState<any>(null)
  const [loading, setLoading] = useState(false)
  const [analyzing, setAnalyzing] = useState(false)
  const [analysisPhase, setAnalysisPhase] = useState(0)
  const [selectedTechnique, setSelectedTechnique] = useState<string | null>(null)
  const [techniqueDetail, setTechniqueDetail] = useState<any>(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [providers, setProviders] = useState<any[]>([])
  const [selectedProvider, setSelectedProvider] = useState('')
  const [lastAnalyzed, setLastAnalyzed] = useState<string | null>(null)
  const [saasConnections, setSaasConnections] = useState<any[]>([])
  const [selectedSource, setSelectedSource] = useState<{ type: 'provider' | 'saas', id: string } | null>(null)
  const [coverageGaps, setCoverageGaps] = useState<any>(null)
  const [showGaps, setShowGaps] = useState(false)
  const phaseTimerRef = useRef<NodeJS.Timeout | null>(null)

  // Persist analysis results in sessionStorage so they survive navigation
  const STORAGE_KEY = 'darca_mitre_analysis'

  useEffect(() => {
    const loadData = async () => {
      try {
        const [provData, saasData] = await Promise.all([
          api.getProviders(),
          api.getSaaSConnections().catch(() => []),
        ])
        setProviders(provData)
        setSaasConnections(saasData)
      } catch {}

      // Restore previous analysis from sessionStorage
      try {
        const cached = sessionStorage.getItem(STORAGE_KEY)
        if (cached) {
          const { data, timestamp, providerId } = JSON.parse(cached)
          setMatrixData(data)
          setLastAnalyzed(timestamp)
          if (providerId) setSelectedProvider(providerId)
        }
      } catch {}
    }
    loadData()
  }, [])

  // Clean up phase timer on unmount
  useEffect(() => {
    return () => {
      if (phaseTimerRef.current) clearTimeout(phaseTimerRef.current)
    }
  }, [])

  const runAnalysis = async () => {
    setAnalyzing(true)
    setLoading(true)
    setAnalysisPhase(0)
    setSelectedTechnique(null)
    setTechniqueDetail(null)

    // Animate through analysis phases
    let phase = 0
    const advancePhase = () => {
      phase++
      if (phase < ANALYSIS_PHASES.length) {
        setAnalysisPhase(phase)
        phaseTimerRef.current = setTimeout(advancePhase, 600 + Math.random() * 400)
      }
    }
    phaseTimerRef.current = setTimeout(advancePhase, 500)

    try {
      const params: Record<string, string> = {}
      if (selectedProvider) params.provider_id = selectedProvider
      const data = await api.getMitreMatrix(params)

      // Ensure we show all phases before revealing results
      const minDisplayTime = ANALYSIS_PHASES.length * 700
      const startTime = Date.now()
      const elapsed = Date.now() - startTime
      if (elapsed < minDisplayTime) {
        await new Promise((r) => setTimeout(r, minDisplayTime - elapsed))
      }

      // Final phase done
      setAnalysisPhase(ANALYSIS_PHASES.length - 1)
      setMatrixData(data)
      const timestamp = new Date().toLocaleTimeString()
      setLastAnalyzed(timestamp)

      // Persist to sessionStorage
      try {
        sessionStorage.setItem(STORAGE_KEY, JSON.stringify({
          data,
          timestamp,
          providerId: selectedProvider,
        }))
      } catch {}
    } catch (err) {
      console.error(err)
    } finally {
      if (phaseTimerRef.current) {
        clearTimeout(phaseTimerRef.current)
        phaseTimerRef.current = null
      }
      // Small delay to show final phase before hiding
      setTimeout(() => {
        setAnalyzing(false)
        setLoading(false)
      }, 300)
    }
  }

  const handleProviderChange = (providerId: string) => {
    setSelectedProvider(providerId)
    // Don't auto-reload - user should click Run Analysis again
  }

  const handleTechniqueClick = async (techId: string) => {
    if (selectedTechnique === techId) {
      setSelectedTechnique(null)
      setTechniqueDetail(null)
      return
    }
    setSelectedTechnique(techId)
    setDetailLoading(true)
    try {
      const params: Record<string, string> = {}
      if (selectedProvider) params.provider_id = selectedProvider
      const detail = await api.getMitreTechnique(techId, params)
      setTechniqueDetail(detail)
    } catch (err) {
      console.error(err)
    } finally {
      setDetailLoading(false)
    }
  }

  const closeDetail = () => {
    setSelectedTechnique(null)
    setTechniqueDetail(null)
  }

  const handleExportNavigator = async () => {
    try {
      const params: Record<string, string> = {}
      if (selectedProvider) params.provider_id = selectedProvider
      const layer = await api.getMitreNavigatorLayer(params)
      const blob = new Blob([JSON.stringify(layer, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `darca-mitre-layer-${new Date().toISOString().slice(0, 10)}.json`
      a.click()
      URL.revokeObjectURL(url)
    } catch (err) {
      console.error('Export failed:', err)
    }
  }

  const handleShowGaps = async () => {
    if (showGaps) { setShowGaps(false); return }
    try {
      const params: Record<string, string> = {}
      if (selectedProvider) params.provider_id = selectedProvider
      const gaps = await api.getMitreCoverageGaps(params)
      setCoverageGaps(gaps)
      setShowGaps(true)
    } catch (err) {
      console.error('Coverage gaps failed:', err)
    }
  }

  // Compute max fail count for heatmap intensity
  const maxFails = matrixData?.matrix?.reduce((max: number, tactic: any) =>
    Math.max(max, ...tactic.techniques.map((t: any) => t.fail_count || 0)), 0) || 1

  const hasMatrix = matrixData?.matrix?.length > 0

  return (
    <div>
      <Header
        title="MITRE ATT&CK Matrix"
        subtitle="Cloud security posture mapped to MITRE ATT&CK framework techniques"
        breadcrumbs={[{ label: 'Posture', href: '/darca/overview' }, { label: 'MITRE ATT&CK' }]}
      />

      {/* Controls Bar */}
      <div className="card mb-6">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2">
              <FunnelIcon className="w-4 h-4 text-brand-gray-400" />
              <span className="text-sm font-semibold text-brand-navy">Account / SaaS</span>
            </div>
            <select
              value={selectedProvider}
              onChange={(e) => handleProviderChange(e.target.value)}
              className="select-field min-w-[220px]"
            >
              <option value="">All Accounts & SaaS</option>
              {providers.length > 0 && (
                <optgroup label="Cloud Providers">
                  {providers.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.alias || p.provider_type?.toUpperCase()} ({p.provider_type}) {p.account_id ? `- ${p.account_id}` : ''}
                    </option>
                  ))}
                </optgroup>
              )}
              {saasConnections.length > 0 && (
                <optgroup label="SaaS Connections">
                  {saasConnections.map((s) => (
                    <option key={`saas-${s.id}`} value={s.id}>
                      {s.name || s.provider_type?.toUpperCase()} (SaaS)
                    </option>
                  ))}
                </optgroup>
              )}
            </select>
            {lastAnalyzed && (
              <span className="text-xs text-brand-gray-400">
                Last analyzed: {lastAnalyzed}
              </span>
            )}
          </div>

          <div className="flex items-center gap-2">
            {hasMatrix && (
              <>
                <button
                  onClick={handleShowGaps}
                  className={`inline-flex items-center gap-2 px-4 py-2.5 border text-sm font-medium rounded-lg transition-colors ${
                    showGaps
                      ? 'bg-brand-blue/10 border-brand-blue/30 text-brand-blue'
                      : 'border-brand-gray-200 text-brand-gray-600 hover:bg-brand-gray-50'
                  }`}
                >
                  <ChartBarIcon className="w-4 h-4" />
                  Coverage Gaps
                </button>
                <button
                  onClick={handleExportNavigator}
                  className="inline-flex items-center gap-2 px-4 py-2.5 border border-brand-gray-200 rounded-lg hover:bg-brand-gray-50 text-sm font-medium text-brand-gray-600 transition-colors"
                >
                  <ArrowDownTrayIcon className="w-4 h-4" />
                  Export Layer
                </button>
              </>
            )}
            <button
              onClick={runAnalysis}
              disabled={analyzing}
              className="inline-flex items-center gap-2 px-5 py-2.5 bg-brand-green text-white text-sm font-semibold rounded-lg hover:bg-brand-green/90 transition-colors disabled:opacity-60 shadow-sm"
            >
              <ArrowPathIcon className={`w-4 h-4 ${analyzing ? 'animate-spin' : ''}`} />
              {analyzing ? 'Analyzing...' : 'Run Analysis'}
            </button>
          </div>
        </div>
      </div>

      {/* Summary Stats */}
      {matrixData?.summary && !analyzing && (
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 mb-6">
          <div className="bg-white rounded-lg border border-brand-gray-200 px-4 py-3">
            <p className="text-xs text-brand-gray-400 uppercase font-semibold">Techniques</p>
            <p className="text-2xl font-bold text-brand-navy">{matrixData.summary.total_techniques}</p>
          </div>
          <div className="bg-white rounded-lg border border-brand-gray-200 px-4 py-3">
            <p className="text-xs text-brand-gray-400 uppercase font-semibold">Assessed</p>
            <p className="text-2xl font-bold text-blue-600">{matrixData.summary.assessed}</p>
          </div>
          <div className="bg-white rounded-lg border border-brand-gray-200 px-4 py-3">
            <p className="text-xs text-brand-gray-400 uppercase font-semibold">Protected</p>
            <p className="text-2xl font-bold text-green-600">{matrixData.summary.protected}</p>
          </div>
          <div className="bg-white rounded-lg border border-brand-gray-200 px-4 py-3">
            <p className="text-xs text-brand-gray-400 uppercase font-semibold">At Risk</p>
            <p className="text-2xl font-bold text-red-600">{matrixData.summary.at_risk}</p>
          </div>
          <div className="bg-white rounded-lg border border-brand-gray-200 px-4 py-3">
            <p className="text-xs text-brand-gray-400 uppercase font-semibold">Not Assessed</p>
            <p className="text-2xl font-bold text-gray-400">{matrixData.summary.not_assessed}</p>
          </div>
          <div className="bg-white rounded-lg border border-brand-gray-200 px-4 py-3">
            <p className="text-xs text-brand-gray-400 uppercase font-semibold">Coverage</p>
            <p className={`text-2xl font-bold ${
              matrixData.summary.coverage_rate >= 70 ? 'text-green-600' :
              matrixData.summary.coverage_rate >= 40 ? 'text-amber-500' : 'text-red-600'
            }`}>{matrixData.summary.coverage_rate}%</p>
          </div>
        </div>
      )}

      {/* Analysis in Progress */}
      {analyzing && (
        <div className="card text-center py-12 mb-6">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-brand-green/10 mb-6">
            <ArrowPathIcon className="w-8 h-8 text-brand-green animate-spin" />
          </div>
          <h3 className="text-lg font-semibold text-brand-navy mb-4">Analyzing Security Posture</h3>
          <div className="max-w-md mx-auto space-y-2">
            {ANALYSIS_PHASES.map((phase, i) => (
              <div
                key={i}
                className={`flex items-center gap-3 px-4 py-2 rounded-lg transition-all duration-300 ${
                  i < analysisPhase
                    ? 'bg-green-50 text-green-700'
                    : i === analysisPhase
                    ? 'bg-brand-green/10 text-brand-navy font-medium'
                    : 'text-brand-gray-300'
                }`}
              >
                <div className={`w-5 h-5 rounded-full flex items-center justify-center flex-shrink-0 ${
                  i < analysisPhase
                    ? 'bg-green-500 text-white'
                    : i === analysisPhase
                    ? 'bg-brand-green text-white animate-pulse'
                    : 'bg-brand-gray-200'
                }`}>
                  {i < analysisPhase ? (
                    <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" />
                    </svg>
                  ) : (
                    <span className="text-[9px] font-bold">{i + 1}</span>
                  )}
                </div>
                <span className="text-sm">{phase}</span>
              </div>
            ))}
          </div>
          {/* Progress bar */}
          <div className="mt-6 max-w-sm mx-auto">
            <div className="h-1.5 bg-brand-gray-200 rounded-full overflow-hidden">
              <div
                className="h-full bg-brand-green rounded-full transition-all duration-500 ease-out"
                style={{ width: `${((analysisPhase + 1) / ANALYSIS_PHASES.length) * 100}%` }}
              />
            </div>
          </div>
        </div>
      )}

      {/* Empty state — no analysis run yet */}
      {!analyzing && !hasMatrix && (
        <div className="card text-center py-16">
          <ShieldCheckIcon className="w-16 h-16 mx-auto text-brand-gray-300 mb-4" />
          <h3 className="text-lg font-semibold text-brand-navy mb-2">MITRE ATT&CK Analysis</h3>
          <p className="text-sm text-brand-gray-400 mb-6 max-w-md mx-auto">
            Map your cloud security findings against the MITRE ATT&CK framework to understand your
            coverage across 11 tactics and 100+ techniques. Select a provider filter if needed,
            then click Run Analysis.
          </p>
          <button
            onClick={runAnalysis}
            disabled={analyzing}
            className="inline-flex items-center gap-2 px-6 py-3 bg-brand-green text-white text-sm font-semibold rounded-lg hover:bg-brand-green/90 transition-colors disabled:opacity-60 shadow-sm"
          >
            <ArrowPathIcon className="w-5 h-5" />
            Run Analysis
          </button>
        </div>
      )}

      {/* No findings banner */}
      {!analyzing && hasMatrix && matrixData?.summary?.assessed === 0 && (
        <div className="bg-amber-50 border border-amber-200 rounded-lg px-4 py-3 mb-6 flex items-center gap-3">
          <ShieldCheckIcon className="w-5 h-5 text-amber-500 flex-shrink-0" />
          <p className="text-sm text-amber-800">
            <strong>No scan findings available.</strong> The matrix shows all techniques as &quot;Not Assessed&quot; because no cloud or SaaS scans have been run yet.
            Go to <a href="/darca/scans" className="underline font-medium">Scans</a> to run your first security scan, then come back to see your MITRE ATT&amp;CK coverage.
          </p>
        </div>
      )}

      {/* Matrix display */}
      {!analyzing && hasMatrix && (
        <>
          {/* Legend */}
          <div className="flex items-center gap-6 mb-4 px-1">
            <div className="flex items-center gap-2">
              <div className="w-4 h-4 rounded bg-green-100 border border-green-300" />
              <span className="text-xs text-brand-gray-600">Protected (all checks pass)</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-4 h-4 rounded bg-red-100 border border-red-300" />
              <span className="text-xs text-brand-gray-600">At Risk (one or more checks fail)</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-4 h-4 rounded bg-gray-50 border border-gray-200" />
              <span className="text-xs text-brand-gray-600">Not Assessed</span>
            </div>
          </div>

          <div className="card p-0 overflow-hidden">
            <div className="overflow-x-auto">
              <div className="inline-flex min-w-full">
                {matrixData?.matrix?.map((tactic: any) => (
                  <div
                    key={tactic.tactic}
                    className={`flex-shrink-0 w-36 border-r border-brand-gray-200 last:border-r-0 border-t-4 ${
                      TACTIC_COLORS[tactic.tactic] || 'border-t-gray-400'
                    }`}
                  >
                    {/* Tactic Header */}
                    <div className="px-2 py-2 bg-brand-gray-50 border-b border-brand-gray-200 sticky top-0">
                      <h3 className="text-[10px] font-bold text-brand-navy uppercase tracking-wider text-center leading-tight">
                        {tactic.tactic_label}
                      </h3>
                      <p className="text-[9px] text-brand-gray-400 text-center mt-0.5">
                        {tactic.techniques.length} techniques
                      </p>
                    </div>
                    {/* Technique Cells */}
                    <div className="p-1.5 space-y-1">
                      {tactic.techniques.map((tech: any) => (
                        <TechniqueCell
                          key={tech.id}
                          technique={tech}
                          onClick={() => handleTechniqueClick(tech.id)}
                          maxFails={maxFails}
                        />
                      ))}
                      {tactic.techniques.length === 0 && (
                        <p className="text-[10px] text-brand-gray-400 text-center py-4 italic">
                          No techniques
                        </p>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </>
      )}

      {/* Coverage Gaps Panel */}
      {showGaps && coverageGaps && (
        <div className="mt-6 card">
          <div className="flex items-start justify-between mb-4">
            <div>
              <h2 className="text-lg font-semibold text-brand-navy">MITRE ATT&CK Coverage Gap Analysis</h2>
              <p className="text-sm text-brand-gray-400 mt-1">
                Coverage Score: <span className={`font-bold ${
                  coverageGaps.coverage_score >= 70 ? 'text-green-600' :
                  coverageGaps.coverage_score >= 40 ? 'text-amber-500' : 'text-red-600'
                }`}>{coverageGaps.coverage_score}%</span>
                &nbsp;&middot;&nbsp;{coverageGaps.protected} protected &middot; {coverageGaps.at_risk} at risk &middot; {coverageGaps.not_covered} not covered
              </p>
            </div>
            <button onClick={() => setShowGaps(false)} className="p-1.5 rounded-lg hover:bg-brand-gray-100 text-brand-gray-400">
              <XMarkIcon className="w-5 h-5" />
            </button>
          </div>

          {coverageGaps.techniques_failing?.length > 0 && (
            <div className="mb-4">
              <h3 className="text-xs font-semibold text-red-600 uppercase tracking-wider mb-2">
                At Risk Techniques ({coverageGaps.techniques_failing.length})
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {coverageGaps.techniques_failing.slice(0, 10).map((t: any) => (
                  <button
                    key={t.id}
                    onClick={() => { handleTechniqueClick(t.id); setShowGaps(false) }}
                    className="flex items-center gap-3 px-3 py-2 bg-red-50 border border-red-200 rounded-lg text-left hover:bg-red-100 transition-colors"
                  >
                    <span className="text-xs font-mono font-bold text-red-700">{t.id}</span>
                    <span className="text-xs text-red-800 flex-1 truncate">{t.name}</span>
                    <span className="text-[10px] font-mono text-red-600">{t.fail_count}F</span>
                  </button>
                ))}
              </div>
            </div>
          )}

          {coverageGaps.techniques_not_covered?.length > 0 && (
            <div>
              <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">
                Not Covered ({coverageGaps.techniques_not_covered.length})
              </h3>
              <div className="flex flex-wrap gap-2">
                {coverageGaps.techniques_not_covered.map((t: any) => (
                  <span key={t.id} className="px-2 py-1 bg-gray-100 border border-gray-200 rounded text-[10px] text-gray-500 font-mono">
                    {t.id} {t.name}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Technique Detail Panel */}
      {selectedTechnique && (
        <div className="mt-6 card">
          <div className="flex items-start justify-between mb-4">
            <div>
              <h2 className="text-lg font-semibold text-brand-navy">
                {detailLoading
                  ? 'Loading...'
                  : `${techniqueDetail?.technique?.id} - ${techniqueDetail?.technique?.name}`}
              </h2>
              <p className="text-sm text-brand-gray-400 mt-1">
                {techniqueDetail?.technique?.tactic && (
                  <span className="capitalize">{techniqueDetail.technique.tactic.replace(/-/g, ' ')}</span>
                )}
              </p>
            </div>
            <button
              onClick={closeDetail}
              className="p-1.5 rounded-lg hover:bg-brand-gray-100 text-brand-gray-400 hover:text-brand-navy"
            >
              <XMarkIcon className="w-5 h-5" />
            </button>
          </div>

          {detailLoading ? (
            <div className="animate-pulse space-y-3">
              {[...Array(3)].map((_, i) => (
                <div key={i} className="h-10 bg-brand-gray-100 rounded" />
              ))}
            </div>
          ) : techniqueDetail ? (
            <div className="space-y-6">
              {/* Technique Description */}
              <div>
                <h4 className="text-xs font-semibold text-brand-gray-500 uppercase tracking-wider mb-2">
                  Description
                </h4>
                <p className="text-sm text-brand-gray-700">{techniqueDetail.technique.description}</p>
                {techniqueDetail.technique.url && (
                  <a
                    href={techniqueDetail.technique.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 mt-2 text-sm text-brand-green hover:underline"
                  >
                    View on MITRE ATT&CK &rarr;
                  </a>
                )}
              </div>

              {/* Assessment Summary */}
              <div className="grid grid-cols-4 gap-4">
                <div className={`rounded-lg p-3 text-center ${
                  techniqueDetail.assessment.status === 'protected'
                    ? 'bg-green-50'
                    : techniqueDetail.assessment.status === 'at_risk'
                    ? 'bg-red-50'
                    : 'bg-gray-50'
                }`}>
                  <p className={`text-lg font-bold ${
                    techniqueDetail.assessment.status === 'protected'
                      ? 'text-green-700'
                      : techniqueDetail.assessment.status === 'at_risk'
                      ? 'text-red-700'
                      : 'text-gray-500'
                  }`}>
                    {techniqueDetail.assessment.status === 'protected'
                      ? 'Protected'
                      : techniqueDetail.assessment.status === 'at_risk'
                      ? 'At Risk'
                      : 'Not Assessed'}
                  </p>
                  <p className="text-xs text-brand-gray-400">Overall Status</p>
                </div>
                <div className="bg-brand-gray-50 rounded-lg p-3 text-center">
                  <p className="text-lg font-bold text-brand-navy">{techniqueDetail.assessment.total}</p>
                  <p className="text-xs text-brand-gray-400">Total Checks</p>
                </div>
                <div className="bg-green-50 rounded-lg p-3 text-center">
                  <p className="text-lg font-bold text-green-700">{techniqueDetail.assessment.pass_count}</p>
                  <p className="text-xs text-green-600">Passed</p>
                </div>
                <div className="bg-red-50 rounded-lg p-3 text-center">
                  <p className="text-lg font-bold text-red-700">{techniqueDetail.assessment.fail_count}</p>
                  <p className="text-xs text-red-600">Failed</p>
                </div>
              </div>

              {/* Related Checks */}
              {techniqueDetail.checks?.length > 0 && (
                <div>
                  <h4 className="text-xs font-semibold text-brand-gray-500 uppercase tracking-wider mb-3">
                    Related Security Checks ({techniqueDetail.checks.length})
                  </h4>
                  <div className="space-y-3">
                    {techniqueDetail.checks.map((check: any, idx: number) => (
                      <div
                        key={idx}
                        className={`rounded-lg border p-4 ${
                          check.status === 'PASS'
                            ? 'border-green-200 bg-green-50/50'
                            : 'border-red-200 bg-red-50/50'
                        }`}
                      >
                        <div className="flex items-start justify-between mb-2">
                          <div>
                            <span className="text-xs font-mono text-brand-gray-500">{check.check_id}</span>
                            <p className="text-sm font-medium text-brand-navy">{check.check_title}</p>
                          </div>
                          <span
                            className={`px-2 py-0.5 rounded-full text-xs font-medium ${
                              check.status === 'PASS'
                                ? 'bg-green-100 text-green-800'
                                : 'bg-red-100 text-red-800'
                            }`}
                          >
                            {check.status}
                          </span>
                        </div>

                        {/* Check description */}
                        {check.check_description && (
                          <p className="text-xs text-brand-gray-600 mb-2">{check.check_description}</p>
                        )}

                        <div className="flex items-center gap-4 text-xs text-brand-gray-500">
                          <span>Service: {check.service}</span>
                          {check.region && <span>Region: {check.region}</span>}
                          {check.resource_name && <span>Resource: {check.resource_name}</span>}
                        </div>

                        {/* Evidence log */}
                        {check.evidence_log && (() => {
                          let ev: any = null
                          try { ev = typeof check.evidence_log === 'string' ? JSON.parse(check.evidence_log) : check.evidence_log } catch {}
                          if (!ev || typeof ev === 'string') {
                            ev = { api_call: check.evidence_log }
                          }
                          return (
                            <div className="mt-3">
                              <p className="text-[10px] font-semibold text-brand-gray-500 uppercase mb-1">API Evidence</p>
                              <div className="bg-brand-navy rounded p-2 font-mono text-[10px] leading-relaxed space-y-1 overflow-x-auto">
                                {ev.api_call && (
                                  <div>
                                    <span className="text-brand-green">$ </span>
                                    <span className="text-gray-300">{ev.api_call}</span>
                                  </div>
                                )}
                                {ev.response && (
                                  <div>
                                    <span className="text-amber-400">{'>'} </span>
                                    <span className="text-gray-400">{ev.response}</span>
                                  </div>
                                )}
                              </div>
                            </div>
                          )
                        })()}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {techniqueDetail.checks?.length === 0 && (
                <div className="text-center py-8">
                  <p className="text-sm text-brand-gray-400">
                    No security checks have been executed that map to this technique yet.
                    Run a cloud or SaaS scan to evaluate your posture.
                  </p>
                </div>
              )}
            </div>
          ) : null}
        </div>
      )}
    </div>
  )
}
