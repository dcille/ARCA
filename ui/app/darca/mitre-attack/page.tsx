'use client'

import { useEffect, useState } from 'react'
import Header from '@/components/layout/Header'
import { api } from '@/lib/api'
import { XMarkIcon } from '@heroicons/react/24/outline'

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

function TechniqueCell({
  technique,
  onClick,
}: {
  technique: any
  onClick: () => void
}) {
  const bgColor =
    technique.color === 'green'
      ? 'bg-green-100 hover:bg-green-200 border-green-300'
      : technique.color === 'red'
      ? 'bg-red-100 hover:bg-red-200 border-red-300'
      : 'bg-gray-50 hover:bg-gray-100 border-gray-200'

  const textColor =
    technique.color === 'green'
      ? 'text-green-800'
      : technique.color === 'red'
      ? 'text-red-800'
      : 'text-gray-500'

  return (
    <button
      onClick={onClick}
      className={`w-full text-left px-2 py-1.5 rounded border text-[10px] leading-tight transition-colors ${bgColor} ${textColor}`}
      title={technique.name}
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
  const [loading, setLoading] = useState(true)
  const [selectedTechnique, setSelectedTechnique] = useState<string | null>(null)
  const [techniqueDetail, setTechniqueDetail] = useState<any>(null)
  const [detailLoading, setDetailLoading] = useState(false)

  useEffect(() => {
    const load = async () => {
      try {
        const data = await api.getMitreMatrix()
        setMatrixData(data)
      } catch (err) {
        console.error(err)
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [])

  const handleTechniqueClick = async (techId: string) => {
    if (selectedTechnique === techId) {
      setSelectedTechnique(null)
      setTechniqueDetail(null)
      return
    }
    setSelectedTechnique(techId)
    setDetailLoading(true)
    try {
      const detail = await api.getMitreTechnique(techId)
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

  return (
    <div>
      <Header
        title="MITRE ATT&CK Matrix"
        subtitle="Cloud security posture mapped to MITRE ATT&CK framework techniques"
      />

      {/* Summary Stats */}
      {matrixData?.summary && (
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

      {/* Matrix */}
      {loading ? (
        <div className="card animate-pulse">
          <div className="h-96 bg-brand-gray-100 rounded" />
        </div>
      ) : (
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
