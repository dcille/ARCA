'use client'

import { useEffect, useState } from 'react'
import { useParams } from 'next/navigation'
import Link from 'next/link'
import Header from '@/components/layout/Header'
import Badge from '@/components/ui/Badge'
import { api } from '@/lib/api'
import { ArrowLeftIcon, ArrowPathIcon, ClipboardDocumentIcon, LinkIcon } from '@heroicons/react/24/outline'

export default function FindingDetailPage() {
  const params = useParams()
  const findingId = params.id as string
  const [finding, setFinding] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [updating, setUpdating] = useState(false)

  useEffect(() => {
    if (findingId === 'all') return
    api.getRRFindingDetail(findingId)
      .then(setFinding)
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [findingId])

  // "all" route shows findings list
  if (findingId === 'all') {
    return <AllFindingsPage />
  }

  async function handleStatusChange(newStatus: string) {
    setUpdating(true)
    try {
      await api.updateRRFinding(findingId, { finding_status: newStatus })
      setFinding((prev: any) => ({ ...prev, finding_status: newStatus }))
    } catch (e) {
      console.error(e)
    }
    setUpdating(false)
  }

  if (loading || !finding) {
    return (
      <div className="space-y-6">
        <Header title="Finding Detail" subtitle="Loading..." />
        <div className="flex items-center justify-center py-20">
          <ArrowPathIcon className="w-8 h-8 animate-spin text-brand-gray-300" />
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Link href="/darca/ransomware-readiness" className="p-2 rounded-lg hover:bg-brand-gray-100 transition-colors">
          <ArrowLeftIcon className="w-5 h-5 text-brand-gray-400" />
        </Link>
        <Header
          title={finding.rule_id}
          subtitle={finding.rule_name}
        />
      </div>

      {/* Status + meta */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-white border border-brand-gray-200 rounded-xl p-6 space-y-4">
          <div className="flex items-center gap-3 flex-wrap">
            <Badge type="severity" value={finding.severity} />
            <span className={`px-2 py-0.5 rounded text-xs font-bold ${finding.status === 'fail' ? 'bg-red-100 text-red-700' : finding.status === 'pass' ? 'bg-emerald-100 text-emerald-700' : 'bg-amber-100 text-amber-700'}`}>
              {finding.status.toUpperCase()}
            </span>
            <span className="text-xs text-brand-gray-400">
              {finding.provider?.toUpperCase()} &middot; {finding.domain}
            </span>
            <span className="text-xs text-brand-gray-400">
              Finding status: <strong>{finding.finding_status}</strong>
            </span>
          </div>

          <div>
            <h3 className="text-sm font-semibold text-brand-navy mb-1">Description</h3>
            <p className="text-sm text-brand-gray-600">{finding.rule_description}</p>
          </div>

          {/* Ransomware context */}
          {finding.ransomware_context && (
            <div className="bg-red-50 border border-red-100 rounded-lg p-3">
              <h3 className="text-sm font-semibold text-red-800 mb-1">Riesgo de Ransomware</h3>
              <p className="text-sm text-red-700">{finding.ransomware_context}</p>
            </div>
          )}

          <div className="grid grid-cols-3 gap-4">
            <div className="bg-brand-gray-50 rounded-lg p-3 text-center">
              <p className="text-lg font-bold text-brand-navy">{finding.resource_count}</p>
              <p className="text-xs text-brand-gray-400">Total Resources</p>
            </div>
            <div className="bg-emerald-50 rounded-lg p-3 text-center">
              <p className="text-lg font-bold text-emerald-700">{finding.passed_resources}</p>
              <p className="text-xs text-emerald-600">Passed</p>
            </div>
            <div className="bg-red-50 rounded-lg p-3 text-center">
              <p className="text-lg font-bold text-red-700">{finding.failed_resources}</p>
              <p className="text-xs text-red-600">Failed</p>
            </div>
          </div>

          {/* Evidence */}
          {finding.evidence && Object.keys(finding.evidence).length > 0 && (
            <div>
              <h3 className="text-sm font-semibold text-brand-navy mb-2">Evidence</h3>
              <div className="bg-brand-gray-50 rounded-lg p-4 space-y-3">
                {/* Summary */}
                {finding.evidence.summary && (
                  <p className="text-sm text-brand-gray-700">{finding.evidence.summary}</p>
                )}

                {/* Expected vs Actual */}
                {(finding.evidence.expected || finding.evidence.actual) && (
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    {finding.evidence.expected && (
                      <div className="bg-white rounded-lg p-3 border border-brand-gray-200">
                        <p className="text-xs font-semibold text-brand-gray-400 uppercase mb-1">Expected</p>
                        <p className="text-sm text-brand-gray-600">{finding.evidence.expected}</p>
                      </div>
                    )}
                    {finding.evidence.actual && (
                      <div className="bg-white rounded-lg p-3 border border-brand-gray-200">
                        <p className="text-xs font-semibold text-brand-gray-400 uppercase mb-1">Actual</p>
                        <p className="text-sm text-brand-gray-600">{finding.evidence.actual}</p>
                      </div>
                    )}
                  </div>
                )}

                {/* Checks evaluated */}
                {finding.evidence.checks_evaluated && finding.evidence.checks_evaluated.length > 0 && (
                  <div>
                    <p className="text-xs font-semibold text-brand-gray-400 uppercase mb-1">Checks Evaluated</p>
                    <div className="flex flex-wrap gap-1.5">
                      {finding.evidence.checks_evaluated.map((check: string) => (
                        <span key={check} className="px-2 py-0.5 bg-white border border-brand-gray-200 rounded text-xs text-brand-gray-600 font-mono">
                          {check}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Failed resource details */}
                {finding.evidence.failed_details && finding.evidence.failed_details.length > 0 && (
                  <div>
                    <p className="text-xs font-semibold text-brand-gray-400 uppercase mb-1">Failed Resources</p>
                    <div className="space-y-1.5 max-h-48 overflow-y-auto">
                      {finding.evidence.failed_details.map((detail: any, i: number) => (
                        <div key={i} className="bg-white rounded p-2 border border-red-100 text-xs">
                          <span className="font-medium text-brand-navy">{detail.resource_name || detail.resource_id || 'Unknown'}</span>
                          {detail.check_id && <span className="text-brand-gray-400 ml-2 font-mono">{detail.check_id}</span>}
                          {detail.status_extended && (
                            <p className="text-brand-gray-500 mt-0.5">{detail.status_extended}</p>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Check type badge */}
                {finding.evidence.check_type && (
                  <div className="flex items-center gap-2 pt-1 border-t border-brand-gray-200">
                    <span className="text-xs text-brand-gray-400">Tipo de check:</span>
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                      finding.evidence.check_type === 'automated' ? 'bg-blue-100 text-blue-700' :
                      finding.evidence.check_type === 'composite' ? 'bg-purple-100 text-purple-700' :
                      'bg-amber-100 text-amber-700'
                    }`}>
                      {finding.evidence.check_type === 'automated' ? 'Automático (CSPM)' :
                       finding.evidence.check_type === 'composite' ? 'Compuesto (multi-check)' :
                       'Manual (gobernanza)'}
                    </span>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* NIST Mapping */}
          <div>
            <h3 className="text-sm font-semibold text-brand-navy mb-1">NIST CSF 2.0 Mapping</h3>
            <p className="text-sm text-brand-gray-600">
              Category: <strong>{finding.nist_mapping?.category}</strong> &middot;
              Subcategory: <strong>{finding.nist_mapping?.subcategory}</strong>
            </p>
          </div>
        </div>

        {/* Actions sidebar */}
        <div className="space-y-4">
          <div className="bg-white border border-brand-gray-200 rounded-xl p-6">
            <h3 className="text-sm font-semibold text-brand-gray-400 uppercase mb-3">Actions</h3>
            <div className="space-y-2">
              {['open', 'accepted', 'exception', 'resolved'].map(status => (
                <button
                  key={status}
                  onClick={() => handleStatusChange(status)}
                  disabled={updating || finding.finding_status === status}
                  className={`w-full text-left px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                    finding.finding_status === status
                      ? 'bg-brand-navy text-white'
                      : 'bg-brand-gray-50 text-brand-gray-600 hover:bg-brand-gray-100'
                  } disabled:opacity-50`}
                >
                  {status.charAt(0).toUpperCase() + status.slice(1)}
                </button>
              ))}
            </div>
          </div>

          <div className="bg-white border border-brand-gray-200 rounded-xl p-6">
            <h3 className="text-sm font-semibold text-brand-gray-400 uppercase mb-3">Timeline</h3>
            <div className="space-y-2 text-sm">
              <p className="text-brand-gray-500">
                First seen: <strong>{finding.first_seen ? new Date(finding.first_seen).toLocaleDateString() : 'N/A'}</strong>
              </p>
              {finding.resolved_at && (
                <p className="text-emerald-600">
                  Resolved: <strong>{new Date(finding.resolved_at).toLocaleDateString()}</strong>
                </p>
              )}
            </div>
          </div>

          {/* Remediation */}
          {finding.remediation && Object.keys(finding.remediation).length > 0 && (
            <div className="bg-white border border-brand-gray-200 rounded-xl p-6">
              <h3 className="text-sm font-semibold text-brand-gray-400 uppercase mb-3">Remediation</h3>
              <div className="space-y-3">
                {Object.entries(finding.remediation).map(([provider, guidance]) => (
                  <div key={provider}>
                    <p className="text-xs font-bold text-brand-navy uppercase">{provider}</p>
                    <p className="text-sm text-brand-gray-600 mt-0.5">{guidance as string}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function AllFindingsPage() {
  const [findings, setFindings] = useState<any>(null)
  const [filters, setFilters] = useState<Record<string, string>>({ page_size: '50' })
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    setLoading(true)
    api.getRRFindings(filters)
      .then(setFindings)
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [JSON.stringify(filters)])

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Link href="/darca/ransomware-readiness" className="p-2 rounded-lg hover:bg-brand-gray-100 transition-colors">
          <ArrowLeftIcon className="w-5 h-5 text-brand-gray-400" />
        </Link>
        <Header title="All RR Findings" subtitle={`${findings?.total ?? 0} total findings`} />
      </div>

      {/* Filters */}
      <div className="flex gap-3 flex-wrap">
        {['all', 'fail', 'pass', 'warning'].map(s => (
          <button
            key={s}
            onClick={() => setFilters(prev => ({ ...prev, status: s === 'all' ? '' : s }))}
            className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
              (filters.status || '') === (s === 'all' ? '' : s)
                ? 'bg-brand-navy text-white'
                : 'bg-brand-gray-100 text-brand-gray-600 hover:bg-brand-gray-200'
            }`}
          >
            {s.charAt(0).toUpperCase() + s.slice(1)}
          </button>
        ))}
        <span className="border-l border-brand-gray-200 mx-1" />
        {['all', 'critical', 'high', 'medium', 'low'].map(s => (
          <button
            key={s}
            onClick={() => setFilters(prev => ({ ...prev, severity: s === 'all' ? '' : s }))}
            className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
              (filters.severity || '') === (s === 'all' ? '' : s)
                ? 'bg-brand-navy text-white'
                : 'bg-brand-gray-100 text-brand-gray-600 hover:bg-brand-gray-200'
            }`}
          >
            {s.charAt(0).toUpperCase() + s.slice(1)}
          </button>
        ))}
      </div>

      {/* Table */}
      <div className="bg-white border border-brand-gray-200 rounded-xl overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center py-20">
            <ArrowPathIcon className="w-6 h-6 animate-spin text-brand-gray-300" />
          </div>
        ) : (
          <div className="divide-y divide-brand-gray-100">
            {findings?.items?.map((f: any) => (
              <Link
                key={f.id}
                href={`/darca/ransomware-readiness/findings/${f.id}`}
                className="flex items-center gap-3 px-6 py-3 hover:bg-brand-gray-50 transition-colors"
              >
                <span className={`px-2 py-0.5 rounded text-xs font-bold ${f.status === 'fail' ? 'bg-red-100 text-red-700' : f.status === 'pass' ? 'bg-emerald-100 text-emerald-700' : 'bg-amber-100 text-amber-700'}`}>
                  {f.status.toUpperCase()}
                </span>
                <Badge type="severity" value={f.severity} />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-brand-navy truncate">{f.rule_id}: {f.rule_name}</p>
                  <p className="text-xs text-brand-gray-400">{f.domain} &middot; {f.provider?.toUpperCase()}</p>
                </div>
                <span className="text-xs text-brand-gray-400">{f.finding_status}</span>
              </Link>
            ))}
            {(!findings?.items || findings.items.length === 0) && (
              <p className="px-6 py-8 text-sm text-brand-gray-400 text-center">No findings match the current filters.</p>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
