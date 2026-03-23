'use client'

import { useEffect, useState } from 'react'
import { useParams, useRouter } from 'next/navigation'
import Header from '@/components/layout/Header'
import { api } from '@/lib/api'
import { ArrowLeftIcon } from '@heroicons/react/24/outline'

const RISK_COLORS: Record<string, string> = {
  Critical: 'bg-red-600 text-white',
  High: 'bg-orange-500 text-white',
  Medium: 'bg-yellow-500 text-white',
  Low: 'bg-green-500 text-white',
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-red-600',
  high: 'text-orange-500',
  medium: 'text-yellow-600',
  low: 'text-blue-500',
  informational: 'text-gray-400',
}

const SEVERITY_BG: Record<string, string> = {
  critical: 'bg-red-50 border-red-200',
  high: 'bg-orange-50 border-orange-200',
  medium: 'bg-yellow-50 border-yellow-200',
  low: 'bg-blue-50 border-blue-200',
}

export default function AccountDashboard() {
  const params = useParams()
  const router = useRouter()
  const providerId = params.id as string
  const [data, setData] = useState<any>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!providerId) return
    api.getAccountDashboard(providerId)
      .then(setData)
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [providerId])

  if (loading) {
    return (
      <div>
        <Header title="Account Dashboard" subtitle="Loading..." />
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {[...Array(8)].map((_, i) => (
            <div key={i} className="card animate-pulse"><div className="h-24 bg-brand-gray-100 rounded" /></div>
          ))}
        </div>
      </div>
    )
  }

  if (!data) {
    return (
      <div>
        <Header title="Account Dashboard" subtitle="Account not found" />
        <button onClick={() => router.push('/darca/providers')} className="btn-outline">Back to Providers</button>
      </div>
    )
  }

  const { provider, posture, inventory, applicable_frameworks, top_findings, mitre_summary, scan_trends, ai_summary } = data

  return (
    <div>
      <Header
        title={`${provider.alias}`}
        subtitle={`${provider.provider_type.toUpperCase()} Account Dashboard${provider.account_id ? ` — ${provider.account_id}` : ''}`}
        actions={
          <button onClick={() => router.push('/darca/providers')} className="btn-outline flex items-center gap-2">
            <ArrowLeftIcon className="w-4 h-4" />
            Back
          </button>
        }
      />

      {/* AI Security Consultant Summary */}
      <div className={`mb-6 rounded-xl border-2 p-5 ${
        ai_summary.risk_level === 'Critical' ? 'border-red-300 bg-red-50' :
        ai_summary.risk_level === 'High' ? 'border-orange-300 bg-orange-50' :
        ai_summary.risk_level === 'Medium' ? 'border-yellow-300 bg-yellow-50' :
        'border-green-300 bg-green-50'
      }`}>
        <div className="flex items-start gap-4">
          <div className={`px-3 py-1.5 rounded-lg text-sm font-bold ${RISK_COLORS[ai_summary.risk_level] || 'bg-gray-500 text-white'}`}>
            {ai_summary.risk_level} Risk
          </div>
          <div className="flex-1">
            <h3 className="text-sm font-semibold text-brand-navy mb-1">Security Consultant Assessment</h3>
            <p className="text-sm text-brand-gray-700 mb-3">{ai_summary.summary}</p>
            <h4 className="text-xs font-semibold text-brand-gray-500 uppercase tracking-wider mb-2">Recommendations</h4>
            <ul className="space-y-1.5">
              {ai_summary.recommendations.map((rec: string, idx: number) => (
                <li key={idx} className="flex items-start gap-2 text-sm text-brand-gray-700">
                  <span className="text-brand-green font-bold mt-0.5">&#8227;</span>
                  {rec}
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>

      {/* Posture Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3 mb-6">
        <div className="card text-center">
          <p className="text-xs text-brand-gray-400 uppercase font-semibold">Total Findings</p>
          <p className="text-2xl font-bold text-brand-navy">{posture.total_findings}</p>
        </div>
        <div className="card text-center">
          <p className="text-xs text-brand-gray-400 uppercase font-semibold">Pass Rate</p>
          <p className={`text-2xl font-bold ${posture.pass_rate >= 80 ? 'text-green-600' : posture.pass_rate >= 50 ? 'text-amber-500' : 'text-red-600'}`}>
            {posture.pass_rate}%
          </p>
        </div>
        <div className="card text-center">
          <p className="text-xs text-brand-gray-400 uppercase font-semibold">Passed</p>
          <p className="text-2xl font-bold text-green-600">{posture.passed}</p>
        </div>
        <div className="card text-center">
          <p className="text-xs text-brand-gray-400 uppercase font-semibold">Failed</p>
          <p className="text-2xl font-bold text-red-600">{posture.failed}</p>
        </div>
        {['critical', 'high'].map((sev) => (
          <div key={sev} className="card text-center">
            <p className="text-xs text-brand-gray-400 uppercase font-semibold">{sev}</p>
            <p className={`text-2xl font-bold ${SEVERITY_COLORS[sev]}`}>{posture.severity_breakdown?.[sev] || 0}</p>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        {/* Inventory Summary */}
        <div className="card">
          <h3 className="text-sm font-semibold text-brand-navy mb-3">Inventory Summary</h3>
          {inventory.length === 0 ? (
            <p className="text-sm text-brand-gray-400">No resources discovered yet.</p>
          ) : (
            <div className="space-y-2 max-h-64 overflow-y-auto">
              {inventory.map((item: any) => (
                <div key={item.service} className="flex items-center justify-between py-1.5 px-2 bg-brand-gray-50 rounded">
                  <span className="text-sm text-brand-gray-700 font-medium">{item.service}</span>
                  <span className="text-sm font-bold text-brand-navy">{item.resource_count}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Applicable Frameworks */}
        <div className="card">
          <h3 className="text-sm font-semibold text-brand-navy mb-3">Applicable Frameworks</h3>
          {applicable_frameworks.length === 0 ? (
            <p className="text-sm text-brand-gray-400">No frameworks map to this provider.</p>
          ) : (
            <div className="space-y-2 max-h-64 overflow-y-auto">
              {applicable_frameworks.map((fw: any) => (
                <div key={fw.id} className="flex items-center justify-between py-1.5 px-2 bg-brand-gray-50 rounded">
                  <div>
                    <span className="text-sm text-brand-gray-700 font-medium">{fw.name}</span>
                  </div>
                  <span className="text-xs text-brand-gray-400">{fw.total_checks} checks</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        {/* Top Findings */}
        <div className="card">
          <h3 className="text-sm font-semibold text-brand-navy mb-3">Top Failed Findings</h3>
          {top_findings.length === 0 ? (
            <p className="text-sm text-brand-gray-400">No failed findings.</p>
          ) : (
            <div className="space-y-2 max-h-80 overflow-y-auto">
              {top_findings.map((f: any) => (
                <div key={f.id} className={`border rounded-lg px-3 py-2 ${SEVERITY_BG[f.severity] || 'bg-gray-50 border-gray-200'}`}>
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex-1 min-w-0">
                      <p className="text-sm text-brand-gray-700 font-medium truncate">{f.check_title}</p>
                      <p className="text-xs text-brand-gray-400">{f.service} &middot; {f.resource_name || f.resource_id || '-'}</p>
                    </div>
                    <span className={`text-xs font-bold uppercase ${SEVERITY_COLORS[f.severity]}`}>{f.severity}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* MITRE ATT&CK Summary */}
        <div className="card">
          <h3 className="text-sm font-semibold text-brand-navy mb-3">MITRE ATT&CK Techniques</h3>
          {mitre_summary.length === 0 ? (
            <p className="text-sm text-brand-gray-400">No MITRE techniques triggered.</p>
          ) : (
            <div className="space-y-2 max-h-80 overflow-y-auto">
              {mitre_summary.map((t: any) => (
                <div key={t.id} className="flex items-center justify-between py-1.5 px-2 bg-brand-gray-50 rounded">
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-mono font-bold text-red-600 bg-red-50 px-1.5 py-0.5 rounded">{t.id}</span>
                    <span className="text-sm text-brand-gray-700">{t.name}</span>
                  </div>
                  <span className="text-xs font-bold text-red-600">{t.finding_count}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Scan Trends */}
      {scan_trends.length > 0 && (
        <div className="card mb-6">
          <h3 className="text-sm font-semibold text-brand-navy mb-3">Scan-to-Scan Trends (Last 30 Days)</h3>
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead>
                <tr className="bg-brand-gray-50">
                  <th className="px-3 py-2 text-left text-xs font-semibold text-brand-gray-500">Date</th>
                  <th className="px-3 py-2 text-right text-xs font-semibold text-brand-gray-500">Total</th>
                  <th className="px-3 py-2 text-right text-xs font-semibold text-green-600">Passed</th>
                  <th className="px-3 py-2 text-right text-xs font-semibold text-red-600">Failed</th>
                  <th className="px-3 py-2 text-right text-xs font-semibold text-brand-gray-500">Pass Rate</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-brand-gray-100">
                {scan_trends.map((s: any, idx: number) => {
                  const prev = idx > 0 ? scan_trends[idx - 1] : null
                  const trend = prev ? s.pass_rate - prev.pass_rate : 0
                  return (
                    <tr key={idx}>
                      <td className="px-3 py-2 text-brand-gray-700">{s.date}</td>
                      <td className="px-3 py-2 text-right font-medium">{s.total_checks}</td>
                      <td className="px-3 py-2 text-right text-green-600">{s.passed}</td>
                      <td className="px-3 py-2 text-right text-red-600">{s.failed}</td>
                      <td className="px-3 py-2 text-right">
                        <span className={s.pass_rate >= 80 ? 'text-green-600' : s.pass_rate >= 50 ? 'text-amber-500' : 'text-red-600'}>
                          {s.pass_rate}%
                        </span>
                        {trend !== 0 && (
                          <span className={`ml-1 text-xs ${trend > 0 ? 'text-green-500' : 'text-red-500'}`}>
                            {trend > 0 ? '+' : ''}{trend.toFixed(1)}%
                          </span>
                        )}
                      </td>
                    </tr>
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
