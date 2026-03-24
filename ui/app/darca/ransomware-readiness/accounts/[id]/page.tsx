'use client'

import { useEffect, useState } from 'react'
import { useParams } from 'next/navigation'
import Link from 'next/link'
import Header from '@/components/layout/Header'
import Badge from '@/components/ui/Badge'
import ScoreGauge from '@/components/ransomware-readiness/ScoreGauge'
import DomainRadarChart from '@/components/ransomware-readiness/DomainRadarChart'
import { api } from '@/lib/api'
import { ArrowLeftIcon, ArrowPathIcon } from '@heroicons/react/24/outline'

const DOMAIN_NAMES: Record<string, string> = {
  D1: 'IAM', D2: 'Data Protection', D3: 'Backup & Recovery',
  D4: 'Network', D5: 'Hardening', D6: 'Logging', D7: 'Governance',
}

export default function AccountDetailPage() {
  const params = useParams()
  const accountId = params.id as string
  const [data, setData] = useState<any>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.getRRAccountDetail(accountId)
      .then(setData)
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [accountId])

  if (loading || !data) {
    return (
      <div className="space-y-6">
        <Header title="Account Detail" subtitle="Loading..." />
        <div className="flex items-center justify-center py-20">
          <ArrowPathIcon className="w-8 h-8 animate-spin text-brand-gray-300" />
        </div>
      </div>
    )
  }

  const { account, score, level, domain_scores, findings } = data

  const radarDomains = Object.entries(domain_scores).map(([id, ds]: [string, any]) => ({
    id,
    name: DOMAIN_NAMES[id] || id,
    score: ds?.final_score ?? 0,
    weight: ds?.weight ?? 0,
  }))

  const failedFindings = findings?.filter((f: any) => f.status === 'fail') || []

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Link href="/darca/ransomware-readiness" className="p-2 rounded-lg hover:bg-brand-gray-100 transition-colors">
          <ArrowLeftIcon className="w-5 h-5 text-brand-gray-400" />
        </Link>
        <Header
          title={`${account.alias || account.account_id}`}
          subtitle={`${account.provider.toUpperCase()} Account — Ransomware Readiness Assessment`}
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Score */}
        <div className="bg-white border border-brand-gray-200 rounded-xl p-6 flex flex-col items-center">
          <ScoreGauge score={score} level={level} size="lg" />
        </div>

        {/* Radar */}
        <div className="bg-white border border-brand-gray-200 rounded-xl p-6">
          <h3 className="text-sm font-semibold text-brand-gray-400 uppercase mb-2">Domain Profile</h3>
          <DomainRadarChart domains={radarDomains} />
        </div>
      </div>

      {/* Domain breakdown */}
      <div className="bg-white border border-brand-gray-200 rounded-xl p-6">
        <h3 className="text-sm font-semibold text-brand-gray-400 uppercase mb-3">Domain Scores</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
          {radarDomains.map(d => (
            <div key={d.id} className="text-center p-3 rounded-lg bg-brand-gray-50">
              <p className="text-xs text-brand-gray-400 font-medium">{d.id}</p>
              <p className="text-2xl font-bold text-brand-navy tabular-nums">{Math.round(d.score)}</p>
              <p className="text-xs text-brand-gray-500">{d.name}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Findings */}
      <div className="bg-white border border-brand-gray-200 rounded-xl overflow-hidden">
        <div className="px-6 py-4 border-b border-brand-gray-100">
          <h3 className="text-sm font-semibold text-brand-gray-400 uppercase">
            Failed Findings ({failedFindings.length})
          </h3>
        </div>
        <div className="divide-y divide-brand-gray-100">
          {failedFindings.length === 0 ? (
            <p className="px-6 py-8 text-sm text-brand-gray-400 text-center">No failed findings for this account.</p>
          ) : (
            failedFindings.map((f: any) => (
              <Link
                key={f.id}
                href={`/darca/ransomware-readiness/findings/${f.id}`}
                className="flex items-center gap-3 px-6 py-3 hover:bg-brand-gray-50 transition-colors"
              >
                <Badge severity={f.severity} />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-brand-navy">{f.rule_id}: {f.rule_name}</p>
                  <p className="text-xs text-brand-gray-400">{f.domain} &middot; {f.failed_resources} affected</p>
                </div>
              </Link>
            ))
          )}
        </div>
      </div>
    </div>
  )
}
