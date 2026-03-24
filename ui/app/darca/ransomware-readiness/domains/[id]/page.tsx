'use client'

import { useEffect, useState } from 'react'
import { useParams } from 'next/navigation'
import Link from 'next/link'
import Header from '@/components/layout/Header'
import Badge from '@/components/ui/Badge'
import ScoreGauge from '@/components/ransomware-readiness/ScoreGauge'
import { api } from '@/lib/api'
import { ArrowLeftIcon, ArrowPathIcon } from '@heroicons/react/24/outline'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts'

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#DC2626', high: '#EA580C', medium: '#D97706', low: '#6B7280',
}

const STATUS_STYLES: Record<string, string> = {
  pass: 'bg-emerald-100 text-emerald-700',
  fail: 'bg-red-100 text-red-700',
  warning: 'bg-amber-100 text-amber-700',
  not_evaluated: 'bg-gray-100 text-gray-500',
}

export default function DomainDetailPage() {
  const params = useParams()
  const domainId = params.id as string
  const [domain, setDomain] = useState<any>(null)
  const [rules, setRules] = useState<any[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    loadData()
  }, [domainId])

  async function loadData() {
    setLoading(true)
    try {
      const [domainsData, rulesData] = await Promise.all([
        api.getRRDomains(),
        api.getRRDomainRules(domainId),
      ])
      const d = domainsData.find((d: any) => d.id === domainId)
      setDomain(d)
      setRules(rulesData || [])
    } catch (e) {
      console.error(e)
    }
    setLoading(false)
  }

  if (loading || !domain) {
    return (
      <div className="space-y-6">
        <Header title="Domain Detail" subtitle="Loading..." />
        <div className="flex items-center justify-center py-20">
          <ArrowPathIcon className="w-8 h-8 animate-spin text-brand-gray-300" />
        </div>
      </div>
    )
  }

  const severityDistribution = [
    { name: 'Critical', count: rules.filter(r => r.severity === 'critical' && r.status === 'fail').length, color: SEVERITY_COLORS.critical },
    { name: 'High', count: rules.filter(r => r.severity === 'high' && r.status === 'fail').length, color: SEVERITY_COLORS.high },
    { name: 'Medium', count: rules.filter(r => r.severity === 'medium' && r.status === 'fail').length, color: SEVERITY_COLORS.medium },
    { name: 'Low', count: rules.filter(r => r.severity === 'low' && r.status === 'fail').length, color: SEVERITY_COLORS.low },
  ]

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Link href="/darca/ransomware-readiness" className="p-2 rounded-lg hover:bg-brand-gray-100 transition-colors">
          <ArrowLeftIcon className="w-5 h-5 text-brand-gray-400" />
        </Link>
        <Header
          title={`${domainId}: ${domain.name}`}
          subtitle={`${domain.description} — NIST CSF: ${domain.nist_csf} — Weight: ${Math.round(domain.weight * 100)}%`}
        />
      </div>

      {/* Score + severity chart */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="bg-white border border-brand-gray-200 rounded-xl p-6 flex flex-col items-center justify-center">
          <ScoreGauge score={domain.score} level={domain.score >= 90 ? 'Excelente' : domain.score >= 70 ? 'Bueno' : domain.score >= 50 ? 'Moderado' : domain.score >= 30 ? 'Bajo' : 'Critico'} size="md" />
          <div className="mt-4 text-center">
            <p className="text-sm text-brand-gray-500">{domain.rule_count} rules &middot; {domain.checks_passed + domain.checks_failed} evaluated</p>
          </div>
        </div>

        <div className="lg:col-span-2 bg-white border border-brand-gray-200 rounded-xl p-6">
          <h3 className="text-sm font-semibold text-brand-gray-400 uppercase mb-3">Failed Findings by Severity</h3>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={severityDistribution} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
              <XAxis type="number" tick={{ fontSize: 11 }} />
              <YAxis dataKey="name" type="category" width={70} tick={{ fontSize: 12 }} />
              <Tooltip />
              <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                {severityDistribution.map((entry, i) => (
                  <Cell key={i} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Rules table */}
      <div className="bg-white border border-brand-gray-200 rounded-xl overflow-hidden">
        <div className="px-6 py-4 border-b border-brand-gray-100">
          <h3 className="text-sm font-semibold text-brand-gray-400 uppercase">
            Rules ({rules.length})
          </h3>
        </div>
        <div className="divide-y divide-brand-gray-100">
          {rules.map(rule => (
            <div key={rule.rule_id} className="px-6 py-3 hover:bg-brand-gray-50 transition-colors">
              <div className="flex items-center gap-3">
                <span className={`inline-block px-2 py-0.5 rounded text-xs font-bold ${STATUS_STYLES[rule.status] || STATUS_STYLES.not_evaluated}`}>
                  {rule.status.toUpperCase()}
                </span>
                <Badge type="severity" value={rule.severity} />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-brand-navy">{rule.rule_id}: {rule.name}</p>
                  <p className="text-xs text-brand-gray-400 mt-0.5">
                    {rule.cloud_providers?.join(', ')?.toUpperCase()} &middot; NIST {rule.nist_subcategory}
                    {rule.is_manual && ' &middot; Manual input required'}
                    {rule.failed_resources > 0 && ` &middot; ${rule.failed_resources} resources affected`}
                  </p>
                </div>
                {rule.last_evaluated && (
                  <span className="text-xs text-brand-gray-400 whitespace-nowrap">
                    {new Date(rule.last_evaluated).toLocaleDateString()}
                  </span>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
