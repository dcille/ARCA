'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import Header from '@/components/layout/Header'
import StatCard from '@/components/ui/StatCard'
import Badge from '@/components/ui/Badge'
import { api } from '@/lib/api'
import { formatDate, formatPercent } from '@/lib/utils'
import {
  ShieldCheckIcon,
  CloudIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  GlobeAltIcon,
  MapIcon,
  ArrowTrendingUpIcon,
  ArrowRightIcon,
  ServerIcon,
} from '@heroicons/react/24/outline'

function SecurityScoreRing({ score }: { score: number }) {
  const radius = 54
  const circumference = 2 * Math.PI * radius
  const offset = circumference - (score / 100) * circumference
  const color = score >= 80 ? '#86BC25' : score >= 50 ? '#D97706' : '#DC2626'
  const label = score >= 80 ? 'Good' : score >= 50 ? 'Fair' : 'Critical'

  return (
    <div className="flex items-center gap-6">
      <div className="relative w-36 h-36">
        <svg viewBox="0 0 120 120" className="w-full h-full -rotate-90">
          <circle cx="60" cy="60" r={radius} fill="none" stroke="#f0f0f0" strokeWidth="8" />
          <circle
            cx="60" cy="60" r={radius} fill="none"
            stroke={color} strokeWidth="8" strokeLinecap="round"
            strokeDasharray={circumference} strokeDashoffset={offset}
            className="transition-all duration-1000 ease-out"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-4xl font-bold text-brand-navy tabular-nums">{Math.round(score)}</span>
          <span className="text-xs text-brand-gray-400 font-medium uppercase">{label}</span>
        </div>
      </div>
      <div className="space-y-2">
        <p className="text-sm text-brand-gray-500">
          Based on overall pass rate and finding severity distribution
        </p>
        <div className="flex gap-3 mt-1">
          {[
            { range: '80-100', label: 'Good', color: 'bg-status-pass' },
            { range: '50-79', label: 'Fair', color: 'bg-amber-500' },
            { range: '0-49', label: 'Critical', color: 'bg-status-fail' },
          ].map(({ range, label, color }) => (
            <span key={range} className="flex items-center gap-1.5 text-xs text-brand-gray-400">
              <span className={`w-2 h-2 rounded-full ${color}`} />
              {range}
            </span>
          ))}
        </div>
      </div>
    </div>
  )
}

export default function OverviewPage() {
  const [data, setData] = useState<any>(null)
  const [attackSummary, setAttackSummary] = useState<any>(null)
  const [trends, setTrends] = useState<any>(null)
  const [providers, setProviders] = useState<any[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    Promise.all([
      api.getDashboardOverview(),
      api.getAttackPathsSummary().catch(() => null),
      api.getDashboardTrends(30).catch(() => null),
      api.getProviders().catch(() => []),
    ])
      .then(([dashData, atkData, trendsData, provData]) => {
        setData(dashData)
        setAttackSummary(atkData)
        setTrends(trendsData)
        setProviders(Array.isArray(provData) ? provData : [])
      })
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [])

  if (loading) {
    return (
      <div>
        <Header title="Overview" subtitle="Security posture at a glance" />
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {[...Array(6)].map((_, i) => (
            <div key={i} className="card-static">
              <div className="h-20 skeleton-shimmer rounded" />
            </div>
          ))}
        </div>
      </div>
    )
  }

  const severities = data?.severity_breakdown || {}

  return (
    <div>
      <Header title="Overview" subtitle="Security posture at a glance" />

      {/* Stats Grid */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-8">
        {[
          { title: 'Cloud Providers', value: data?.total_cloud_providers || 0, icon: <CloudIcon className="w-6 h-6" />, bg: 'bg-brand-blue/10 text-brand-blue' },
          { title: 'SaaS Connections', value: data?.total_saas_connections || 0, icon: <GlobeAltIcon className="w-6 h-6" />, bg: 'bg-brand-teal/10 text-brand-teal' },
          { title: 'Total Scans', value: data?.total_scans || 0, icon: <ShieldCheckIcon className="w-6 h-6" /> },
          { title: 'Total Findings', value: data?.total_findings || 0, icon: <ExclamationTriangleIcon className="w-6 h-6" />, bg: 'bg-severity-medium/10 text-severity-medium' },
          { title: 'Attack Paths', value: attackSummary?.total_paths ?? 0, icon: <MapIcon className="w-6 h-6" />, color: (attackSummary?.total_paths ?? 0) > 0 ? 'text-severity-high' : 'text-status-pass', bg: (attackSummary?.total_paths ?? 0) > 0 ? 'bg-severity-high/10 text-severity-high' : 'bg-status-pass/10 text-status-pass' },
          { title: 'Pass Rate', value: formatPercent(data?.pass_rate || 0), icon: <CheckCircleIcon className="w-6 h-6" />, color: (data?.pass_rate || 0) >= 80 ? 'text-status-pass' : (data?.pass_rate || 0) >= 50 ? 'text-status-pending' : 'text-status-fail' },
        ].map((stat, i) => (
          <div key={stat.title} className={`animate-fade-in stagger-${i + 1}`} style={{ opacity: 0 }}>
            <StatCard
              title={stat.title}
              value={stat.value}
              icon={stat.icon}
              valueColor={stat.color}
              iconBg={stat.bg}
            />
          </div>
        ))}
      </div>

      {/* Security Score + Severity */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        {data && (
          <div className="card-static animate-fade-in" style={{ animationDelay: '0.15s', opacity: 0 }}>
            <h3 className="text-lg font-semibold text-brand-navy mb-4">Security Posture Score</h3>
            <SecurityScoreRing score={data.pass_rate || 0} />
          </div>
        )}

        <div className="card-static animate-fade-in" style={{ animationDelay: '0.2s', opacity: 0 }}>
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-brand-navy">Severity Breakdown</h3>
            <Link href="/darca/findings" className="text-xs text-brand-green hover:underline flex items-center gap-1">
              View all <ArrowRightIcon className="w-3 h-3" />
            </Link>
          </div>
          <div className="space-y-3">
            {['critical', 'high', 'medium', 'low', 'informational'].map((sev) => {
              const count = severities[sev] || 0
              const total = data?.total_findings || 1
              const pct = (count / total) * 100

              return (
                <div key={sev} className="flex items-center gap-3">
                  <Badge type="severity" value={sev} className="w-28 justify-center" />
                  <div className="flex-1">
                    <div className="w-full bg-brand-gray-100 rounded-full h-2">
                      <div
                        className={`h-2 rounded-full transition-all duration-700 ease-out ${
                          sev === 'critical' ? 'bg-severity-critical' :
                          sev === 'high' ? 'bg-severity-high' :
                          sev === 'medium' ? 'bg-severity-medium' :
                          sev === 'low' ? 'bg-severity-low' :
                          'bg-severity-informational'
                        }`}
                        style={{ width: `${Math.max(pct, 1)}%` }}
                      />
                    </div>
                  </div>
                  <span className="text-sm font-semibold text-brand-gray-600 w-12 text-right tabular-nums">
                    {count}
                  </span>
                </div>
              )
            })}
          </div>
        </div>
      </div>

      {/* Services + Attack Paths */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        <div className="card-static animate-fade-in" style={{ animationDelay: '0.25s', opacity: 0 }}>
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-brand-navy">Top Services by Findings</h3>
            <Link href="/darca/inventory" className="text-xs text-brand-green hover:underline flex items-center gap-1">
              Inventory <ArrowRightIcon className="w-3 h-3" />
            </Link>
          </div>
          {data?.findings_by_service && Object.keys(data.findings_by_service).length > 0 ? (
            <div className="space-y-1">
              {Object.entries(data.findings_by_service)
                .sort(([, a]: any, [, b]: any) => b - a)
                .slice(0, 8)
                .map(([service, count]: any, i: number) => {
                  const maxCount = Math.max(...Object.values(data.findings_by_service as Record<string, number>))
                  const pct = (count / maxCount) * 100
                  return (
                    <div key={service} className="flex items-center gap-3 py-1.5">
                      <span className="text-sm text-brand-gray-600 w-32 truncate" title={service}>{service}</span>
                      <div className="flex-1">
                        <div className="w-full bg-brand-gray-100 rounded-full h-1.5">
                          <div
                            className="h-1.5 rounded-full bg-brand-navy/60 transition-all duration-500"
                            style={{ width: `${pct}%` }}
                          />
                        </div>
                      </div>
                      <span className="text-sm font-semibold text-brand-navy w-10 text-right tabular-nums">{count}</span>
                    </div>
                  )
                })}
            </div>
          ) : (
            <p className="text-brand-gray-400 text-sm">No findings yet. Run a scan to get started.</p>
          )}
        </div>

        {attackSummary && (attackSummary.total_paths > 0) && (
          <div className="card-static animate-fade-in" style={{ animationDelay: '0.3s', opacity: 0 }}>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-brand-navy">Attack Paths by Severity</h3>
              <Link href="/darca/attack-paths" className="text-xs text-brand-green hover:underline flex items-center gap-1">
                View all <ArrowRightIcon className="w-3 h-3" />
              </Link>
            </div>
            <div className="grid grid-cols-2 gap-4">
              {[
                { key: 'critical', field: 'critical_paths' },
                { key: 'high', field: 'high_paths' },
                { key: 'medium', field: 'medium_paths' },
                { key: 'low', field: 'low_paths' },
              ].map(({ key, field }) => {
                const count = attackSummary[field] || 0
                return (
                  <div key={key} className="text-center p-4 rounded-xl bg-brand-gray-50 border border-brand-gray-100">
                    <p className={`text-3xl font-bold tabular-nums ${
                      key === 'critical' ? 'text-severity-critical' :
                      key === 'high' ? 'text-severity-high' :
                      key === 'medium' ? 'text-severity-medium' : 'text-severity-low'
                    }`}>{count}</p>
                    <p className="text-xs text-brand-gray-400 uppercase font-semibold mt-1">{key}</p>
                  </div>
                )
              })}
            </div>
          </div>
        )}
      </div>

      {/* Pass Rate Trend */}
      {trends?.scan_history && trends.scan_history.length > 1 && (
        <div className="card-static mb-8 animate-fade-in" style={{ animationDelay: '0.35s', opacity: 0 }}>
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <ArrowTrendingUpIcon className="w-5 h-5 text-brand-gray-400" />
              <h3 className="text-lg font-semibold text-brand-navy">Pass Rate Trend</h3>
            </div>
            <span className="text-xs text-brand-gray-400">{trends.scan_history.length} scans over last 30 days</span>
          </div>
          <div className="flex items-end gap-[3px] h-40">
            {trends.scan_history.map((s: any, i: number) => {
              const rate = s.pass_rate || 0
              const barColor = rate >= 80 ? 'bg-status-pass' : rate >= 50 ? 'bg-amber-400' : 'bg-status-fail'
              return (
                <div key={i} className="flex-1 flex flex-col items-center gap-1 group relative" title={`${s.date}: ${rate}% (${s.passed}/${s.total_checks})`}>
                  <span className="text-[9px] text-brand-gray-400 opacity-0 group-hover:opacity-100 transition-opacity font-medium">
                    {rate}%
                  </span>
                  <div className="w-full flex flex-col justify-end" style={{ height: '120px' }}>
                    <div
                      className={`w-full rounded-t-sm ${barColor} transition-all duration-300 hover:opacity-80 group-hover:ring-1 group-hover:ring-brand-navy/20`}
                      style={{ height: `${Math.max(rate * 1.2, 3)}px` }}
                    />
                  </div>
                  <span className="text-[8px] text-brand-gray-400 truncate w-full text-center">
                    {s.date?.slice(5)}
                  </span>
                </div>
              )
            })}
          </div>
          <div className="flex items-center justify-end mt-3 gap-4 text-xs text-brand-gray-400">
            <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-status-pass" /> &ge;80%</span>
            <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-amber-400" /> 50-79%</span>
            <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-status-fail" /> &lt;50%</span>
          </div>
        </div>
      )}

      {/* Findings Severity Trend */}
      {trends?.findings_trend && trends.findings_trend.length > 1 && (
        <div className="card-static mb-8 animate-fade-in" style={{ animationDelay: '0.4s', opacity: 0 }}>
          <h3 className="text-lg font-semibold text-brand-navy mb-4">Findings Severity Trend</h3>
          <div className="flex items-end gap-[3px] h-40">
            {trends.findings_trend.map((d: any, i: number) => {
              const total = (d.critical || 0) + (d.high || 0) + (d.medium || 0) + (d.low || 0)
              const maxTotal = Math.max(...trends.findings_trend.map((t: any) =>
                (t.critical || 0) + (t.high || 0) + (t.medium || 0) + (t.low || 0)
              ), 1)
              const scale = 120 / maxTotal

              return (
                <div key={i} className="flex-1 flex flex-col items-center gap-1 group" title={`${d.date}: ${total} findings`}>
                  <span className="text-[9px] text-brand-gray-400 opacity-0 group-hover:opacity-100 transition-opacity font-medium">
                    {total}
                  </span>
                  <div className="w-full flex flex-col justify-end" style={{ height: '120px' }}>
                    {d.critical > 0 && <div className="w-full bg-severity-critical rounded-t-sm" style={{ height: `${d.critical * scale}px` }} />}
                    {d.high > 0 && <div className="w-full bg-severity-high" style={{ height: `${d.high * scale}px` }} />}
                    {d.medium > 0 && <div className="w-full bg-severity-medium" style={{ height: `${d.medium * scale}px` }} />}
                    {d.low > 0 && <div className="w-full bg-severity-low" style={{ height: `${d.low * scale}px` }} />}
                  </div>
                  <span className="text-[8px] text-brand-gray-400 truncate w-full text-center">
                    {d.date?.slice(5)}
                  </span>
                </div>
              )
            })}
          </div>
          <div className="flex items-center justify-end mt-3 gap-4 text-xs text-brand-gray-400">
            <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-severity-critical" /> Critical</span>
            <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-severity-high" /> High</span>
            <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-severity-medium" /> Medium</span>
            <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-severity-low" /> Low</span>
          </div>
        </div>
      )}

      {/* Cloud Accounts */}
      {providers.length > 0 && (
        <div className="card-static mb-8 animate-fade-in" style={{ animationDelay: '0.42s', opacity: 0 }}>
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-brand-navy">Cloud Accounts</h3>
            <Link href="/darca/providers" className="text-xs text-brand-green hover:underline flex items-center gap-1">
              Manage <ArrowRightIcon className="w-3 h-3" />
            </Link>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {providers.map((p: any) => {
              const providerIcons: Record<string, string> = {
                aws: '/icons/aws.svg',
                azure: '/icons/azure.svg',
                gcp: '/icons/gcp.svg',
                oci: '/icons/oci.svg',
                alibaba: '/icons/alibaba.svg',
                kubernetes: '/icons/k8s.svg',
              }
              const providerColors: Record<string, string> = {
                aws: 'border-l-orange-400',
                azure: 'border-l-blue-500',
                gcp: 'border-l-red-400',
                oci: 'border-l-red-600',
                alibaba: 'border-l-orange-500',
                kubernetes: 'border-l-blue-600',
              }
              return (
                <Link
                  key={p.id}
                  href={`/darca/providers/${p.id}/dashboard`}
                  className={`flex items-center gap-3 p-3 rounded-lg bg-brand-gray-50 border border-brand-gray-100 border-l-4 ${providerColors[p.provider_type] || 'border-l-brand-gray-300'} hover:shadow-md hover:bg-white transition-all group`}
                >
                  <div className="w-8 h-8 flex items-center justify-center rounded-lg bg-white shadow-sm">
                    <span className="text-xs font-bold text-brand-navy uppercase">{p.provider_type.slice(0, 3)}</span>
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-semibold text-brand-navy truncate">{p.alias}</p>
                    <p className="text-xs text-brand-gray-400">{p.provider_type.toUpperCase()}{p.account_id ? ` · ${p.account_id}` : ''}</p>
                  </div>
                  <ArrowRightIcon className="w-4 h-4 text-brand-gray-300 group-hover:text-brand-green transition-colors" />
                </Link>
              )
            })}
          </div>
        </div>
      )}

      {/* Recent Scans */}
      <div className="card-static animate-fade-in" style={{ animationDelay: '0.45s', opacity: 0 }}>
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-brand-navy">Recent Scans</h3>
          <Link href="/darca/scans" className="text-xs text-brand-green hover:underline flex items-center gap-1">
            All scans <ArrowRightIcon className="w-3 h-3" />
          </Link>
        </div>
        {data?.recent_scans?.length > 0 ? (
          <div className="overflow-x-auto -mx-6">
            <table className="min-w-full divide-y divide-brand-gray-200">
              <thead>
                <tr className="bg-brand-gray-50/80">
                  <th className="px-6 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase tracking-wider">Type</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase tracking-wider">Status</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase tracking-wider">Progress</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase tracking-wider">Checks</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase tracking-wider">Pass/Fail</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase tracking-wider">Date</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-brand-gray-100">
                {data.recent_scans.map((scan: any) => (
                  <tr key={scan.id} className="hover:bg-brand-gray-50 transition-colors">
                    <td className="px-6 py-3 text-sm">
                      <Badge type="status" value={scan.scan_type} />
                    </td>
                    <td className="px-6 py-3 text-sm">
                      <Badge type="status" value={scan.status} />
                    </td>
                    <td className="px-6 py-3 text-sm">
                      <div className="flex items-center gap-2">
                        <div className="w-16 bg-brand-gray-100 rounded-full h-1.5">
                          <div
                            className="h-1.5 rounded-full bg-brand-green transition-all"
                            style={{ width: `${scan.progress}%` }}
                          />
                        </div>
                        <span className="text-brand-gray-500 tabular-nums text-xs">{scan.progress}%</span>
                      </div>
                    </td>
                    <td className="px-6 py-3 text-sm text-brand-gray-600 tabular-nums">
                      {scan.total_checks}
                    </td>
                    <td className="px-6 py-3 text-sm tabular-nums">
                      <span className="text-status-pass font-medium">{scan.passed_checks}</span>
                      <span className="text-brand-gray-300 mx-1">/</span>
                      <span className="text-status-fail font-medium">{scan.failed_checks}</span>
                    </td>
                    <td className="px-6 py-3 text-sm text-brand-gray-400">
                      {formatDate(scan.created_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="py-8 text-center">
            <ShieldCheckIcon className="w-12 h-12 text-brand-gray-200 mx-auto mb-3" />
            <p className="text-brand-gray-400 text-sm">No scans yet. Configure a provider and start scanning.</p>
            <Link href="/darca/providers" className="inline-flex items-center gap-1 mt-2 text-sm text-brand-green hover:underline">
              Add a provider <ArrowRightIcon className="w-3 h-3" />
            </Link>
          </div>
        )}
      </div>
    </div>
  )
}
