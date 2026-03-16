'use client'

import { useEffect, useState } from 'react'
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
} from '@heroicons/react/24/outline'

export default function OverviewPage() {
  const [data, setData] = useState<any>(null)
  const [attackSummary, setAttackSummary] = useState<any>(null)
  const [trends, setTrends] = useState<any>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    Promise.all([
      api.getDashboardOverview(),
      api.getAttackPathsSummary().catch(() => null),
      api.getDashboardTrends(30).catch(() => null),
    ])
      .then(([dashData, atkData, trendsData]) => {
        setData(dashData)
        setAttackSummary(atkData)
        setTrends(trendsData)
      })
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [])

  if (loading) {
    return (
      <div>
        <Header title="Overview" subtitle="Security posture at a glance" />
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="card animate-pulse">
              <div className="h-20 bg-brand-gray-100 rounded" />
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
      <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-6 mb-8">
        <StatCard
          title="Cloud Providers"
          value={data?.total_cloud_providers || 0}
          icon={<CloudIcon className="w-6 h-6" />}
        />
        <StatCard
          title="SaaS Connections"
          value={data?.total_saas_connections || 0}
          icon={<GlobeAltIcon className="w-6 h-6" />}
        />
        <StatCard
          title="Total Scans"
          value={data?.total_scans || 0}
          icon={<ShieldCheckIcon className="w-6 h-6" />}
        />
        <StatCard
          title="Total Findings"
          value={data?.total_findings || 0}
          icon={<ExclamationTriangleIcon className="w-6 h-6" />}
        />
        <StatCard
          title="Attack Paths"
          value={attackSummary?.total_paths ?? 0}
          icon={<MapIcon className="w-6 h-6" />}
          valueColor={
            (attackSummary?.total_paths ?? 0) > 0
              ? 'text-severity-high'
              : 'text-status-pass'
          }
        />
        <StatCard
          title="Pass Rate"
          value={formatPercent(data?.pass_rate || 0)}
          icon={<CheckCircleIcon className="w-6 h-6" />}
          valueColor={
            (data?.pass_rate || 0) >= 80
              ? 'text-status-pass'
              : (data?.pass_rate || 0) >= 50
              ? 'text-status-pending'
              : 'text-status-fail'
          }
        />
      </div>

      {/* Security Posture Score */}
      {data && (
        <div className="card mb-8">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-lg font-semibold text-brand-navy">Security Posture Score</h3>
              <p className="text-sm text-brand-gray-400 mt-1">Based on overall pass rate and finding severity distribution</p>
            </div>
            <div className="flex items-center gap-4">
              <div className={`text-5xl font-bold ${
                (data.pass_rate || 0) >= 80 ? 'text-status-pass' :
                (data.pass_rate || 0) >= 50 ? 'text-amber-500' : 'text-status-fail'
              }`}>
                {Math.round(data.pass_rate || 0)}
              </div>
              <div className="text-sm text-brand-gray-400">/ 100</div>
            </div>
          </div>
          <div className="mt-4 w-full bg-brand-gray-100 rounded-full h-3">
            <div
              className={`h-3 rounded-full transition-all ${
                (data.pass_rate || 0) >= 80 ? 'bg-status-pass' :
                (data.pass_rate || 0) >= 50 ? 'bg-amber-500' : 'bg-status-fail'
              }`}
              style={{ width: `${Math.max(data.pass_rate || 0, 2)}%` }}
            />
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        {/* Severity Breakdown */}
        <div className="card">
          <h3 className="text-lg font-semibold text-brand-navy mb-4">Severity Breakdown</h3>
          <div className="space-y-3">
            {['critical', 'high', 'medium', 'low', 'informational'].map((sev) => {
              const count = severities[sev] || 0
              const total = data?.total_findings || 1
              const pct = (count / total) * 100

              return (
                <div key={sev} className="flex items-center gap-3">
                  <Badge type="severity" value={sev} className="w-28 justify-center" />
                  <div className="flex-1">
                    <div className="w-full bg-brand-gray-100 rounded-full h-2.5">
                      <div
                        className={`h-2.5 rounded-full ${
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
                  <span className="text-sm font-medium text-brand-gray-600 w-12 text-right">
                    {count}
                  </span>
                </div>
              )
            })}
          </div>
        </div>

        {/* Findings by Service */}
        <div className="card">
          <h3 className="text-lg font-semibold text-brand-navy mb-4">Top Services by Findings</h3>
          {data?.findings_by_service && Object.keys(data.findings_by_service).length > 0 ? (
            <div className="space-y-2">
              {Object.entries(data.findings_by_service)
                .sort(([, a]: any, [, b]: any) => b - a)
                .slice(0, 10)
                .map(([service, count]: any) => (
                  <div key={service} className="flex items-center justify-between py-2 border-b border-brand-gray-100 last:border-0">
                    <span className="text-sm text-brand-gray-600">{service}</span>
                    <span className="text-sm font-semibold text-brand-navy">{count}</span>
                  </div>
                ))}
            </div>
          ) : (
            <p className="text-brand-gray-400 text-sm">No findings yet. Run a scan to get started.</p>
          )}
        </div>
      </div>

      {/* Attack Paths Summary */}
      {attackSummary && (attackSummary.total_paths > 0) && (
        <div className="card mb-8">
          <h3 className="text-lg font-semibold text-brand-navy mb-4">Attack Paths by Severity</h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {['critical', 'high', 'medium', 'low'].map((sev) => {
              const count = attackSummary.by_severity?.[sev] || 0
              return (
                <div key={sev} className="text-center p-4 rounded-lg bg-brand-gray-50">
                  <p className={`text-3xl font-bold ${
                    sev === 'critical' ? 'text-severity-critical' :
                    sev === 'high' ? 'text-severity-high' :
                    sev === 'medium' ? 'text-severity-medium' : 'text-severity-low'
                  }`}>{count}</p>
                  <p className="text-xs text-brand-gray-400 uppercase font-semibold mt-1">{sev}</p>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Scan Trend Chart */}
      {trends?.scan_history && trends.scan_history.length > 1 && (
        <div className="card mb-8">
          <h3 className="text-lg font-semibold text-brand-navy mb-4">Pass Rate Trend</h3>
          <div className="flex items-end gap-1 h-40">
            {trends.scan_history.map((s: any, i: number) => {
              const rate = s.pass_rate || 0
              const barColor = rate >= 80 ? 'bg-status-pass' : rate >= 50 ? 'bg-amber-400' : 'bg-status-fail'
              return (
                <div key={i} className="flex-1 flex flex-col items-center gap-1 group" title={`${s.date}: ${rate}% (${s.passed}/${s.total_checks})`}>
                  <span className="text-[9px] text-brand-gray-400 opacity-0 group-hover:opacity-100 transition-opacity">
                    {rate}%
                  </span>
                  <div className="w-full flex flex-col justify-end" style={{ height: '120px' }}>
                    <div
                      className={`w-full rounded-t ${barColor} transition-all hover:opacity-80`}
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
          <div className="flex items-center justify-between mt-2 text-xs text-brand-gray-400">
            <span>{trends.scan_history.length} scans over last 30 days</span>
            <div className="flex items-center gap-3">
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-status-pass" /> &ge;80%</span>
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-amber-400" /> 50-79%</span>
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-status-fail" /> &lt;50%</span>
            </div>
          </div>
        </div>
      )}

      {/* Findings Severity Trend */}
      {trends?.findings_trend && trends.findings_trend.length > 1 && (
        <div className="card mb-8">
          <h3 className="text-lg font-semibold text-brand-navy mb-4">Findings Severity Trend</h3>
          <div className="flex items-end gap-1 h-40">
            {trends.findings_trend.map((d: any, i: number) => {
              const total = (d.critical || 0) + (d.high || 0) + (d.medium || 0) + (d.low || 0)
              const maxTotal = Math.max(...trends.findings_trend.map((t: any) =>
                (t.critical || 0) + (t.high || 0) + (t.medium || 0) + (t.low || 0)
              ), 1)
              const scale = 120 / maxTotal

              return (
                <div key={i} className="flex-1 flex flex-col items-center gap-1 group" title={`${d.date}: ${total} findings`}>
                  <span className="text-[9px] text-brand-gray-400 opacity-0 group-hover:opacity-100 transition-opacity">
                    {total}
                  </span>
                  <div className="w-full flex flex-col justify-end" style={{ height: '120px' }}>
                    {d.critical > 0 && <div className="w-full bg-severity-critical" style={{ height: `${d.critical * scale}px` }} />}
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
          <div className="flex items-center justify-end mt-2 gap-3 text-xs text-brand-gray-400">
            <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-severity-critical" /> Critical</span>
            <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-severity-high" /> High</span>
            <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-severity-medium" /> Medium</span>
            <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-severity-low" /> Low</span>
          </div>
        </div>
      )}

      {/* Recent Scans */}
      <div className="card">
        <h3 className="text-lg font-semibold text-brand-navy mb-4">Recent Scans</h3>
        {data?.recent_scans?.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-brand-gray-200">
              <thead>
                <tr className="bg-brand-gray-50">
                  <th className="px-4 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase">Type</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase">Status</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase">Progress</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase">Checks</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase">Pass/Fail</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase">Date</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-brand-gray-100">
                {data.recent_scans.map((scan: any) => (
                  <tr key={scan.id} className="hover:bg-brand-gray-50">
                    <td className="px-4 py-3 text-sm">
                      <Badge type="status" value={scan.scan_type} />
                    </td>
                    <td className="px-4 py-3 text-sm">
                      <Badge type="status" value={scan.status} />
                    </td>
                    <td className="px-4 py-3 text-sm text-brand-gray-600">
                      {scan.progress}%
                    </td>
                    <td className="px-4 py-3 text-sm text-brand-gray-600">
                      {scan.total_checks}
                    </td>
                    <td className="px-4 py-3 text-sm">
                      <span className="text-status-pass">{scan.passed_checks}</span>
                      {' / '}
                      <span className="text-status-fail">{scan.failed_checks}</span>
                    </td>
                    <td className="px-4 py-3 text-sm text-brand-gray-400">
                      {formatDate(scan.created_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-brand-gray-400 text-sm">No scans yet. Configure a provider and start scanning.</p>
        )}
      </div>
    </div>
  )
}
