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
} from '@heroicons/react/24/outline'

export default function OverviewPage() {
  const [data, setData] = useState<any>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.getDashboardOverview()
      .then(setData)
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
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-6 mb-8">
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
