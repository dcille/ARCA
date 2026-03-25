'use client'

import { useEffect, useState } from 'react'
import Header from '@/components/layout/Header'
import { api } from '@/lib/api'
import { cn } from '@/lib/utils'
import {
  DocumentArrowDownIcon,
  DocumentTextIcon,
  DocumentChartBarIcon,
  FunnelIcon,
  TableCellsIcon,
  CodeBracketIcon,
  ShieldExclamationIcon,
  CheckCircleIcon,
  ArrowPathIcon,
} from '@heroicons/react/24/outline'
import toast from 'react-hot-toast'

export default function ReportsPage() {
  const [providers, setProviders] = useState<any[]>([])
  const [scans, setScans] = useState<any[]>([])
  const [loading, setLoading] = useState<string | null>(null)
  const [stats, setStats] = useState<{ total: number; critical: number; high: number; passRate: number } | null>(null)
  const [filters, setFilters] = useState({
    provider_type: '',
    account_id: '',
    scan_id: '',
    severity: '',
    service: '',
  })

  useEffect(() => {
    Promise.all([
      api.getProviders().then(setProviders).catch(() => []),
      api.getScans().then(setScans).catch(() => []),
      api.getFindingsStats().then((data: any) => {
        if (data) {
          setStats({
            total: data.total || data.total_findings || 0,
            critical: data.by_severity?.critical || data.critical || 0,
            high: data.by_severity?.high || data.high || 0,
            passRate: data.pass_rate || 0,
          })
        }
      }).catch(() => null),
    ])
  }, [])

  const uniqueProviderTypes = Array.from(new Set(providers.map((p: any) => p.provider_type as string)))
  const accountsForType = filters.provider_type
    ? providers.filter(p => p.provider_type === filters.provider_type)
    : providers

  const recentScans = scans
    .filter(s => s.status === 'completed')
    .sort((a, b) => new Date(b.completed_at || b.created_at).getTime() - new Date(a.completed_at || a.created_at).getTime())
    .slice(0, 10)

  const handleDownloadReport = async (type: 'executive' | 'technical') => {
    setLoading(type)
    try {
      const params: Record<string, string> = {}
      if (filters.provider_type) params.provider_type = filters.provider_type
      if (filters.account_id) params.account_id = filters.account_id
      if (filters.scan_id) params.scan_id = filters.scan_id
      if (type === 'technical') {
        if (filters.severity) params.severity = filters.severity
        if (filters.service) params.service = filters.service
      }
      await api.downloadReport(type, params)
      toast.success(`${type === 'executive' ? 'Executive' : 'Technical'} report downloaded`)
    } catch (err: any) {
      toast.error(err.message || 'Failed to generate report')
    } finally {
      setLoading(null)
    }
  }

  const handleDownloadRRReport = async () => {
    setLoading('rr')
    try {
      await api.downloadRRReport()
      toast.success('Ransomware Readiness report downloaded')
    } catch (err: any) {
      toast.error(err.message || 'Failed to generate RR report')
    } finally {
      setLoading(null)
    }
  }

  const handleExport = async (format: 'csv' | 'json') => {
    setLoading(format)
    try {
      const params: Record<string, string> = {}
      if (filters.provider_type) params.provider_type = filters.provider_type
      if (filters.severity) params.severity = filters.severity
      if (filters.service) params.service = filters.service
      await api.exportFindings(format, params)
      toast.success(`Findings exported as ${format.toUpperCase()}`)
    } catch (err: any) {
      toast.error(err.message || 'Export failed')
    } finally {
      setLoading(null)
    }
  }

  return (
    <div>
      <Header
        title="Reports"
        subtitle="Generate executive and technical security reports, export findings data"
        breadcrumbs={[{ label: 'Operations', href: '/darca/scans' }, { label: 'Reports' }]}
      />

      {/* Quick Stats */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
          <div className="bg-white border border-brand-gray-200 rounded-lg p-4">
            <p className="text-xs text-brand-gray-400 uppercase font-semibold">Total Findings</p>
            <p className="text-2xl font-bold text-brand-navy">{stats.total}</p>
          </div>
          <div className="bg-white border border-brand-gray-200 rounded-lg p-4">
            <p className="text-xs text-brand-gray-400 uppercase font-semibold">Critical</p>
            <p className="text-2xl font-bold text-red-600">{stats.critical}</p>
          </div>
          <div className="bg-white border border-brand-gray-200 rounded-lg p-4">
            <p className="text-xs text-brand-gray-400 uppercase font-semibold">High</p>
            <p className="text-2xl font-bold text-orange-500">{stats.high}</p>
          </div>
          <div className="bg-white border border-brand-gray-200 rounded-lg p-4">
            <p className="text-xs text-brand-gray-400 uppercase font-semibold">Pass Rate</p>
            <p className={cn('text-2xl font-bold', stats.passRate >= 70 ? 'text-green-600' : 'text-amber-500')}>
              {stats.passRate}%
            </p>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="card mb-6">
        <div className="flex items-center gap-2 mb-4">
          <FunnelIcon className="w-5 h-5 text-brand-gray-400" />
          <h3 className="text-sm font-semibold text-brand-navy">Report Filters</h3>
          <span className="text-xs text-brand-gray-400 ml-2">
            Applied to Executive, Technical, and Data Export reports
          </span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-4">
          <div>
            <label className="block text-xs font-medium text-brand-gray-500 mb-1">Cloud Provider</label>
            <select
              value={filters.provider_type}
              onChange={(e) => setFilters({ ...filters, provider_type: e.target.value, account_id: '' })}
              className="w-full select-field"
            >
              <option value="">All Providers</option>
              {uniqueProviderTypes.map(pt => (
                <option key={pt} value={pt}>{pt.toUpperCase()}</option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-xs font-medium text-brand-gray-500 mb-1">Account</label>
            <select
              value={filters.account_id}
              onChange={(e) => setFilters({ ...filters, account_id: e.target.value })}
              className="w-full select-field"
            >
              <option value="">All Accounts</option>
              {accountsForType.map(p => (
                <option key={p.id} value={p.account_id || p.id}>
                  {p.alias} {p.account_id ? `(${p.account_id})` : ''}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-xs font-medium text-brand-gray-500 mb-1">Scan</label>
            <select
              value={filters.scan_id}
              onChange={(e) => setFilters({ ...filters, scan_id: e.target.value })}
              className="w-full select-field"
            >
              <option value="">Latest Scan</option>
              {recentScans.map(s => (
                <option key={s.id} value={s.id}>
                  {s.provider_alias || s.scan_type} - {new Date(s.completed_at || s.created_at).toLocaleDateString()}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-xs font-medium text-brand-gray-500 mb-1">Severity</label>
            <select
              value={filters.severity}
              onChange={(e) => setFilters({ ...filters, severity: e.target.value })}
              className="w-full select-field"
            >
              <option value="">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>

          <div>
            <label className="block text-xs font-medium text-brand-gray-500 mb-1">Service</label>
            <input
              type="text"
              placeholder="e.g., iam, s3, network"
              value={filters.service}
              onChange={(e) => setFilters({ ...filters, service: e.target.value })}
              className="w-full select-field"
            />
          </div>

          <div className="flex items-end">
            <button
              onClick={() => setFilters({ provider_type: '', account_id: '', scan_id: '', severity: '', service: '' })}
              className="px-4 py-2 text-sm text-brand-gray-500 hover:text-brand-navy border border-brand-gray-300 rounded-lg hover:bg-brand-gray-50 transition-colors"
            >
              Clear Filters
            </button>
          </div>
        </div>
      </div>

      {/* Report Cards */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
        {/* Executive Report */}
        <div className="card hover:shadow-lg transition-shadow">
          <div className="flex items-start gap-4">
            <div className="p-3 bg-brand-green/10 rounded-xl">
              <DocumentChartBarIcon className="w-8 h-8 text-brand-green" />
            </div>
            <div className="flex-1">
              <h3 className="text-lg font-bold text-brand-navy">Executive Report</h3>
              <p className="text-sm text-brand-gray-500 mt-1 mb-3">
                High-level security posture summary with key metrics, risk overview,
                charts, attack paths, and recommendations.
              </p>
              <div className="text-xs text-brand-gray-400 mb-4 space-y-0.5">
                <p><CheckCircleIcon className="w-3.5 h-3.5 inline mr-1 text-brand-green" />Severity distribution charts</p>
                <p><CheckCircleIcon className="w-3.5 h-3.5 inline mr-1 text-brand-green" />Top affected services</p>
                <p><CheckCircleIcon className="w-3.5 h-3.5 inline mr-1 text-brand-green" />Attack path analysis</p>
                <p><CheckCircleIcon className="w-3.5 h-3.5 inline mr-1 text-brand-green" />MITRE ATT&CK coverage</p>
                <p><CheckCircleIcon className="w-3.5 h-3.5 inline mr-1 text-brand-green" />Compliance status</p>
                <p><CheckCircleIcon className="w-3.5 h-3.5 inline mr-1 text-brand-green" />Actionable recommendations</p>
              </div>
              <button
                onClick={() => handleDownloadReport('executive')}
                disabled={!!loading}
                className={cn(
                  'flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium transition-colors w-full justify-center',
                  loading
                    ? 'bg-brand-gray-200 text-brand-gray-400 cursor-not-allowed'
                    : 'bg-brand-green text-white hover:bg-brand-green/90'
                )}
              >
                {loading === 'executive' ? (
                  <ArrowPathIcon className="w-4 h-4 animate-spin" />
                ) : (
                  <DocumentArrowDownIcon className="w-4 h-4" />
                )}
                {loading === 'executive' ? 'Generating...' : 'Download Executive PDF'}
              </button>
            </div>
          </div>
        </div>

        {/* Technical Report */}
        <div className="card hover:shadow-lg transition-shadow">
          <div className="flex items-start gap-4">
            <div className="p-3 bg-blue-50 rounded-xl">
              <DocumentTextIcon className="w-8 h-8 text-blue-600" />
            </div>
            <div className="flex-1">
              <h3 className="text-lg font-bold text-brand-navy">Technical Report</h3>
              <p className="text-sm text-brand-gray-500 mt-1 mb-3">
                Detailed technical assessment with every finding, remediation steps,
                and compliance mapping.
              </p>
              <div className="text-xs text-brand-gray-400 mb-4 space-y-0.5">
                <p><CheckCircleIcon className="w-3.5 h-3.5 inline mr-1 text-blue-500" />All findings with details</p>
                <p><CheckCircleIcon className="w-3.5 h-3.5 inline mr-1 text-blue-500" />Remediation steps</p>
                <p><CheckCircleIcon className="w-3.5 h-3.5 inline mr-1 text-blue-500" />Affected resources</p>
                <p><CheckCircleIcon className="w-3.5 h-3.5 inline mr-1 text-blue-500" />Attack path details</p>
                <p><CheckCircleIcon className="w-3.5 h-3.5 inline mr-1 text-blue-500" />MITRE technique mapping</p>
                <p><CheckCircleIcon className="w-3.5 h-3.5 inline mr-1 text-blue-500" />Compliance controls</p>
              </div>
              <button
                onClick={() => handleDownloadReport('technical')}
                disabled={!!loading}
                className={cn(
                  'flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium transition-colors w-full justify-center',
                  loading
                    ? 'bg-brand-gray-200 text-brand-gray-400 cursor-not-allowed'
                    : 'bg-blue-600 text-white hover:bg-blue-700'
                )}
              >
                {loading === 'technical' ? (
                  <ArrowPathIcon className="w-4 h-4 animate-spin" />
                ) : (
                  <DocumentArrowDownIcon className="w-4 h-4" />
                )}
                {loading === 'technical' ? 'Generating...' : 'Download Technical PDF'}
              </button>
            </div>
          </div>
        </div>

        {/* Ransomware Readiness Report */}
        <div className="card hover:shadow-lg transition-shadow">
          <div className="flex items-start gap-4">
            <div className="p-3 bg-red-50 rounded-xl">
              <ShieldExclamationIcon className="w-8 h-8 text-red-500" />
            </div>
            <div className="flex-1">
              <h3 className="text-lg font-bold text-brand-navy">Ransomware Readiness</h3>
              <p className="text-sm text-brand-gray-500 mt-1 mb-3">
                NIST CSF 2.0 ransomware preparedness assessment report with domain scores
                and critical findings.
              </p>
              <div className="text-xs text-brand-gray-400 mb-4 space-y-0.5">
                <p><CheckCircleIcon className="w-3.5 h-3.5 inline mr-1 text-red-400" />Global readiness score</p>
                <p><CheckCircleIcon className="w-3.5 h-3.5 inline mr-1 text-red-400" />7 domain breakdown</p>
                <p><CheckCircleIcon className="w-3.5 h-3.5 inline mr-1 text-red-400" />Critical & high findings</p>
                <p><CheckCircleIcon className="w-3.5 h-3.5 inline mr-1 text-red-400" />Top recommendations</p>
                <p><CheckCircleIcon className="w-3.5 h-3.5 inline mr-1 text-red-400" />NIST CSF 2.0 mapping</p>
              </div>
              <button
                onClick={handleDownloadRRReport}
                disabled={!!loading}
                className={cn(
                  'flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium transition-colors w-full justify-center',
                  loading
                    ? 'bg-brand-gray-200 text-brand-gray-400 cursor-not-allowed'
                    : 'bg-red-500 text-white hover:bg-red-600'
                )}
              >
                {loading === 'rr' ? (
                  <ArrowPathIcon className="w-4 h-4 animate-spin" />
                ) : (
                  <DocumentArrowDownIcon className="w-4 h-4" />
                )}
                {loading === 'rr' ? 'Generating...' : 'Download RR Report'}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Data Export */}
      <div className="card">
        <div className="flex items-start gap-4">
          <div>
            <h3 className="text-lg font-bold text-brand-navy mb-1">Data Export</h3>
            <p className="text-sm text-brand-gray-500 mb-4">
              Export raw findings data for integration with external tools, SIEM systems, or custom analysis.
              Filters above are applied to the export.
            </p>
          </div>
        </div>
        <div className="flex gap-4">
          <button
            onClick={() => handleExport('csv')}
            disabled={!!loading}
            className={cn(
              'flex items-center gap-2 px-5 py-2.5 rounded-lg text-sm font-medium border transition-colors',
              loading
                ? 'border-brand-gray-200 text-brand-gray-400 cursor-not-allowed'
                : 'border-brand-gray-300 text-brand-navy hover:bg-brand-gray-50'
            )}
          >
            {loading === 'csv' ? (
              <ArrowPathIcon className="w-4 h-4 animate-spin" />
            ) : (
              <TableCellsIcon className="w-4 h-4" />
            )}
            Export CSV
          </button>
          <button
            onClick={() => handleExport('json')}
            disabled={!!loading}
            className={cn(
              'flex items-center gap-2 px-5 py-2.5 rounded-lg text-sm font-medium border transition-colors',
              loading
                ? 'border-brand-gray-200 text-brand-gray-400 cursor-not-allowed'
                : 'border-brand-gray-300 text-brand-navy hover:bg-brand-gray-50'
            )}
          >
            {loading === 'json' ? (
              <ArrowPathIcon className="w-4 h-4 animate-spin" />
            ) : (
              <CodeBracketIcon className="w-4 h-4" />
            )}
            Export JSON
          </button>
        </div>
      </div>
    </div>
  )
}
