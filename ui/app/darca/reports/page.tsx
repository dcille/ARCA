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
  ArrowDownTrayIcon,
  TableCellsIcon,
  CodeBracketIcon,
} from '@heroicons/react/24/outline'
import toast from 'react-hot-toast'

export default function ReportsPage() {
  const [providers, setProviders] = useState<any[]>([])
  const [loading, setLoading] = useState(false)
  const [filters, setFilters] = useState({
    provider_type: '',
    account_id: '',
    scan_id: '',
    severity: '',
    service: '',
  })

  useEffect(() => {
    api.getProviders().then(setProviders).catch(console.error)
  }, [])

  const uniqueProviderTypes = Array.from(new Set(providers.map((p: any) => p.provider_type as string)))
  const accountsForType = filters.provider_type
    ? providers.filter(p => p.provider_type === filters.provider_type)
    : providers

  const handleDownloadReport = async (type: 'executive' | 'technical') => {
    setLoading(true)
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
      setLoading(false)
    }
  }

  const handleExport = async (format: 'csv' | 'json') => {
    setLoading(true)
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
      setLoading(false)
    }
  }

  return (
    <div>
      <Header title="Reports" subtitle="Generate executive and technical security reports, export findings data" />

      {/* Filters */}
      <div className="card mb-6">
        <div className="flex items-center gap-2 mb-4">
          <FunnelIcon className="w-5 h-5 text-brand-gray-400" />
          <h3 className="text-sm font-semibold text-brand-navy">Report Filters</h3>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-4">
          <div>
            <label className="block text-xs font-medium text-brand-gray-500 mb-1">Cloud Provider</label>
            <select
              value={filters.provider_type}
              onChange={(e) => setFilters({ ...filters, provider_type: e.target.value, account_id: '' })}
              className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-brand-green outline-none"
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
              className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-brand-green outline-none"
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
            <label className="block text-xs font-medium text-brand-gray-500 mb-1">Severity</label>
            <select
              value={filters.severity}
              onChange={(e) => setFilters({ ...filters, severity: e.target.value })}
              className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-brand-green outline-none"
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
              className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-brand-green outline-none"
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
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        {/* Executive Report */}
        <div className="card hover:shadow-lg transition-shadow">
          <div className="flex items-start gap-4">
            <div className="p-3 bg-brand-green/10 rounded-xl">
              <DocumentChartBarIcon className="w-8 h-8 text-brand-green" />
            </div>
            <div className="flex-1">
              <h3 className="text-lg font-bold text-brand-navy">Executive Report</h3>
              <p className="text-sm text-brand-gray-500 mt-1 mb-4">
                High-level security posture summary with key metrics, risk overview,
                top affected services, attack path analysis, and actionable recommendations.
                Designed for leadership and stakeholders.
              </p>
              <div className="text-xs text-brand-gray-400 mb-4 space-y-1">
                <p>Includes: Key metrics, severity breakdown, service analysis, attack paths, compliance status, recommendations</p>
              </div>
              <button
                onClick={() => handleDownloadReport('executive')}
                disabled={loading}
                className={cn(
                  'flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors',
                  loading
                    ? 'bg-brand-gray-200 text-brand-gray-400 cursor-not-allowed'
                    : 'bg-brand-green text-white hover:bg-brand-green/90'
                )}
              >
                <DocumentArrowDownIcon className="w-4 h-4" />
                {loading ? 'Generating...' : 'Download Executive PDF'}
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
              <p className="text-sm text-brand-gray-500 mt-1 mb-4">
                Detailed technical assessment with every finding, remediation steps,
                attack path analysis, and compliance mapping.
                Designed for security engineers and DevOps teams.
              </p>
              <div className="text-xs text-brand-gray-400 mb-4 space-y-1">
                <p>Includes: All findings with details, remediation steps, affected resources, attack paths, compliance controls</p>
              </div>
              <button
                onClick={() => handleDownloadReport('technical')}
                disabled={loading}
                className={cn(
                  'flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors',
                  loading
                    ? 'bg-brand-gray-200 text-brand-gray-400 cursor-not-allowed'
                    : 'bg-blue-600 text-white hover:bg-blue-700'
                )}
              >
                <DocumentArrowDownIcon className="w-4 h-4" />
                {loading ? 'Generating...' : 'Download Technical PDF'}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Data Export */}
      <div className="card">
        <h3 className="text-lg font-bold text-brand-navy mb-2">Data Export</h3>
        <p className="text-sm text-brand-gray-500 mb-4">
          Export raw findings data for integration with external tools, SIEM systems, or custom analysis.
        </p>
        <div className="flex gap-4">
          <button
            onClick={() => handleExport('csv')}
            disabled={loading}
            className={cn(
              'flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium border transition-colors',
              loading
                ? 'border-brand-gray-200 text-brand-gray-400 cursor-not-allowed'
                : 'border-brand-gray-300 text-brand-navy hover:bg-brand-gray-50'
            )}
          >
            <TableCellsIcon className="w-4 h-4" />
            Export CSV
          </button>
          <button
            onClick={() => handleExport('json')}
            disabled={loading}
            className={cn(
              'flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium border transition-colors',
              loading
                ? 'border-brand-gray-200 text-brand-gray-400 cursor-not-allowed'
                : 'border-brand-gray-300 text-brand-navy hover:bg-brand-gray-50'
            )}
          >
            <CodeBracketIcon className="w-4 h-4" />
            Export JSON
          </button>
        </div>
      </div>
    </div>
  )
}
