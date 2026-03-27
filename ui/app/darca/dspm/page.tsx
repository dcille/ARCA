'use client'

import React, { useEffect, useState } from 'react'
import Header from '@/components/layout/Header'
import { api } from '@/lib/api'

const RISK_COLORS: Record<string, string> = {
  critical: 'bg-red-100 text-red-800 border-red-200',
  high: 'bg-orange-100 text-orange-800 border-orange-200',
  medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
  low: 'bg-blue-100 text-blue-800 border-blue-200',
  none: 'bg-green-100 text-green-800 border-green-200',
  unknown: 'bg-gray-100 text-gray-500 border-gray-200',
}

const CATEGORY_LABELS: Record<string, { label: string; color: string }> = {
  encryption: { label: 'Encryption', color: 'bg-purple-100 text-purple-700' },
  access: { label: 'Access Control', color: 'bg-red-100 text-red-700' },
  classification: { label: 'Classification', color: 'bg-blue-100 text-blue-700' },
  retention: { label: 'Retention', color: 'bg-teal-100 text-teal-700' },
  backup: { label: 'Backup', color: 'bg-amber-100 text-amber-700' },
  logging: { label: 'Logging', color: 'bg-gray-100 text-gray-700' },
}

const STORE_TYPE_ICONS: Record<string, string> = {
  object_storage: 'OBJ',
  relational_db: 'SQL',
  nosql_db: 'NoSQL',
  data_warehouse: 'DW',
  file_storage: 'FS',
  cache: 'CACHE',
  secrets: 'KEY',
  search_engine: 'SRCH',
}

const PROVIDER_COLORS: Record<string, string> = {
  aws: 'bg-[#FF9900]/10 text-[#FF9900] border-[#FF9900]/30',
  azure: 'bg-[#0078D4]/10 text-[#0078D4] border-[#0078D4]/30',
  gcp: 'bg-[#4285F4]/10 text-[#4285F4] border-[#4285F4]/30',
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-100 text-red-700 border-red-200',
  high: 'bg-orange-100 text-orange-700 border-orange-200',
  medium: 'bg-yellow-100 text-yellow-700 border-yellow-200',
  low: 'bg-blue-100 text-blue-700 border-blue-200',
}

const GDPR_CATEGORY_LABELS: Record<string, { label: string; color: string }> = {
  identification: { label: 'Identification', color: 'bg-purple-100 text-purple-700' },
  financial: { label: 'Financial', color: 'bg-red-100 text-red-700' },
  contact: { label: 'Contact', color: 'bg-blue-100 text-blue-700' },
  online_identifier: { label: 'Online Identifier', color: 'bg-teal-100 text-teal-700' },
  health: { label: 'Health', color: 'bg-pink-100 text-pink-700' },
}

const CLASSIFICATION_LEVEL_COLORS: Record<string, { bg: string; text: string; border: string; dot: string }> = {
  public: { bg: 'bg-green-50', text: 'text-green-700', border: 'border-green-200', dot: 'bg-green-500' },
  internal: { bg: 'bg-blue-50', text: 'text-blue-700', border: 'border-blue-200', dot: 'bg-blue-500' },
  confidential: { bg: 'bg-orange-50', text: 'text-orange-700', border: 'border-orange-200', dot: 'bg-orange-500' },
  restricted: { bg: 'bg-red-50', text: 'text-red-700', border: 'border-red-200', dot: 'bg-red-500' },
}

const MODULE_LABELS: Record<string, { label: string; color: string }> = {
  pii_scanner: { label: 'PII Scanner', color: 'bg-purple-100 text-purple-700' },
  permission_analyzer: { label: 'Permission Analyzer', color: 'bg-red-100 text-red-700' },
  shadow_detector: { label: 'Shadow Detector', color: 'bg-orange-100 text-orange-700' },
  data_classifier: { label: 'Data Classifier', color: 'bg-blue-100 text-blue-700' },
  content_sampler: { label: 'Content Sampler', color: 'bg-teal-100 text-teal-700' },
  native_integrations: { label: 'Native Integrations', color: 'bg-amber-100 text-amber-700' },
  data_store_checks: { label: 'Data Store Checks', color: 'bg-gray-100 text-gray-700' },
}

type TabId = 'inventory' | 'findings' | 'checks' | 'pii' | 'classification' | 'modules' | 'dspm-scans' | 'dspm-findings'

export default function DSPMPage() {
  const [overview, setOverview] = useState<any>(null)
  const [piiPatterns, setPiiPatterns] = useState<any>(null)
  const [classificationLevels, setClassificationLevels] = useState<any>(null)
  const [scanCapabilities, setScanCapabilities] = useState<any>(null)
  const [findingsData, setFindingsData] = useState<any>(null)
  const [findingsLoading, setFindingsLoading] = useState(false)
  const [findingsCategoryFilter, setFindingsCategoryFilter] = useState('')
  const [findingsStatusFilter, setFindingsStatusFilter] = useState('')
  const [loading, setLoading] = useState(true)
  const [activeTab, setActiveTab] = useState<TabId>('inventory')
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null)

  // DSPM Scan state
  const [scanning, setScanning] = useState(false)
  const [scanProgress, setScanProgress] = useState<any>(null)
  const [dspmScans, setDspmScans] = useState<any[]>([])
  const [dspmFindings, setDspmFindings] = useState<any>(null)
  const [dspmFindingsLoading, setDspmFindingsLoading] = useState(false)
  const [dspmModuleFilter, setDspmModuleFilter] = useState('')
  const [dspmSeverityFilter, setDspmSeverityFilter] = useState('')
  const [selectedScanDetail, setSelectedScanDetail] = useState<any>(null)
  const [enableContentScanning, setEnableContentScanning] = useState(false)

  useEffect(() => {
    Promise.all([
      api.getDSPMOverview().catch(() => null),
      api.getDSPMPIIPatterns().catch(() => null),
      api.getDSPMClassificationLevels().catch(() => null),
      api.getDSPMScanCapabilities().catch(() => null),
      api.getDSPMFindings().catch(() => null),
    ])
      .then(([overviewData, piiData, classData, capData, findData]) => {
        setOverview(overviewData)
        setPiiPatterns(piiData)
        setClassificationLevels(classData)
        setScanCapabilities(capData)
        setFindingsData(findData)
      })
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [])

  const loadFindings = async () => {
    setFindingsLoading(true)
    try {
      const params: Record<string, string> = {}
      if (findingsCategoryFilter) params.category = findingsCategoryFilter
      const data = await api.getDSPMFindings(params)
      setFindingsData(data)
    } catch (e) {
      console.error(e)
    }
    setFindingsLoading(false)
  }

  useEffect(() => {
    if (activeTab === 'findings' && (findingsCategoryFilter)) {
      loadFindings()
    }
  }, [findingsCategoryFilter])

  // Load DSPM scans when tab is active
  useEffect(() => {
    if (activeTab === 'dspm-scans') {
      loadDSPMScans()
    }
  }, [activeTab])

  // Load DSPM findings when tab is active
  useEffect(() => {
    if (activeTab === 'dspm-findings') {
      loadDSPMFindings()
    }
  }, [activeTab, dspmModuleFilter, dspmSeverityFilter])

  const loadDSPMScans = async () => {
    try {
      const data = await api.getDSPMScans(20)
      setDspmScans(data || [])
    } catch (e) {
      console.error(e)
    }
  }

  const loadDSPMFindings = async () => {
    setDspmFindingsLoading(true)
    try {
      const params: Record<string, string> = {}
      if (dspmModuleFilter) params.module = dspmModuleFilter
      if (dspmSeverityFilter) params.severity = dspmSeverityFilter
      const data = await api.getDSPMScanFindings(params)
      setDspmFindings(data)
    } catch (e) {
      console.error(e)
    }
    setDspmFindingsLoading(false)
  }

  const triggerDSPMScan = async () => {
    setScanning(true)
    setScanProgress(null)
    try {
      const result = await api.triggerDSPMScan({
        enable_content_scanning: enableContentScanning,
      })
      const scanId = result.scan_id || result.scans?.[0]?.scan_id
      if (scanId) {
        // Poll for status
        const pollInterval = setInterval(async () => {
          try {
            const status = await api.getDSPMScanStatus(scanId)
            setScanProgress(status)
            if (status.status === 'completed' || status.status === 'failed') {
              clearInterval(pollInterval)
              setScanning(false)
              loadDSPMScans()
              loadDSPMFindings()
              // Reload overview
              api.getDSPMOverview().then(d => setOverview(d)).catch(() => {})
            }
          } catch {
            clearInterval(pollInterval)
            setScanning(false)
          }
        }, 3000)
      } else {
        setScanning(false)
      }
    } catch (e) {
      console.error(e)
      setScanning(false)
    }
  }

  const viewScanDetail = async (scanId: string) => {
    try {
      const detail = await api.getDSPMScanDetail(scanId)
      setSelectedScanDetail(detail)
    } catch (e) {
      console.error(e)
    }
  }

  const updateFindingStatus = async (findingId: string, newStatus: string) => {
    try {
      await api.updateDSPMFindingStatus(findingId, newStatus)
      loadDSPMFindings()
    } catch (e) {
      console.error(e)
    }
  }

  if (loading) {
    return (
      <div>
        <Header title="Data Security (DSPM)" subtitle="Data Security Posture Management" breadcrumbs={[{ label: 'Assets', href: '/darca/inventory' }, { label: 'Data Security' }]} />
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
          {[...Array(6)].map((_, i) => (
            <div key={i} className="card animate-pulse"><div className="h-20 bg-brand-gray-100 rounded" /></div>
          ))}
        </div>
      </div>
    )
  }

  const summary = overview?.summary || {}
  const inventory = overview?.data_inventory || []
  const checks = overview?.check_catalog || []
  const totalPiiPatterns = piiPatterns?.total_patterns || 0
  const totalModules = scanCapabilities?.total_modules || 7

  return (
    <div>
      <Header title="Data Security (DSPM)" subtitle="Data Security Posture Management — data store inventory, classification, and risk" breadcrumbs={[{ label: 'Assets', href: '/darca/inventory' }, { label: 'Data Security' }]} />

      {/* Run DSPM Scan Controls */}
      <div className="flex items-center gap-4 mb-6">
        <button
          onClick={triggerDSPMScan}
          disabled={scanning}
          className={`px-4 py-2 rounded-lg text-sm font-semibold text-white transition-colors ${
            scanning
              ? 'bg-brand-gray-300 cursor-not-allowed'
              : 'bg-brand-green hover:bg-brand-green/90'
          }`}
        >
          {scanning ? 'Scanning...' : 'Run DSPM Scan'}
        </button>
        <label className="flex items-center gap-2 text-xs text-brand-gray-600">
          <input
            type="checkbox"
            checked={enableContentScanning}
            onChange={(e) => setEnableContentScanning(e.target.checked)}
            className="rounded border-brand-gray-300"
          />
          Enable content scanning (PII detection)
        </label>
        {scanProgress && (
          <div className="flex items-center gap-2 text-xs">
            <span className={`font-bold px-2 py-0.5 rounded ${
              scanProgress.status === 'completed' ? 'bg-green-100 text-green-700' :
              scanProgress.status === 'failed' ? 'bg-red-100 text-red-700' :
              'bg-blue-100 text-blue-700'
            }`}>
              {scanProgress.status.toUpperCase()}
            </span>
            {scanProgress.status === 'completed' && (
              <span className="text-brand-gray-500">
                {scanProgress.total_findings} findings | Risk: {scanProgress.overall_risk_label} | {scanProgress.duration_seconds?.toFixed(1)}s
              </span>
            )}
          </div>
        )}
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-6">
        <div className="card text-center">
          <p className="text-xs text-brand-gray-400 uppercase font-semibold">Data Stores</p>
          <p className="text-2xl font-bold text-brand-navy">{summary.total_data_stores || 0}</p>
        </div>
        <div className="card text-center cursor-pointer hover:shadow-md transition-shadow" onClick={() => { setActiveTab('findings'); setFindingsStatusFilter('FAIL') }}>
          <p className="text-xs text-brand-gray-400 uppercase font-semibold">At Risk</p>
          <p className="text-2xl font-bold text-red-600">{summary.stores_at_risk || 0}</p>
        </div>
        <div className="card text-center cursor-pointer hover:shadow-md transition-shadow" onClick={() => setActiveTab('findings')}>
          <p className="text-xs text-brand-gray-400 uppercase font-semibold">Data Findings</p>
          <p className="text-2xl font-bold text-brand-navy">{summary.total_findings || 0}</p>
        </div>
        <div className="card text-center">
          <p className="text-xs text-brand-gray-400 uppercase font-semibold">Pass Rate</p>
          <p className={`text-2xl font-bold ${
            summary.pass_rate >= 80 ? 'text-green-600' : summary.pass_rate >= 50 ? 'text-amber-500' : 'text-red-600'
          }`}>
            {summary.pass_rate || 0}%
          </p>
        </div>
        <div className="card text-center">
          <p className="text-xs text-brand-gray-400 uppercase font-semibold">PII Patterns</p>
          <p className="text-2xl font-bold text-purple-600">{totalPiiPatterns}</p>
        </div>
        <div className="card text-center">
          <p className="text-xs text-brand-gray-400 uppercase font-semibold">DSPM Modules</p>
          <p className="text-2xl font-bold text-brand-green">{totalModules}</p>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="flex gap-1 mb-6 bg-brand-gray-100 rounded-lg p-1 w-fit">
        {([
          { id: 'inventory' as const, label: 'Data Inventory' },
          { id: 'findings' as const, label: 'Findings' },
          { id: 'checks' as const, label: 'Security Checks' },
          { id: 'pii' as const, label: 'PII Detection' },
          { id: 'classification' as const, label: 'Data Classification' },
          { id: 'dspm-scans' as const, label: 'DSPM Scans' },
          { id: 'dspm-findings' as const, label: 'DSPM Findings' },
          { id: 'modules' as const, label: 'DSPM Modules' },
        ] as const).map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
              activeTab === tab.id ? 'bg-white text-brand-navy shadow-sm' : 'text-brand-gray-500 hover:text-brand-gray-700'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Data Inventory Tab */}
      {activeTab === 'inventory' && (
        <div className="card overflow-hidden p-0">
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-brand-gray-200">
              <thead>
                <tr className="bg-brand-gray-50">
                  <th className="px-4 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase">Provider</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase">Account</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase">Data Store</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase">Type</th>
                  <th className="px-4 py-3 text-right text-xs font-semibold text-brand-gray-500 uppercase">Findings</th>
                  <th className="px-4 py-3 text-right text-xs font-semibold text-green-600 uppercase">Passed</th>
                  <th className="px-4 py-3 text-right text-xs font-semibold text-red-600 uppercase">Failed</th>
                  <th className="px-4 py-3 text-center text-xs font-semibold text-brand-gray-500 uppercase">Risk</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-brand-gray-100">
                {inventory.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="px-6 py-12 text-center text-brand-gray-400">
                      No data stores found. Connect a cloud provider and run a scan to discover data stores.
                    </td>
                  </tr>
                ) : (
                  inventory.map((store: any, idx: number) => (
                    <tr key={idx} className="hover:bg-brand-gray-50">
                      <td className="px-4 py-3">
                        <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${
                          PROVIDER_COLORS[store.provider_type] || 'bg-gray-100 text-gray-500 border-gray-200'
                        }`}>
                          {store.provider_type.toUpperCase()}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-sm text-brand-navy font-medium">{store.provider_alias}</td>
                      <td className="px-4 py-3 text-sm text-brand-gray-700">{store.label}</td>
                      <td className="px-4 py-3">
                        <span className="text-[10px] font-mono bg-brand-gray-100 text-brand-gray-600 px-1.5 py-0.5 rounded">
                          {STORE_TYPE_ICONS[store.store_type] || store.store_type}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-sm text-right font-medium">{store.total_findings}</td>
                      <td className="px-4 py-3 text-sm text-right text-green-600">{store.passed}</td>
                      <td className="px-4 py-3 text-sm text-right text-red-600">{store.failed}</td>
                      <td className="px-4 py-3 text-center">
                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
                          RISK_COLORS[store.risk_score] || 'bg-gray-100 text-gray-500 border-gray-200'
                        }`}>
                          {store.risk_score.toUpperCase()}
                        </span>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Findings Tab */}
      {activeTab === 'findings' && (
        <div className="space-y-4">
          {/* Category summary cards */}
          {findingsData?.category_summary && Object.keys(findingsData.category_summary).length > 0 && (
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
              {Object.entries(findingsData.category_summary).map(([cat, stats]: [string, any]) => {
                const catInfo = CATEGORY_LABELS[cat] || { label: cat, color: 'bg-gray-100 text-gray-600' }
                return (
                  <button
                    key={cat}
                    onClick={() => setFindingsCategoryFilter(findingsCategoryFilter === cat ? '' : cat)}
                    className={`card text-center cursor-pointer transition-all ${
                      findingsCategoryFilter === cat ? 'ring-2 ring-brand-green' : ''
                    }`}
                  >
                    <span className={`text-[10px] font-medium px-1.5 py-0.5 rounded ${catInfo.color}`}>{catInfo.label}</span>
                    <p className="text-lg font-bold text-brand-navy mt-1">{stats.total}</p>
                    <div className="flex justify-center gap-2 text-[10px] mt-1">
                      <span className="text-green-600">{stats.pass} pass</span>
                      <span className="text-red-600">{stats.fail} fail</span>
                    </div>
                  </button>
                )
              })}
            </div>
          )}

          {/* Filters */}
          <div className="flex gap-3 items-center">
            {findingsCategoryFilter && (
              <button
                onClick={() => setFindingsCategoryFilter('')}
                className="text-xs text-brand-gray-500 hover:text-brand-navy flex items-center gap-1"
              >
                Clear filter
              </button>
            )}
            <select
              value={findingsStatusFilter}
              onChange={(e) => setFindingsStatusFilter(e.target.value)}
              className="px-3 py-1.5 border border-brand-gray-200 rounded-lg text-sm"
            >
              <option value="">All Statuses</option>
              <option value="FAIL">Failed</option>
              <option value="PASS">Passed</option>
            </select>
            <span className="text-xs text-brand-gray-400">
              {findingsData?.total || 0} total findings
            </span>
          </div>

          {/* Findings table */}
          <div className="card overflow-hidden p-0">
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-brand-gray-200">
                <thead>
                  <tr className="bg-brand-gray-50">
                    <th className="px-4 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase">Status</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase">Severity</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase">Check</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase">Category</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase">Data Store</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase">Resource</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase">Service</th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-brand-gray-100">
                  {(!findingsData?.findings || findingsData.findings.length === 0) ? (
                    <tr>
                      <td colSpan={7} className="px-6 py-12 text-center text-brand-gray-400">
                        No DSPM findings found. Run a cloud scan to discover data security issues.
                      </td>
                    </tr>
                  ) : (
                    findingsData.findings
                      .filter((f: any) => !findingsStatusFilter || f.status === findingsStatusFilter)
                      .map((f: any, idx: number) => {
                        const catInfo = CATEGORY_LABELS[f.dspm_category] || { label: f.dspm_category, color: 'bg-gray-100 text-gray-600' }
                        const isExpanded = expandedFindingId === (f.id || String(idx))
                        return (
                          <React.Fragment key={f.id || idx}>
                            <tr
                              className="hover:bg-brand-gray-50 cursor-pointer"
                              onClick={() => setExpandedFindingId(isExpanded ? null : (f.id || String(idx)))}
                            >
                              <td className="px-4 py-3">
                                <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                                  f.status === 'FAIL'
                                    ? 'bg-red-100 text-red-700 border border-red-200'
                                    : 'bg-green-100 text-green-700 border border-green-200'
                                }`}>
                                  {f.status}
                                </span>
                              </td>
                              <td className="px-4 py-3">
                                <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
                                  SEVERITY_COLORS[f.severity] || 'bg-gray-100 text-gray-600 border-gray-200'
                                }`}>
                                  {f.severity?.toUpperCase()}
                                </span>
                              </td>
                              <td className="px-4 py-3 text-sm text-brand-navy font-medium max-w-xs truncate">
                                {f.check_title}
                              </td>
                              <td className="px-4 py-3">
                                <span className={`text-[10px] font-medium px-1.5 py-0.5 rounded ${catInfo.color}`}>
                                  {catInfo.label}
                                </span>
                              </td>
                              <td className="px-4 py-3 text-xs text-brand-gray-600">
                                {f.dspm_data_store || '-'}
                              </td>
                              <td className="px-4 py-3 text-xs text-brand-gray-600 max-w-[200px] truncate">
                                {f.resource_name || f.resource_id || '-'}
                              </td>
                              <td className="px-4 py-3 text-xs text-brand-gray-500">
                                {f.service}
                              </td>
                            </tr>
                            {isExpanded && (
                              <tr>
                                <td colSpan={7} className="px-4 py-4 bg-brand-gray-50 border-t border-brand-gray-100">
                                  <div className="grid grid-cols-2 gap-4 text-sm">
                                    <div>
                                      <p className="text-xs font-semibold text-brand-gray-500 mb-1">Check ID</p>
                                      <p className="text-xs font-mono text-brand-gray-700">{f.check_id}</p>
                                    </div>
                                    <div>
                                      <p className="text-xs font-semibold text-brand-gray-500 mb-1">Resource</p>
                                      <p className="text-xs text-brand-gray-700">{f.resource_name || f.resource_id || 'N/A'}</p>
                                    </div>
                                    <div>
                                      <p className="text-xs font-semibold text-brand-gray-500 mb-1">Data Store</p>
                                      <p className="text-xs text-brand-gray-700">{f.dspm_data_store || 'N/A'}</p>
                                    </div>
                                    <div>
                                      <p className="text-xs font-semibold text-brand-gray-500 mb-1">Provider</p>
                                      <p className="text-xs text-brand-gray-700">{f.dspm_provider || 'N/A'}</p>
                                    </div>
                                    {f.remediation && (
                                      <div className="col-span-2">
                                        <p className="text-xs font-semibold text-brand-gray-500 mb-1">Remediation</p>
                                        <p className="text-xs text-brand-gray-700">{f.remediation}</p>
                                      </div>
                                    )}
                                    {!f.remediation && f.status === 'PASS' && (
                                      <div className="col-span-2">
                                        <p className="text-xs font-semibold text-brand-gray-500 mb-1">Status Detail</p>
                                        <p className="text-xs text-green-600">This check passed — the data store meets the security requirement for {catInfo.label.toLowerCase()}.</p>
                                      </div>
                                    )}
                                    {!f.remediation && f.status === 'FAIL' && (
                                      <div className="col-span-2">
                                        <p className="text-xs font-semibold text-brand-gray-500 mb-1">Status Detail</p>
                                        <p className="text-xs text-red-600">This check failed — the data store does not meet the security requirement. Review and apply the recommended remediation.</p>
                                      </div>
                                    )}
                                  </div>
                                </td>
                              </tr>
                            )}
                          </React.Fragment>
                        )
                      })
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Security Checks Tab */}
      {activeTab === 'checks' && (
        <div className="space-y-3">
          {checks.map((check: any) => {
            const cat = CATEGORY_LABELS[check.category] || { label: check.category, color: 'bg-gray-100 text-gray-600' }
            return (
              <div key={check.check_id} className="card">
                <div className="flex items-start justify-between gap-3">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-[10px] font-mono font-semibold text-brand-green bg-brand-green/10 px-1.5 py-0.5 rounded">
                        {check.check_id}
                      </span>
                      <span className={`text-[10px] font-medium px-1.5 py-0.5 rounded ${cat.color}`}>
                        {cat.label}
                      </span>
                      <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                        check.severity === 'critical' ? 'bg-red-100 text-red-700' :
                        check.severity === 'high' ? 'bg-orange-100 text-orange-700' :
                        check.severity === 'medium' ? 'bg-yellow-100 text-yellow-700' :
                        'bg-blue-100 text-blue-700'
                      }`}>
                        {check.severity.toUpperCase()}
                      </span>
                    </div>
                    <h4 className="text-sm font-medium text-brand-navy">{check.title}</h4>
                    <p className="text-xs text-brand-gray-500 mt-1">{check.description}</p>
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* PII Detection Tab */}
      {activeTab === 'pii' && (
        <div className="space-y-6">
          {/* Severity Summary */}
          {piiPatterns?.severity_summary && (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {(['critical', 'high', 'medium', 'low'] as const).map((sev) => (
                <div key={sev} className={`card text-center border ${SEVERITY_COLORS[sev]}`}>
                  <p className="text-xs uppercase font-semibold">{sev}</p>
                  <p className="text-2xl font-bold">{piiPatterns.severity_summary[sev] || 0}</p>
                  <p className="text-[10px] opacity-70">patterns</p>
                </div>
              ))}
            </div>
          )}

          {/* Patterns by GDPR Category */}
          {piiPatterns?.patterns_by_gdpr_category && (
            Object.entries(piiPatterns.patterns_by_gdpr_category).map(([category, patterns]: [string, any]) => {
              const catInfo = GDPR_CATEGORY_LABELS[category] || { label: category, color: 'bg-gray-100 text-gray-700' }
              return (
                <div key={category}>
                  <div className="flex items-center gap-2 mb-3">
                    <span className={`text-xs font-semibold px-2 py-1 rounded ${catInfo.color}`}>
                      {catInfo.label}
                    </span>
                    <span className="text-xs text-brand-gray-400">{patterns.length} pattern{patterns.length !== 1 ? 's' : ''}</span>
                  </div>
                  <div className="card overflow-hidden p-0">
                    <table className="min-w-full divide-y divide-brand-gray-200">
                      <thead>
                        <tr className="bg-brand-gray-50">
                          <th className="px-4 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase">Pattern</th>
                          <th className="px-4 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase">ID</th>
                          <th className="px-4 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase">Category</th>
                          <th className="px-4 py-3 text-center text-xs font-semibold text-brand-gray-500 uppercase">Severity</th>
                          <th className="px-4 py-3 text-center text-xs font-semibold text-brand-gray-500 uppercase">Confidence</th>
                          <th className="px-4 py-3 text-center text-xs font-semibold text-brand-gray-500 uppercase">Validator</th>
                        </tr>
                      </thead>
                      <tbody className="bg-white divide-y divide-brand-gray-100">
                        {patterns.map((p: any) => (
                          <tr key={p.pattern_id} className="hover:bg-brand-gray-50">
                            <td className="px-4 py-3 text-sm font-medium text-brand-navy">{p.name}</td>
                            <td className="px-4 py-3">
                              <span className="text-[10px] font-mono text-brand-gray-500 bg-brand-gray-100 px-1.5 py-0.5 rounded">
                                {p.pattern_id}
                              </span>
                            </td>
                            <td className="px-4 py-3 text-xs text-brand-gray-600">{p.category}</td>
                            <td className="px-4 py-3 text-center">
                              <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
                                SEVERITY_COLORS[p.severity] || 'bg-gray-100 text-gray-600 border-gray-200'
                              }`}>
                                {p.severity.toUpperCase()}
                              </span>
                            </td>
                            <td className="px-4 py-3 text-center">
                              <span className={`text-[10px] font-semibold px-2 py-0.5 rounded ${
                                p.confidence === 'high'
                                  ? 'bg-green-100 text-green-700'
                                  : 'bg-yellow-100 text-yellow-700'
                              }`}>
                                {p.confidence.toUpperCase()}
                              </span>
                            </td>
                            <td className="px-4 py-3 text-center">
                              {p.has_validator ? (
                                <span className="text-[10px] font-semibold bg-green-100 text-green-700 px-2 py-0.5 rounded">YES</span>
                              ) : (
                                <span className="text-[10px] font-semibold bg-brand-gray-100 text-brand-gray-400 px-2 py-0.5 rounded">NO</span>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )
            })
          )}

          {!piiPatterns && (
            <div className="card text-center py-12 text-brand-gray-400">
              Unable to load PII pattern data. Ensure the DSPM API is available.
            </div>
          )}
        </div>
      )}

      {/* Data Classification Tab */}
      {activeTab === 'classification' && (
        <div className="space-y-6">
          {/* Classification Levels */}
          <div>
            <h3 className="text-sm font-semibold text-brand-navy mb-3">Classification Levels</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              {classificationLevels?.levels?.map((level: string) => {
                const details = classificationLevels.level_details?.[level]
                const colors = CLASSIFICATION_LEVEL_COLORS[level] || CLASSIFICATION_LEVEL_COLORS.public
                return (
                  <div key={level} className={`card border ${colors.border} ${colors.bg}`}>
                    <div className="flex items-center gap-2 mb-2">
                      <span className={`w-3 h-3 rounded-full ${colors.dot}`} />
                      <h4 className={`text-sm font-bold ${colors.text}`}>{details?.label || level}</h4>
                      <span className={`ml-auto text-[10px] font-mono ${colors.text} opacity-60`}>
                        Level {details?.order ?? '?'}
                      </span>
                    </div>
                    <p className="text-xs text-brand-gray-600">{details?.description || ''}</p>
                  </div>
                )
              })}
            </div>
          </div>

          {/* Classification Rules */}
          {classificationLevels?.rules && classificationLevels.rules.length > 0 && (
            <div>
              <h3 className="text-sm font-semibold text-brand-navy mb-3">Classification Rules</h3>
              <div className="card overflow-hidden p-0">
                <table className="min-w-full divide-y divide-brand-gray-200">
                  <thead>
                    <tr className="bg-brand-gray-50">
                      <th className="px-4 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase">PII Categories</th>
                      <th className="px-4 py-3 text-center text-xs font-semibold text-brand-gray-500 uppercase">Min Matches</th>
                      <th className="px-4 py-3 text-center text-xs font-semibold text-brand-gray-500 uppercase">Classification</th>
                      <th className="px-4 py-3 text-center text-xs font-semibold text-brand-gray-500 uppercase">Confidence</th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-brand-gray-100">
                    {classificationLevels.rules.map((rule: any, idx: number) => {
                      const levelColors = CLASSIFICATION_LEVEL_COLORS[rule.level] || CLASSIFICATION_LEVEL_COLORS.public
                      return (
                        <tr key={idx} className="hover:bg-brand-gray-50">
                          <td className="px-4 py-3">
                            <div className="flex flex-wrap gap-1">
                              {rule.pii_categories.map((cat: string) => (
                                <span key={cat} className="text-[10px] font-medium bg-purple-100 text-purple-700 px-1.5 py-0.5 rounded">
                                  {cat}
                                </span>
                              ))}
                            </div>
                          </td>
                          <td className="px-4 py-3 text-sm text-center font-medium text-brand-navy">{rule.min_matches}</td>
                          <td className="px-4 py-3 text-center">
                            <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${levelColors.border} ${levelColors.bg} ${levelColors.text}`}>
                              {rule.level.toUpperCase()}
                            </span>
                          </td>
                          <td className="px-4 py-3 text-center">
                            <span className="text-sm font-medium text-brand-navy">{Math.round(rule.confidence * 100)}%</span>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Tag Conventions */}
          {classificationLevels?.tag_conventions && (
            <div>
              <h3 className="text-sm font-semibold text-brand-navy mb-3">Cloud Provider Tag Conventions</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {Object.entries(classificationLevels.tag_conventions).map(([provider, mapping]: [string, any]) => (
                  <div key={provider} className="card">
                    <div className="flex items-center gap-2 mb-3">
                      <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${
                        PROVIDER_COLORS[provider] || 'bg-gray-100 text-gray-500 border-gray-200'
                      }`}>
                        {provider.toUpperCase()}
                      </span>
                      <span className="text-xs font-mono text-brand-gray-500">Key: {mapping.key}</span>
                    </div>
                    <div className="space-y-1">
                      {Object.entries(mapping.values).map(([level, value]: [string, any]) => {
                        const levelColors = CLASSIFICATION_LEVEL_COLORS[level] || CLASSIFICATION_LEVEL_COLORS.public
                        return (
                          <div key={level} className="flex items-center justify-between text-xs">
                            <span className={`font-medium ${levelColors.text}`}>{level}</span>
                            <span className="font-mono text-brand-gray-500">{value}</span>
                          </div>
                        )
                      })}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {!classificationLevels && (
            <div className="card text-center py-12 text-brand-gray-400">
              Unable to load classification data. Ensure the DSPM API is available.
            </div>
          )}
        </div>
      )}

      {/* DSPM Scans Tab */}
      {activeTab === 'dspm-scans' && (
        <div className="space-y-4">
          {selectedScanDetail ? (
            <div className="space-y-4">
              <button
                onClick={() => setSelectedScanDetail(null)}
                className="text-xs text-brand-gray-500 hover:text-brand-navy flex items-center gap-1"
              >
                &larr; Back to scan list
              </button>
              <div className="card">
                <div className="flex items-center gap-3 mb-4">
                  <h3 className="text-sm font-bold text-brand-navy">DSPM Scan Detail</h3>
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                    selectedScanDetail.status === 'completed' ? 'bg-green-100 text-green-700 border border-green-200' :
                    selectedScanDetail.status === 'failed' ? 'bg-red-100 text-red-700 border border-red-200' :
                    'bg-blue-100 text-blue-700 border border-blue-200'
                  }`}>
                    {selectedScanDetail.status?.toUpperCase()}
                  </span>
                  {selectedScanDetail.provider_type && (
                    <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${
                      PROVIDER_COLORS[selectedScanDetail.provider_type] || 'bg-gray-100 text-gray-500 border-gray-200'
                    }`}>
                      {selectedScanDetail.provider_type?.toUpperCase()}
                    </span>
                  )}
                </div>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                  <div className="text-center">
                    <p className="text-xs text-brand-gray-400 uppercase">Findings</p>
                    <p className="text-xl font-bold text-brand-navy">{selectedScanDetail.total_findings}</p>
                  </div>
                  <div className="text-center">
                    <p className="text-xs text-brand-gray-400 uppercase">Risk</p>
                    <p className={`text-xl font-bold ${
                      selectedScanDetail.overall_risk_label === 'critical' ? 'text-red-600' :
                      selectedScanDetail.overall_risk_label === 'high' ? 'text-orange-600' :
                      selectedScanDetail.overall_risk_label === 'medium' ? 'text-yellow-600' :
                      'text-green-600'
                    }`}>{selectedScanDetail.overall_risk_label?.toUpperCase()} ({selectedScanDetail.overall_risk_score?.toFixed(1)})</p>
                  </div>
                  <div className="text-center">
                    <p className="text-xs text-brand-gray-400 uppercase">Modules Run</p>
                    <p className="text-xl font-bold text-brand-navy">{selectedScanDetail.modules_run}</p>
                  </div>
                  <div className="text-center">
                    <p className="text-xs text-brand-gray-400 uppercase">Duration</p>
                    <p className="text-xl font-bold text-brand-navy">{selectedScanDetail.duration_seconds?.toFixed(1)}s</p>
                  </div>
                </div>
                {/* Findings by severity */}
                {selectedScanDetail.findings_by_severity && Object.keys(selectedScanDetail.findings_by_severity).length > 0 && (
                  <div className="flex gap-2 mb-4">
                    {Object.entries(selectedScanDetail.findings_by_severity).map(([sev, count]: [string, any]) => (
                      <span key={sev} className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
                        SEVERITY_COLORS[sev] || 'bg-gray-100 text-gray-600 border-gray-200'
                      }`}>
                        {sev.toUpperCase()}: {count}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              {/* Findings grouped by module */}
              {selectedScanDetail.findings_by_module_detail && Object.entries(selectedScanDetail.findings_by_module_detail).map(([mod, findings]: [string, any]) => {
                const modInfo = MODULE_LABELS[mod] || { label: mod, color: 'bg-gray-100 text-gray-600' }
                return (
                  <div key={mod}>
                    <div className="flex items-center gap-2 mb-2">
                      <span className={`text-xs font-semibold px-2 py-1 rounded ${modInfo.color}`}>{modInfo.label}</span>
                      <span className="text-xs text-brand-gray-400">{findings.length} finding{findings.length !== 1 ? 's' : ''}</span>
                    </div>
                    <div className="card overflow-hidden p-0">
                      <table className="min-w-full divide-y divide-brand-gray-200">
                        <thead>
                          <tr className="bg-brand-gray-50">
                            <th className="px-4 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase">Severity</th>
                            <th className="px-4 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase">Title</th>
                            <th className="px-4 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase">Resource</th>
                            <th className="px-4 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase">Category</th>
                            <th className="px-4 py-3 text-right text-xs font-semibold text-brand-gray-500 uppercase">Risk Score</th>
                          </tr>
                        </thead>
                        <tbody className="bg-white divide-y divide-brand-gray-100">
                          {findings.map((f: any) => (
                            <tr key={f.id} className="hover:bg-brand-gray-50">
                              <td className="px-4 py-3">
                                <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
                                  SEVERITY_COLORS[f.severity] || 'bg-gray-100 text-gray-600 border-gray-200'
                                }`}>{f.severity?.toUpperCase()}</span>
                              </td>
                              <td className="px-4 py-3 text-sm text-brand-navy font-medium max-w-xs truncate">{f.title}</td>
                              <td className="px-4 py-3 text-xs text-brand-gray-600 max-w-[200px] truncate">{f.resource_name || f.resource_id || '-'}</td>
                              <td className="px-4 py-3 text-xs text-brand-gray-600">{f.category || '-'}</td>
                              <td className="px-4 py-3 text-sm text-right font-medium">{f.risk_score?.toFixed(1)}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )
              })}
            </div>
          ) : (
            <div className="card overflow-hidden p-0">
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-brand-gray-200">
                  <thead>
                    <tr className="bg-brand-gray-50">
                      <th className="px-4 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase">Status</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase">Provider</th>
                      <th className="px-4 py-3 text-right text-xs font-semibold text-brand-gray-500 uppercase">Findings</th>
                      <th className="px-4 py-3 text-center text-xs font-semibold text-brand-gray-500 uppercase">Risk</th>
                      <th className="px-4 py-3 text-right text-xs font-semibold text-brand-gray-500 uppercase">Modules</th>
                      <th className="px-4 py-3 text-right text-xs font-semibold text-brand-gray-500 uppercase">Duration</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase">Content Scan</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase">Date</th>
                      <th className="px-4 py-3 text-center text-xs font-semibold text-brand-gray-500 uppercase">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-brand-gray-100">
                    {dspmScans.length === 0 ? (
                      <tr>
                        <td colSpan={9} className="px-6 py-12 text-center text-brand-gray-400">
                          No DSPM scans yet. Click &quot;Run DSPM Scan&quot; to start.
                        </td>
                      </tr>
                    ) : (
                      dspmScans.map((s: any) => (
                        <tr key={s.scan_id} className="hover:bg-brand-gray-50">
                          <td className="px-4 py-3">
                            <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                              s.status === 'completed' ? 'bg-green-100 text-green-700 border border-green-200' :
                              s.status === 'failed' ? 'bg-red-100 text-red-700 border border-red-200' :
                              s.status === 'running' ? 'bg-blue-100 text-blue-700 border border-blue-200' :
                              'bg-gray-100 text-gray-500 border border-gray-200'
                            }`}>{s.status?.toUpperCase()}</span>
                          </td>
                          <td className="px-4 py-3">
                            {s.provider_type && (
                              <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${
                                PROVIDER_COLORS[s.provider_type] || 'bg-gray-100 text-gray-500 border-gray-200'
                              }`}>{s.provider_type?.toUpperCase()}</span>
                            )}
                            <span className="ml-2 text-xs text-brand-gray-600">{s.provider_alias}</span>
                          </td>
                          <td className="px-4 py-3 text-sm text-right font-medium">{s.total_findings}</td>
                          <td className="px-4 py-3 text-center">
                            <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
                              RISK_COLORS[s.overall_risk_label] || 'bg-gray-100 text-gray-500 border-gray-200'
                            }`}>{s.overall_risk_label?.toUpperCase()}</span>
                          </td>
                          <td className="px-4 py-3 text-sm text-right">{s.modules_run}</td>
                          <td className="px-4 py-3 text-sm text-right text-brand-gray-500">{s.duration_seconds?.toFixed(1)}s</td>
                          <td className="px-4 py-3 text-xs">
                            {s.enable_content_scanning ? (
                              <span className="text-[10px] font-semibold bg-purple-100 text-purple-700 px-1.5 py-0.5 rounded">PII</span>
                            ) : (
                              <span className="text-[10px] text-brand-gray-400">-</span>
                            )}
                          </td>
                          <td className="px-4 py-3 text-xs text-brand-gray-500">{s.created_at ? new Date(s.created_at).toLocaleDateString() : '-'}</td>
                          <td className="px-4 py-3 text-center">
                            <button
                              onClick={() => viewScanDetail(s.scan_id)}
                              className="text-xs text-brand-green hover:underline font-medium"
                            >View</button>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* DSPM Findings Tab — unified view with Source column */}
      {activeTab === 'dspm-findings' && (
        <div className="space-y-4">
          {/* Filters */}
          <div className="flex gap-3 items-center flex-wrap">
            <select
              value={dspmModuleFilter}
              onChange={(e) => setDspmModuleFilter(e.target.value)}
              className="px-3 py-1.5 border border-brand-gray-200 rounded-lg text-sm"
            >
              <option value="">All Modules</option>
              {Object.entries(MODULE_LABELS).map(([id, info]) => (
                <option key={id} value={id}>{info.label}</option>
              ))}
            </select>
            <select
              value={dspmSeverityFilter}
              onChange={(e) => setDspmSeverityFilter(e.target.value)}
              className="px-3 py-1.5 border border-brand-gray-200 rounded-lg text-sm"
            >
              <option value="">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
            <span className="text-xs text-brand-gray-400">
              {dspmFindings?.total || 0} DSPM findings
            </span>
          </div>

          {/* Findings table */}
          <div className="card overflow-hidden p-0">
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-brand-gray-200">
                <thead>
                  <tr className="bg-brand-gray-50">
                    <th className="px-4 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase">Severity</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase">Title</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase">Module</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase">Category</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase">Resource</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase">Source</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase">Status</th>
                    <th className="px-4 py-3 text-center text-xs font-semibold text-brand-gray-500 uppercase">Actions</th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-brand-gray-100">
                  {dspmFindingsLoading ? (
                    <tr><td colSpan={8} className="px-6 py-12 text-center text-brand-gray-400">Loading...</td></tr>
                  ) : (!dspmFindings?.findings || dspmFindings.findings.length === 0) ? (
                    <tr><td colSpan={8} className="px-6 py-12 text-center text-brand-gray-400">No DSPM findings found. Run a DSPM scan to discover data security issues.</td></tr>
                  ) : (
                    dspmFindings.findings.map((f: any) => {
                      const modInfo = MODULE_LABELS[f.module] || { label: f.module, color: 'bg-gray-100 text-gray-600' }
                      return (
                        <tr key={f.id} className="hover:bg-brand-gray-50">
                          <td className="px-4 py-3">
                            <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
                              SEVERITY_COLORS[f.severity] || 'bg-gray-100 text-gray-600 border-gray-200'
                            }`}>{f.severity?.toUpperCase()}</span>
                          </td>
                          <td className="px-4 py-3 text-sm text-brand-navy font-medium max-w-xs truncate" title={f.description}>{f.title}</td>
                          <td className="px-4 py-3">
                            <span className={`text-[10px] font-medium px-1.5 py-0.5 rounded ${modInfo.color}`}>{modInfo.label}</span>
                          </td>
                          <td className="px-4 py-3 text-xs text-brand-gray-600">{f.category || '-'}</td>
                          <td className="px-4 py-3 text-xs text-brand-gray-600 max-w-[200px] truncate">{f.resource_name || f.resource_id || '-'}</td>
                          <td className="px-4 py-3">
                            <span className="text-[10px] font-medium bg-indigo-100 text-indigo-700 px-1.5 py-0.5 rounded">
                              {f.source === 'dspm_engine' ? 'DSPM Engine' : 'Cloud Scanner'}
                            </span>
                          </td>
                          <td className="px-4 py-3">
                            <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                              f.status === 'open' ? 'bg-red-100 text-red-700' :
                              f.status === 'resolved' ? 'bg-green-100 text-green-700' :
                              'bg-gray-100 text-gray-500'
                            }`}>{f.status?.toUpperCase()}</span>
                          </td>
                          <td className="px-4 py-3 text-center">
                            <select
                              value={f.status}
                              onChange={(e) => updateFindingStatus(f.id, e.target.value)}
                              className="text-xs border border-brand-gray-200 rounded px-1 py-0.5"
                            >
                              <option value="open">Open</option>
                              <option value="resolved">Resolved</option>
                              <option value="ignored">Ignored</option>
                            </select>
                          </td>
                        </tr>
                      )
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* DSPM Modules Tab */}
      {activeTab === 'modules' && (
        <div className="space-y-6">
          {/* Module Summary */}
          {scanCapabilities && (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="card text-center">
                <p className="text-xs text-brand-gray-400 uppercase font-semibold">Total Modules</p>
                <p className="text-2xl font-bold text-brand-navy">{scanCapabilities.total_modules}</p>
              </div>
              <div className="card text-center">
                <p className="text-xs text-brand-gray-400 uppercase font-semibold">Active</p>
                <p className="text-2xl font-bold text-brand-green">{scanCapabilities.active_modules}</p>
              </div>
              <div className="card text-center">
                <p className="text-xs text-brand-gray-400 uppercase font-semibold">PII Patterns</p>
                <p className="text-2xl font-bold text-purple-600">{scanCapabilities.total_pii_patterns}</p>
              </div>
              <div className="card text-center">
                <p className="text-xs text-brand-gray-400 uppercase font-semibold">Security Checks</p>
                <p className="text-2xl font-bold text-brand-navy">{scanCapabilities.total_security_checks}</p>
              </div>
            </div>
          )}

          {/* Module Cards */}
          <div className="space-y-4">
            {scanCapabilities?.modules?.map((mod: any) => (
              <div key={mod.id} className="card">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-2">
                      <h4 className="text-sm font-bold text-brand-navy">{mod.name}</h4>
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                        mod.status === 'active'
                          ? 'bg-green-100 text-green-700 border border-green-200'
                          : 'bg-gray-100 text-gray-500 border border-gray-200'
                      }`}>
                        {mod.status.toUpperCase()}
                      </span>
                      {mod.pattern_count !== undefined && (
                        <span className="text-[10px] font-medium bg-purple-100 text-purple-700 px-1.5 py-0.5 rounded">
                          {mod.pattern_count} patterns
                        </span>
                      )}
                      {mod.check_count !== undefined && (
                        <span className="text-[10px] font-medium bg-blue-100 text-blue-700 px-1.5 py-0.5 rounded">
                          {mod.check_count} checks
                        </span>
                      )}
                      {mod.classification_levels && (
                        <span className="text-[10px] font-medium bg-orange-100 text-orange-700 px-1.5 py-0.5 rounded">
                          {mod.classification_levels.length} levels
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-brand-gray-500 mb-3">{mod.description}</p>
                    <div className="flex flex-wrap gap-1.5">
                      {mod.capabilities.map((cap: string, i: number) => (
                        <span key={i} className="text-[10px] bg-brand-gray-100 text-brand-gray-600 px-2 py-0.5 rounded">
                          {cap}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>

          {!scanCapabilities && (
            <div className="card text-center py-12 text-brand-gray-400">
              Unable to load module data. Ensure the DSPM API is available.
            </div>
          )}
        </div>
      )}
    </div>
  )
}
