'use client'

import { useEffect, useState } from 'react'
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

export default function DSPMPage() {
  const [overview, setOverview] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [activeTab, setActiveTab] = useState<'inventory' | 'checks'>('inventory')

  useEffect(() => {
    api.getDSPMOverview()
      .then(setOverview)
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [])

  if (loading) {
    return (
      <div>
        <Header title="Data Security (DSPM)" subtitle="Data Security Posture Management" />
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="card animate-pulse"><div className="h-20 bg-brand-gray-100 rounded" /></div>
          ))}
        </div>
      </div>
    )
  }

  const summary = overview?.summary || {}
  const inventory = overview?.data_inventory || []
  const checks = overview?.check_catalog || []

  return (
    <div>
      <Header title="Data Security (DSPM)" subtitle="Data Security Posture Management — data store inventory, classification, and risk" />

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <div className="card text-center">
          <p className="text-xs text-brand-gray-400 uppercase font-semibold">Data Stores</p>
          <p className="text-2xl font-bold text-brand-navy">{summary.total_data_stores || 0}</p>
        </div>
        <div className="card text-center">
          <p className="text-xs text-brand-gray-400 uppercase font-semibold">At Risk</p>
          <p className="text-2xl font-bold text-red-600">{summary.stores_at_risk || 0}</p>
        </div>
        <div className="card text-center">
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
      </div>

      {/* Tab Navigation */}
      <div className="flex gap-1 mb-6 bg-brand-gray-100 rounded-lg p-1 w-fit">
        {[
          { id: 'inventory' as const, label: 'Data Inventory' },
          { id: 'checks' as const, label: 'Security Checks' },
        ].map((tab) => (
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
    </div>
  )
}
