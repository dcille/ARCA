'use client'

import { useEffect, useState } from 'react'
import Header from '@/components/layout/Header'
import DataTable from '@/components/ui/DataTable'
import Badge from '@/components/ui/Badge'
import { api } from '@/lib/api'
import { formatDate } from '@/lib/utils'
import toast from 'react-hot-toast'

export default function ScansPage() {
  const [scans, setScans] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [providers, setProviders] = useState<any[]>([])
  const [connections, setConnections] = useState<any[]>([])
  const [showModal, setShowModal] = useState(false)
  const [scanType, setScanType] = useState('cloud')
  const [selectedProvider, setSelectedProvider] = useState('')
  const [selectedConnection, setSelectedConnection] = useState('')

  const loadData = async () => {
    setLoading(true)
    try {
      const [s, p, c] = await Promise.all([
        api.getScans(),
        api.getProviders(),
        api.getSaaSConnections(),
      ])
      setScans(s)
      setProviders(p)
      setConnections(c)
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { loadData() }, [])

  const handleCreateScan = async () => {
    try {
      const data: any = { scan_type: scanType }
      if (scanType === 'cloud') {
        data.provider_id = selectedProvider
      } else {
        data.connection_id = selectedConnection
      }
      await api.createScan(data)
      toast.success('Scan started!')
      setShowModal(false)
      loadData()
    } catch (err: any) {
      toast.error(err.message || 'Failed to start scan')
    }
  }

  const columns = [
    {
      key: 'scan_type',
      header: 'Type',
      render: (item: any) => (
        <span className={`px-2.5 py-1 rounded-full text-xs font-medium ${
          item.scan_type === 'cloud'
            ? 'bg-brand-blue/10 text-brand-blue'
            : 'bg-brand-teal/10 text-brand-teal'
        }`}>
          {item.scan_type === 'cloud' ? 'Cloud' : 'SaaS'}
        </span>
      ),
    },
    {
      key: 'status',
      header: 'Status',
      render: (item: any) => <Badge type="status" value={item.status} />,
    },
    {
      key: 'progress',
      header: 'Progress',
      render: (item: any) => (
        <div className="flex items-center gap-2">
          <div className="w-24 bg-brand-gray-100 rounded-full h-2">
            <div
              className="bg-brand-green h-2 rounded-full transition-all"
              style={{ width: `${item.progress}%` }}
            />
          </div>
          <span className="text-xs text-brand-gray-500">{item.progress}%</span>
        </div>
      ),
    },
    { key: 'total_checks', header: 'Total Checks' },
    {
      key: 'results',
      header: 'Pass / Fail',
      render: (item: any) => (
        <span>
          <span className="text-status-pass font-medium">{item.passed_checks}</span>
          {' / '}
          <span className="text-status-fail font-medium">{item.failed_checks}</span>
        </span>
      ),
    },
    {
      key: 'created_at',
      header: 'Started',
      render: (item: any) => <span className="text-brand-gray-400 text-sm">{formatDate(item.created_at)}</span>,
    },
  ]

  return (
    <div>
      <Header
        title="Scans"
        subtitle="Manage and monitor security scans"
        actions={
          <button onClick={() => setShowModal(true)} className="btn-primary">
            New Scan
          </button>
        }
      />

      <DataTable
        columns={columns}
        data={scans}
        loading={loading}
        emptyMessage="No scans yet. Click 'New Scan' to get started."
      />

      {/* New Scan Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="bg-white rounded-xl shadow-xl p-6 w-full max-w-md">
            <h3 className="text-lg font-semibold text-brand-navy mb-4">Start New Scan</h3>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Scan Type</label>
                <div className="flex gap-3">
                  <button
                    onClick={() => setScanType('cloud')}
                    className={`flex-1 py-2 px-4 rounded-lg border-2 text-sm font-medium transition-colors ${
                      scanType === 'cloud'
                        ? 'border-brand-green bg-brand-green/5 text-brand-green'
                        : 'border-brand-gray-200 text-brand-gray-500'
                    }`}
                  >
                    Cloud
                  </button>
                  <button
                    onClick={() => setScanType('saas')}
                    className={`flex-1 py-2 px-4 rounded-lg border-2 text-sm font-medium transition-colors ${
                      scanType === 'saas'
                        ? 'border-brand-teal bg-brand-teal/5 text-brand-teal'
                        : 'border-brand-gray-200 text-brand-gray-500'
                    }`}
                  >
                    SaaS
                  </button>
                </div>
              </div>

              {scanType === 'cloud' ? (
                <div>
                  <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Cloud Provider</label>
                  <select
                    value={selectedProvider}
                    onChange={(e) => setSelectedProvider(e.target.value)}
                    className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm"
                  >
                    <option value="">Select a provider...</option>
                    {providers.map((p) => (
                      <option key={p.id} value={p.id}>{p.alias} ({p.provider_type})</option>
                    ))}
                  </select>
                </div>
              ) : (
                <div>
                  <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">SaaS Connection</label>
                  <select
                    value={selectedConnection}
                    onChange={(e) => setSelectedConnection(e.target.value)}
                    className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm"
                  >
                    <option value="">Select a connection...</option>
                    {connections.map((c) => (
                      <option key={c.id} value={c.id}>{c.alias} ({c.provider_type})</option>
                    ))}
                  </select>
                </div>
              )}
            </div>

            <div className="flex gap-3 mt-6">
              <button onClick={() => setShowModal(false)} className="flex-1 btn-outline">
                Cancel
              </button>
              <button
                onClick={handleCreateScan}
                disabled={scanType === 'cloud' ? !selectedProvider : !selectedConnection}
                className="flex-1 btn-primary disabled:opacity-50"
              >
                Start Scan
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
