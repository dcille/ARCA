'use client'

import { useEffect, useState } from 'react'
import Header from '@/components/layout/Header'
import StatCard from '@/components/ui/StatCard'
import Badge from '@/components/ui/Badge'
import DataTable from '@/components/ui/DataTable'
import { api } from '@/lib/api'
import { formatDate, formatPercent, getSaaSLabel } from '@/lib/utils'
import toast from 'react-hot-toast'
import {
  GlobeAltIcon,
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  PlusIcon,
  TrashIcon,
  ArrowPathIcon,
  BeakerIcon,
} from '@heroicons/react/24/outline'

const SAAS_PROVIDERS_BASE = [
  { id: 'servicenow', name: 'ServiceNow', icon: 'SN', color: 'bg-[#81B5A1]' },
  { id: 'm365', name: 'Microsoft 365', icon: 'M365', color: 'bg-[#0078D4]' },
  { id: 'salesforce', name: 'Salesforce', icon: 'SF', color: 'bg-[#00A1E0]' },
  { id: 'snowflake', name: 'Snowflake', icon: 'SN*', color: 'bg-[#29B5E8]' },
  { id: 'github', name: 'GitHub', icon: 'GH', color: 'bg-[#24292F]' },
  { id: 'google_workspace', name: 'Google Workspace', icon: 'GW', color: 'bg-[#4285F4]' },
  { id: 'cloudflare', name: 'Cloudflare', icon: 'CF', color: 'bg-[#F38020]' },
  { id: 'openstack', name: 'OpenStack', icon: 'OS', color: 'bg-[#ED1944]' },
]

type Tab = 'overview' | 'connections' | 'findings'

export default function SaaSSecurityPage() {
  const [tab, setTab] = useState<Tab>('overview')
  const [overview, setOverview] = useState<any>(null)
  const [connections, setConnections] = useState<any[]>([])
  const [findings, setFindings] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [showAddModal, setShowAddModal] = useState(false)
  const [providerType, setProviderType] = useState('servicenow')
  const [alias, setAlias] = useState('')
  const [credFields, setCredFields] = useState<Record<string, string>>({})
  const [filterProvider, setFilterProvider] = useState('')
  const [filterSeverity, setFilterSeverity] = useState('')

  // Merge registry check counts with provider base info
  const SAAS_PROVIDERS = SAAS_PROVIDERS_BASE.map(p => ({
    ...p,
    checks: overview?.registry_check_counts?.[p.id] || 0,
  }))

  const loadData = async () => {
    setLoading(true)
    try {
      const [ov, conns, finds] = await Promise.all([
        api.getSaaSOverview(),
        api.getSaaSConnections(),
        api.getSaaSFindings(),
      ])
      setOverview(ov)
      setConnections(conns)
      setFindings(finds)
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { loadData() }, [])

  const loadFindings = async () => {
    try {
      const params: Record<string, string> = {}
      if (filterProvider) params.provider_type = filterProvider
      if (filterSeverity) params.severity = filterSeverity
      const data = await api.getSaaSFindings(params)
      setFindings(data)
    } catch (err) {
      console.error(err)
    }
  }

  useEffect(() => { if (tab === 'findings') loadFindings() }, [filterProvider, filterSeverity])

  const CREDENTIAL_FIELDS: Record<string, Array<{ key: string; label: string; type?: string; placeholder?: string; help?: string }>> = {
    servicenow: [
      { key: 'instance_name', label: 'Instance Name (e.g., dev12345)' },
      { key: 'username', label: 'Username' },
      { key: 'password', label: 'Password', type: 'password' },
      { key: 'instance_region', label: 'Region (us/eu/ap)' },
    ],
    m365: [
      { key: 'tenant_id', label: 'Tenant ID (Directory ID)', placeholder: '72f988bf-86f1-41af-91ab-2d7cd011db47', help: 'Entra admin center > Overview > Tenant ID' },
      { key: 'client_id', label: 'Application (Client) ID', placeholder: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890', help: 'App registrations > Your App > Application (client) ID' },
      { key: 'client_secret', label: 'Client Secret Value', type: 'password', help: 'App registrations > Certificates and secrets > Value column (not the Secret ID)' },
      { key: 'tenant_location', label: 'Tenant Location (US/EU/AP)', placeholder: 'US', help: 'Geographic region of your Microsoft 365 tenant' },
    ],
    salesforce: [
      { key: 'client_id', label: 'Connected App Client ID' },
      { key: 'client_secret', label: 'Connected App Client Secret', type: 'password' },
      { key: 'username', label: 'Username (email)' },
      { key: 'password', label: 'Password', type: 'password' },
      { key: 'security_token', label: 'Security Token', type: 'password' },
      { key: 'instance_location', label: 'Instance Location (e.g., NA224)' },
      { key: 'api_version', label: 'API Version (e.g., v58.0)' },
    ],
    snowflake: [
      { key: 'username', label: 'Username' },
      { key: 'password', label: 'Password', type: 'password' },
      { key: 'account_id', label: 'Account ID (e.g., XXXX-YYYY)' },
      { key: 'warehouse_name', label: 'Warehouse Name' },
      { key: 'region', label: 'Region' },
    ],
    github: [
      { key: 'personal_access_token', label: 'Personal Access Token', type: 'password' },
      { key: 'organization', label: 'Organization (optional)' },
    ],
    google_workspace: [
      { key: 'service_account_json', label: 'Service Account Key (JSON)', type: 'password' },
      { key: 'delegated_admin_email', label: 'Delegated Admin Email' },
      { key: 'customer_id', label: 'Customer ID' },
    ],
    cloudflare: [
      { key: 'api_token', label: 'API Token', type: 'password' },
      { key: 'account_id', label: 'Account ID' },
    ],
    openstack: [
      { key: 'auth_url', label: 'Auth URL (Keystone endpoint)' },
      { key: 'username', label: 'Username' },
      { key: 'password', label: 'Password', type: 'password' },
      { key: 'project_name', label: 'Project Name' },
      { key: 'user_domain_name', label: 'User Domain Name' },
      { key: 'project_domain_name', label: 'Project Domain Name' },
    ],
  }

  const handleAddConnection = async () => {
    try {
      await api.createSaaSConnection({
        provider_type: providerType,
        alias,
        credentials: credFields,
      })
      toast.success('Connection added!')
      setShowAddModal(false)
      setAlias('')
      setCredFields({})
      loadData()
    } catch (err: any) {
      toast.error(err.message || 'Failed to add connection')
    }
  }

  const handleTestConnection = async (id: string) => {
    try {
      const result = await api.testSaaSConnection(id)
      if (result.success) {
        toast.success(result.message)
      } else {
        toast.error(result.message)
      }
      loadData()
    } catch (err: any) {
      toast.error(err.message)
    }
  }

  const handleDeleteConnection = async (id: string) => {
    if (!confirm('Delete this connection?')) return
    try {
      await api.deleteSaaSConnection(id)
      toast.success('Connection deleted')
      loadData()
    } catch (err: any) {
      toast.error(err.message)
    }
  }

  const handleStartScan = async (connectionId: string) => {
    try {
      await api.createScan({ scan_type: 'saas', connection_id: connectionId })
      toast.success('SaaS scan started!')
      loadData()
    } catch (err: any) {
      toast.error(err.message)
    }
  }

  const findingColumns = [
    {
      key: 'provider_type',
      header: 'Provider',
      render: (item: any) => (
        <span className="text-sm font-medium">{getSaaSLabel(item.provider_type)}</span>
      ),
    },
    {
      key: 'severity',
      header: 'Severity',
      render: (item: any) => <Badge type="severity" value={item.severity} />,
    },
    {
      key: 'status',
      header: 'Status',
      render: (item: any) => <Badge type="status" value={item.status} />,
    },
    { key: 'check_title', header: 'Check', className: 'max-w-sm' },
    { key: 'service_area', header: 'Area' },
    {
      key: 'resource_name',
      header: 'Resource',
      render: (item: any) => (
        <span className="text-brand-gray-600 truncate block max-w-36">
          {item.resource_name || item.resource_id || '-'}
        </span>
      ),
    },
    {
      key: 'created_at',
      header: 'Date',
      render: (item: any) => <span className="text-brand-gray-400 text-xs">{formatDate(item.created_at)}</span>,
    },
  ]

  return (
    <div>
      <Header
        title="SaaS Security"
        subtitle="Security posture management for SaaS applications"
        actions={
          <button onClick={() => setShowAddModal(true)} className="btn-primary flex items-center gap-2">
            <PlusIcon className="w-4 h-4" />
            Add Connection
          </button>
        }
      />

      {/* Tab navigation */}
      <div className="flex gap-1 mb-6 bg-brand-gray-100 rounded-lg p-1 w-fit">
        {(['overview', 'connections', 'findings'] as Tab[]).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
              tab === t
                ? 'bg-white text-brand-navy shadow-sm'
                : 'text-brand-gray-500 hover:text-brand-gray-700'
            }`}
          >
            {t.charAt(0).toUpperCase() + t.slice(1)}
          </button>
        ))}
      </div>

      {/* Overview Tab */}
      {tab === 'overview' && (
        <>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            <StatCard
              title="SaaS Connections"
              value={overview?.total_connections || 0}
              icon={<GlobeAltIcon className="w-6 h-6" />}
            />
            <StatCard
              title="Total Findings"
              value={overview?.total_findings || 0}
              icon={<ExclamationTriangleIcon className="w-6 h-6" />}
            />
            <StatCard
              title="Critical + High"
              value={(overview?.critical_findings || 0) + (overview?.high_findings || 0)}
              icon={<ShieldCheckIcon className="w-6 h-6" />}
              valueColor="text-status-fail"
            />
            <StatCard
              title="Pass Rate"
              value={formatPercent(overview?.pass_rate || 0)}
              icon={<CheckCircleIcon className="w-6 h-6" />}
              valueColor={
                (overview?.pass_rate || 0) >= 80 ? 'text-status-pass' :
                (overview?.pass_rate || 0) >= 50 ? 'text-status-pending' : 'text-status-fail'
              }
            />
          </div>

          {/* Provider Cards */}
          <h3 className="text-lg font-semibold text-brand-navy mb-4">SaaS Providers</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            {SAAS_PROVIDERS.map((provider) => {
              const providerData = overview?.by_provider?.[provider.id] || {}
              const total = providerData.total || 0
              const passed = providerData.passed || 0
              const failed = providerData.failed || 0
              const passRate = total > 0 ? (passed / total) * 100 : 0

              return (
                <div key={provider.id} className="card hover:shadow-md transition-shadow">
                  <div className="flex items-center gap-3 mb-4">
                    <div className={`w-10 h-10 rounded-lg ${provider.color} flex items-center justify-center`}>
                      <span className="text-white font-bold text-xs">{provider.icon}</span>
                    </div>
                    <div>
                      <h4 className="font-semibold text-brand-navy text-sm">{provider.name}</h4>
                      <p className="text-xs text-brand-gray-400">{provider.checks} checks</p>
                    </div>
                  </div>

                  {total > 0 ? (
                    <div className="space-y-2">
                      <div className="flex justify-between text-sm">
                        <span className="text-brand-gray-500">Findings</span>
                        <span className="font-medium text-brand-navy">{total}</span>
                      </div>
                      <div className="w-full bg-brand-gray-100 rounded-full h-2">
                        <div
                          className="bg-brand-green h-2 rounded-full"
                          style={{ width: `${passRate}%` }}
                        />
                      </div>
                      <div className="flex justify-between text-xs">
                        <span className="text-status-pass">{passed} passed</span>
                        <span className="text-status-fail">{failed} failed</span>
                      </div>
                    </div>
                  ) : (
                    <p className="text-xs text-brand-gray-400">No scans yet</p>
                  )}
                </div>
              )
            })}
          </div>

          {/* Severity Distribution */}
          <div className="card">
            <h3 className="text-lg font-semibold text-brand-navy mb-4">SaaS Severity Distribution</h3>
            <div className="grid grid-cols-5 gap-4">
              {['critical', 'high', 'medium', 'low', 'informational'].map((sev) => {
                const count = overview?.[`${sev}_findings`] || 0
                return (
                  <div key={sev} className="text-center">
                    <div className={`text-3xl font-bold ${
                      sev === 'critical' ? 'text-severity-critical' :
                      sev === 'high' ? 'text-severity-high' :
                      sev === 'medium' ? 'text-severity-medium' :
                      sev === 'low' ? 'text-severity-low' :
                      'text-severity-informational'
                    }`}>
                      {count}
                    </div>
                    <div className="text-xs text-brand-gray-400 mt-1 capitalize">{sev}</div>
                  </div>
                )
              })}
            </div>
          </div>
        </>
      )}

      {/* Connections Tab */}
      {tab === 'connections' && (
        <div className="space-y-4">
          {connections.length === 0 ? (
            <div className="card text-center py-12">
              <GlobeAltIcon className="w-12 h-12 text-brand-gray-300 mx-auto mb-4" />
              <p className="text-brand-gray-400 mb-4">No SaaS connections configured yet.</p>
              <button onClick={() => setShowAddModal(true)} className="btn-primary">
                Add your first connection
              </button>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {connections.map((conn) => {
                const prov = SAAS_PROVIDERS.find((p) => p.id === conn.provider_type)
                return (
                  <div key={conn.id} className="card hover:shadow-md transition-shadow">
                    <div className="flex items-start justify-between mb-4">
                      <div className="flex items-center gap-3">
                        <div className={`w-10 h-10 rounded-lg ${prov?.color || 'bg-brand-gray-400'} flex items-center justify-center`}>
                          <span className="text-white font-bold text-xs">{prov?.icon || '?'}</span>
                        </div>
                        <div>
                          <h3 className="font-semibold text-brand-navy">{conn.alias}</h3>
                          <p className="text-xs text-brand-gray-400">{prov?.name || conn.provider_type}</p>
                        </div>
                      </div>
                      <Badge type="status" value={conn.status} />
                    </div>

                    <div className="text-xs text-brand-gray-400 mb-4">
                      Last scan: {conn.last_scan_at ? formatDate(conn.last_scan_at) : 'Never'}
                    </div>

                    <div className="flex gap-2">
                      <button
                        onClick={() => handleTestConnection(conn.id)}
                        className="flex-1 flex items-center justify-center gap-1.5 px-3 py-2 text-xs font-medium border border-brand-gray-200 rounded-lg hover:bg-brand-gray-50 text-brand-gray-600"
                      >
                        <BeakerIcon className="w-3.5 h-3.5" />
                        Test
                      </button>
                      <button
                        onClick={() => handleStartScan(conn.id)}
                        className="flex-1 flex items-center justify-center gap-1.5 px-3 py-2 text-xs font-medium bg-brand-green text-white rounded-lg hover:bg-brand-green-dark"
                      >
                        <ArrowPathIcon className="w-3.5 h-3.5" />
                        Scan
                      </button>
                      <button
                        onClick={() => handleDeleteConnection(conn.id)}
                        className="px-3 py-2 text-xs border border-red-200 rounded-lg hover:bg-red-50 text-red-500"
                      >
                        <TrashIcon className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      )}

      {/* Findings Tab */}
      {tab === 'findings' && (
        <>
          <div className="flex gap-4 mb-6">
            <select
              value={filterProvider}
              onChange={(e) => setFilterProvider(e.target.value)}
              className="px-3 py-2 border border-brand-gray-300 rounded-lg text-sm"
            >
              <option value="">All Providers</option>
              {SAAS_PROVIDERS.map((p) => (
                <option key={p.id} value={p.id}>{p.name}</option>
              ))}
            </select>
            <select
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
              className="px-3 py-2 border border-brand-gray-300 rounded-lg text-sm"
            >
              <option value="">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>

          <DataTable
            columns={findingColumns}
            data={findings}
            loading={loading}
            emptyMessage="No SaaS findings yet. Add a connection and run a scan."
          />
        </>
      )}

      {/* Add Connection Modal */}
      {showAddModal && (
        <div className="modal-backdrop">
          <div className="bg-white rounded-xl shadow-xl p-6 w-full max-w-lg max-h-[90vh] overflow-y-auto">
            <h3 className="text-lg font-semibold text-brand-navy mb-4">Add SaaS Connection</h3>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">SaaS Provider</label>
                <div className="grid grid-cols-2 gap-2">
                  {SAAS_PROVIDERS.map((p) => (
                    <button
                      key={p.id}
                      onClick={() => { setProviderType(p.id); setCredFields({}) }}
                      className={`flex items-center gap-2 p-3 rounded-lg border-2 text-sm font-medium transition-colors ${
                        providerType === p.id
                          ? 'border-brand-green bg-brand-green/5 text-brand-green'
                          : 'border-brand-gray-200 text-brand-gray-500 hover:border-brand-gray-300'
                      }`}
                    >
                      <div className={`w-6 h-6 rounded ${p.color} flex items-center justify-center`}>
                        <span className="text-white text-[8px] font-bold">{p.icon}</span>
                      </div>
                      {p.name}
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Connection Name</label>
                <input
                  type="text"
                  value={alias}
                  onChange={(e) => setAlias(e.target.value)}
                  className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm"
                  placeholder="e.g., Production ServiceNow"
                />
              </div>

              <div className="border-t border-brand-gray-200 pt-4">
                <p className="text-sm font-medium text-brand-gray-700 mb-3">Credentials</p>
                <div className="space-y-3">
                  {(CREDENTIAL_FIELDS[providerType] || []).map((field) => (
                    <div key={field.key}>
                      <label className="block text-xs font-medium text-brand-gray-500 mb-1">
                        {field.label}
                      </label>
                      <input
                        type={field.type || 'text'}
                        placeholder={field.placeholder || ''}
                        value={credFields[field.key] || ''}
                        onChange={(e) => setCredFields({ ...credFields, [field.key]: e.target.value })}
                        className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm"
                      />
                      {field.help && (
                        <p className="text-xs text-brand-gray-400 mt-1">{field.help}</p>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className="flex gap-3 mt-6">
              <button onClick={() => setShowAddModal(false)} className="flex-1 btn-outline">Cancel</button>
              <button
                onClick={handleAddConnection}
                disabled={!alias}
                className="flex-1 btn-primary disabled:opacity-50"
              >
                Add Connection
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
