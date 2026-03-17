'use client'

import { useEffect, useState } from 'react'
import Header from '@/components/layout/Header'
import Badge from '@/components/ui/Badge'
import { api } from '@/lib/api'
import { formatDate } from '@/lib/utils'
import toast from 'react-hot-toast'
import { TrashIcon, PlusIcon, BuildingOffice2Icon, UserIcon, MagnifyingGlassIcon, ChevronDownIcon, ChevronRightIcon } from '@heroicons/react/24/outline'

const PROVIDER_TYPES = [
  { id: 'aws', name: 'Amazon Web Services', color: 'bg-[#FF9900]' },
  { id: 'azure', name: 'Microsoft Azure', color: 'bg-[#0078D4]' },
  { id: 'gcp', name: 'Google Cloud Platform', color: 'bg-[#4285F4]' },
  { id: 'oci', name: 'Oracle Cloud Infrastructure', color: 'bg-[#C74634]' },
  { id: 'alibaba', name: 'Alibaba Cloud', color: 'bg-[#FF6A00]' },
  { id: 'kubernetes', name: 'Kubernetes', color: 'bg-[#326CE5]' },
]

export default function ProvidersPage() {
  const [providers, setProviders] = useState<any[]>([])
  const [childAccounts, setChildAccounts] = useState<Record<string, any[]>>({})
  const [loading, setLoading] = useState(true)
  const [showModal, setShowModal] = useState(false)
  const [expandedProviders, setExpandedProviders] = useState<Set<string>>(new Set())
  const [discoveringAccounts, setDiscoveringAccounts] = useState<string | null>(null)
  const [discoveredAccounts, setDiscoveredAccounts] = useState<any[]>([])
  const [showDiscoverModal, setShowDiscoverModal] = useState(false)
  const [form, setForm] = useState({
    provider_type: 'aws',
    alias: '',
    access_key_id: '',
    secret_access_key: '',
    session_token: '',
    subscription_id: '',
    tenant_id: '',
    client_id: '',
    client_secret: '',
    project_id: '',
    service_account_key: '',
    tenancy_ocid: '',
    user_ocid: '',
    fingerprint: '',
    private_key: '',
    kubeconfig: '',
    region: '',
    alibaba_access_key_id: '',
    alibaba_access_key_secret: '',
    account_type: 'single',
  })

  const loadProviders = async () => {
    try {
      const data = await api.getProviders()
      setProviders(data)

      // Load child accounts for management/organization providers
      const children: Record<string, any[]> = {}
      for (const p of data) {
        if (p.is_management_account) {
          try {
            children[p.id] = await api.getChildAccounts(p.id)
          } catch {
            children[p.id] = []
          }
        }
      }
      setChildAccounts(children)
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { loadProviders() }, [])

  const handleCreate = async () => {
    try {
      let credentials: any = {}
      switch (form.provider_type) {
        case 'aws':
          credentials = {
            access_key_id: form.access_key_id,
            secret_access_key: form.secret_access_key,
            session_token: form.session_token || undefined,
          }
          break
        case 'azure':
          credentials = {
            subscription_id: form.subscription_id,
            tenant_id: form.tenant_id,
            client_id: form.client_id,
            client_secret: form.client_secret,
          }
          break
        case 'gcp':
          credentials = {
            project_id: form.project_id,
            service_account_key: form.service_account_key,
          }
          break
        case 'oci':
          credentials = {
            tenancy_ocid: form.tenancy_ocid,
            user_ocid: form.user_ocid,
            fingerprint: form.fingerprint,
            private_key: form.private_key,
          }
          break
        case 'alibaba':
          credentials = {
            access_key_id: form.alibaba_access_key_id,
            access_key_secret: form.alibaba_access_key_secret,
          }
          break
        case 'kubernetes':
          credentials = { kubeconfig: form.kubeconfig }
          break
      }

      const newProvider = await api.createProvider({
        provider_type: form.provider_type,
        alias: form.alias,
        credentials,
        region: form.region || undefined,
        account_type: form.account_type,
      })
      toast.success('Provider added!')
      setShowModal(false)

      // If it's an organization account, prompt to discover accounts
      if (form.account_type === 'organization') {
        handleDiscoverAccounts(newProvider.id)
      }

      loadProviders()
    } catch (err: any) {
      toast.error(err.message || 'Failed to add provider')
    }
  }

  const handleDelete = async (id: string) => {
    if (!confirm('Delete this provider?')) return
    try {
      await api.deleteProvider(id)
      toast.success('Provider deleted')
      loadProviders()
    } catch (err: any) {
      toast.error(err.message)
    }
  }

  const handleDiscoverAccounts = async (providerId: string) => {
    setDiscoveringAccounts(providerId)
    try {
      const accounts = await api.discoverAccounts(providerId)
      setDiscoveredAccounts(accounts)
      setShowDiscoverModal(true)
    } catch (err: any) {
      toast.error(err.message || 'Failed to discover accounts')
    } finally {
      setDiscoveringAccounts(null)
    }
  }

  const toggleProviderExpand = (providerId: string) => {
    setExpandedProviders((prev) => {
      const next = new Set(prev)
      if (next.has(providerId)) {
        next.delete(providerId)
      } else {
        next.add(providerId)
      }
      return next
    })
  }

  // Filter out child accounts from the top-level grid (show only parents / standalone)
  const topLevelProviders = providers.filter((p) => !p.parent_provider_id)

  return (
    <div>
      <Header
        title="Cloud Providers"
        subtitle="Manage cloud provider connections for security scanning"
        actions={
          <button onClick={() => setShowModal(true)} className="btn-primary flex items-center gap-2">
            <PlusIcon className="w-4 h-4" />
            Add Provider
          </button>
        }
      />

      {loading ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {[...Array(3)].map((_, i) => (
            <div key={i} className="card animate-pulse"><div className="h-28 bg-brand-gray-100 rounded" /></div>
          ))}
        </div>
      ) : providers.length === 0 ? (
        <div className="card text-center py-12">
          <p className="text-brand-gray-400 mb-4">No cloud providers configured yet.</p>
          <button onClick={() => setShowModal(true)} className="btn-primary">Add your first provider</button>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {topLevelProviders.map((p) => {
            const ptype = PROVIDER_TYPES.find((t) => t.id === p.provider_type)
            const isManagement = p.is_management_account
            const children = childAccounts[p.id] || []
            const isExpanded = expandedProviders.has(p.id)

            return (
              <div key={p.id} className="space-y-0">
                <div className={`card hover:shadow-md transition-shadow ${isManagement ? 'border-l-4 border-l-brand-green' : ''}`}>
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-3">
                      <div className={`w-10 h-10 rounded-lg ${ptype?.color || 'bg-brand-gray-400'} flex items-center justify-center`}>
                        <span className="text-white font-bold text-sm">{p.provider_type.slice(0, 3).toUpperCase()}</span>
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <h3 className="font-semibold text-brand-navy">{p.alias}</h3>
                          {isManagement ? (
                            <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-xs font-medium bg-brand-green/10 text-brand-green">
                              <BuildingOffice2Icon className="w-3 h-3" />
                              Org
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-xs font-medium bg-brand-gray-100 text-brand-gray-500">
                              <UserIcon className="w-3 h-3" />
                              Single
                            </span>
                          )}
                        </div>
                        <p className="text-xs text-brand-gray-400">{ptype?.name || p.provider_type}</p>
                      </div>
                    </div>
                    <button onClick={() => handleDelete(p.id)} className="p-1.5 rounded-lg hover:bg-red-50 text-brand-gray-400 hover:text-red-500">
                      <TrashIcon className="w-4 h-4" />
                    </button>
                  </div>

                  <div className="flex items-center justify-between mt-4">
                    <Badge type="status" value={p.status} />
                    <span className="text-xs text-brand-gray-400">{formatDate(p.created_at)}</span>
                  </div>

                  {/* Management account actions */}
                  {isManagement && (
                    <div className="mt-4 pt-3 border-t border-brand-gray-100 flex items-center justify-between">
                      <button
                        onClick={() => handleDiscoverAccounts(p.id)}
                        disabled={discoveringAccounts === p.id}
                        className="flex items-center gap-1.5 text-xs font-medium text-brand-green hover:text-brand-green/80 disabled:opacity-50"
                      >
                        <MagnifyingGlassIcon className="w-3.5 h-3.5" />
                        {discoveringAccounts === p.id ? 'Discovering...' : 'Discover Accounts'}
                      </button>
                      {children.length > 0 && (
                        <button
                          onClick={() => toggleProviderExpand(p.id)}
                          className="flex items-center gap-1 text-xs text-brand-gray-500 hover:text-brand-navy"
                        >
                          {isExpanded ? (
                            <ChevronDownIcon className="w-3.5 h-3.5" />
                          ) : (
                            <ChevronRightIcon className="w-3.5 h-3.5" />
                          )}
                          {children.length} child account{children.length !== 1 ? 's' : ''}
                        </button>
                      )}
                    </div>
                  )}
                </div>

                {/* Child accounts nested under parent */}
                {isManagement && isExpanded && children.length > 0 && (
                  <div className="ml-4 mt-2 space-y-2">
                    {children.map((child) => {
                      const ctype = PROVIDER_TYPES.find((t) => t.id === child.provider_type)
                      return (
                        <div key={child.id} className="card py-3 px-4 border-l-4 border-l-brand-gray-300">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2">
                              <div className={`w-7 h-7 rounded ${ctype?.color || 'bg-brand-gray-400'} flex items-center justify-center`}>
                                <span className="text-white font-bold text-[10px]">{child.provider_type.slice(0, 3).toUpperCase()}</span>
                              </div>
                              <div>
                                <p className="text-sm font-medium text-brand-navy">{child.alias}</p>
                                <p className="text-xs text-brand-gray-400 font-mono">{child.account_id || 'No account ID'}</p>
                              </div>
                            </div>
                            <div className="flex items-center gap-2">
                              <Badge type="status" value={child.status} />
                              <button onClick={() => handleDelete(child.id)} className="p-1 rounded hover:bg-red-50 text-brand-gray-400 hover:text-red-500">
                                <TrashIcon className="w-3.5 h-3.5" />
                              </button>
                            </div>
                          </div>
                        </div>
                      )
                    })}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}

      {/* Add Provider Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="bg-white rounded-xl shadow-xl p-6 w-full max-w-lg max-h-[90vh] overflow-y-auto">
            <h3 className="text-lg font-semibold text-brand-navy mb-4">Add Cloud Provider</h3>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Provider Type</label>
                <select
                  value={form.provider_type}
                  onChange={(e) => setForm({ ...form, provider_type: e.target.value })}
                  className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm"
                >
                  {PROVIDER_TYPES.map((t) => (
                    <option key={t.id} value={t.id}>{t.name}</option>
                  ))}
                </select>
              </div>

              {form.provider_type !== 'kubernetes' && (
                <div>
                  <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Account Type</label>
                  <div className="grid grid-cols-2 gap-2">
                    {[
                      { id: 'single', label: 'Single Account', desc: 'Scan a single account or subscription' },
                      { id: 'organization', label: 'Organization', desc: 'Management/root account with child accounts' },
                    ].map((at) => (
                      <button
                        key={at.id}
                        onClick={() => setForm({ ...form, account_type: at.id })}
                        className={`p-3 rounded-lg border-2 text-left transition-colors ${
                          form.account_type === at.id
                            ? 'border-brand-green bg-brand-green/5'
                            : 'border-brand-gray-200 hover:border-brand-gray-300'
                        }`}
                      >
                        <span className="text-sm font-medium text-brand-navy">{at.label}</span>
                        <p className="text-xs text-brand-gray-400 mt-0.5">{at.desc}</p>
                      </button>
                    ))}
                  </div>
                </div>
              )}

              <div>
                <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Alias</label>
                <input
                  type="text"
                  value={form.alias}
                  onChange={(e) => setForm({ ...form, alias: e.target.value })}
                  className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm"
                  placeholder="e.g., Production AWS"
                />
              </div>

              {form.provider_type === 'aws' && (
                <>
                  <div>
                    <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Access Key ID</label>
                    <input type="text" value={form.access_key_id} onChange={(e) => setForm({ ...form, access_key_id: e.target.value })} className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm" />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Secret Access Key</label>
                    <input type="password" value={form.secret_access_key} onChange={(e) => setForm({ ...form, secret_access_key: e.target.value })} className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm" />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Region</label>
                    <input type="text" value={form.region} onChange={(e) => setForm({ ...form, region: e.target.value })} placeholder="us-east-1" className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm" />
                  </div>
                </>
              )}

              {form.provider_type === 'azure' && (
                <>
                  <div>
                    <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Subscription ID</label>
                    <input type="text" value={form.subscription_id} onChange={(e) => setForm({ ...form, subscription_id: e.target.value })} className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm" />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Tenant ID</label>
                    <input type="text" value={form.tenant_id} onChange={(e) => setForm({ ...form, tenant_id: e.target.value })} className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm" />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Client ID</label>
                    <input type="text" value={form.client_id} onChange={(e) => setForm({ ...form, client_id: e.target.value })} className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm" />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Client Secret</label>
                    <input type="password" value={form.client_secret} onChange={(e) => setForm({ ...form, client_secret: e.target.value })} className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm" />
                  </div>
                </>
              )}

              {form.provider_type === 'gcp' && (
                <>
                  <div>
                    <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Project ID</label>
                    <input type="text" value={form.project_id} onChange={(e) => setForm({ ...form, project_id: e.target.value })} className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm" />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Service Account Key (JSON)</label>
                    <textarea value={form.service_account_key} onChange={(e) => setForm({ ...form, service_account_key: e.target.value })} rows={4} className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm font-mono" placeholder='{"type": "service_account", ...}' />
                  </div>
                </>
              )}

              {form.provider_type === 'oci' && (
                <>
                  <div>
                    <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Tenancy OCID</label>
                    <input type="text" value={form.tenancy_ocid} onChange={(e) => setForm({ ...form, tenancy_ocid: e.target.value })} className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm" placeholder="ocid1.tenancy.oc1.." />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">User OCID</label>
                    <input type="text" value={form.user_ocid} onChange={(e) => setForm({ ...form, user_ocid: e.target.value })} className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm" placeholder="ocid1.user.oc1.." />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">API Key Fingerprint</label>
                    <input type="text" value={form.fingerprint} onChange={(e) => setForm({ ...form, fingerprint: e.target.value })} className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm" placeholder="aa:bb:cc:..." />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Private Key (PEM)</label>
                    <textarea value={form.private_key} onChange={(e) => setForm({ ...form, private_key: e.target.value })} rows={4} className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm font-mono" placeholder="-----BEGIN RSA PRIVATE KEY-----" />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Region</label>
                    <input type="text" value={form.region} onChange={(e) => setForm({ ...form, region: e.target.value })} placeholder="us-ashburn-1" className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm" />
                  </div>
                </>
              )}

              {form.provider_type === 'alibaba' && (
                <>
                  <div>
                    <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Access Key ID</label>
                    <input type="text" value={form.alibaba_access_key_id} onChange={(e) => setForm({ ...form, alibaba_access_key_id: e.target.value })} className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm" />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Access Key Secret</label>
                    <input type="password" value={form.alibaba_access_key_secret} onChange={(e) => setForm({ ...form, alibaba_access_key_secret: e.target.value })} className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm" />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Region</label>
                    <input type="text" value={form.region} onChange={(e) => setForm({ ...form, region: e.target.value })} placeholder="cn-hangzhou" className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm" />
                  </div>
                </>
              )}

              {form.provider_type === 'kubernetes' && (
                <div>
                  <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Kubeconfig (YAML)</label>
                  <textarea value={form.kubeconfig} onChange={(e) => setForm({ ...form, kubeconfig: e.target.value })} rows={6} className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm font-mono" placeholder="apiVersion: v1..." />
                </div>
              )}
            </div>

            <div className="flex gap-3 mt-6">
              <button onClick={() => setShowModal(false)} className="flex-1 btn-outline">Cancel</button>
              <button onClick={handleCreate} disabled={!form.alias} className="flex-1 btn-primary disabled:opacity-50">Add Provider</button>
            </div>
          </div>
        </div>
      )}

      {/* Discover Accounts Modal */}
      {showDiscoverModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="bg-white rounded-xl shadow-xl p-6 w-full max-w-lg max-h-[90vh] overflow-y-auto">
            <h3 className="text-lg font-semibold text-brand-navy mb-2">Discovered Accounts</h3>
            <p className="text-sm text-brand-gray-400 mb-4">
              The following child accounts/subscriptions were discovered under this organization.
            </p>

            {discoveredAccounts.length === 0 ? (
              <div className="text-center py-8">
                <p className="text-brand-gray-400">No child accounts discovered.</p>
              </div>
            ) : (
              <div className="space-y-3">
                {discoveredAccounts.map((acct, idx) => (
                  <div key={idx} className="flex items-center justify-between p-3 bg-brand-gray-50 rounded-lg">
                    <div>
                      <p className="text-sm font-medium text-brand-navy">{acct.name}</p>
                      <p className="text-xs text-brand-gray-400 font-mono">{acct.account_id}</p>
                    </div>
                    <span className={`inline-block px-2 py-0.5 rounded-full text-xs font-medium ${acct.status === 'active' ? 'bg-green-100 text-green-800' : 'bg-yellow-100 text-yellow-800'}`}>
                      {acct.status}
                    </span>
                  </div>
                ))}
              </div>
            )}

            <div className="flex gap-3 mt-6">
              <button
                onClick={() => {
                  setShowDiscoverModal(false)
                  setDiscoveredAccounts([])
                }}
                className="flex-1 btn-primary"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
