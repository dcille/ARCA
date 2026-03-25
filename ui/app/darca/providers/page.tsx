'use client'

import { useEffect, useState } from 'react'
import Header from '@/components/layout/Header'
import Badge from '@/components/ui/Badge'
import { api } from '@/lib/api'
import { formatDate } from '@/lib/utils'
import toast from 'react-hot-toast'
import { useRouter } from 'next/navigation'
import { TrashIcon, PlusIcon, BuildingOffice2Icon, UserIcon, MagnifyingGlassIcon, ChevronDownIcon, ChevronRightIcon, PencilSquareIcon, ChartBarSquareIcon } from '@heroicons/react/24/outline'

const PROVIDER_TYPES = [
  { id: 'aws', name: 'Amazon Web Services', color: 'bg-[#FF9900]' },
  { id: 'azure', name: 'Microsoft Azure', color: 'bg-[#0078D4]' },
  { id: 'gcp', name: 'Google Cloud Platform', color: 'bg-[#4285F4]' },
  { id: 'oci', name: 'Oracle Cloud Infrastructure', color: 'bg-[#C74634]' },
  { id: 'alibaba', name: 'Alibaba Cloud', color: 'bg-[#FF6A00]' },
  { id: 'ibm_cloud', name: 'IBM Cloud', color: 'bg-[#054ADA]' },
  { id: 'kubernetes', name: 'Kubernetes', color: 'bg-[#326CE5]' },
]

const SETUP_INSTRUCTIONS: Record<string, { title: string; steps: string[]; permissions: string; docsUrl: string }> = {
  aws: {
    title: 'AWS IAM Setup',
    steps: [
      'Go to AWS IAM Console > Users > Create user',
      'Attach the ReadOnlyAccess managed policy (or SecurityAudit for minimal access)',
      'Create an Access Key under Security credentials > Access keys',
      'Copy the Access Key ID and Secret Access Key',
      'For Organizations: use a management account with OrganizationsReadOnlyAccess',
    ],
    permissions: 'Required: ReadOnlyAccess or SecurityAudit. For Organizations: OrganizationsReadOnlyAccess',
    docsUrl: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html',
  },
  azure: {
    title: 'Azure App Registration Setup',
    steps: [
      'Go to Azure Portal > Azure Active Directory > App registrations > New registration',
      'Note the Application (Client) ID and Directory (Tenant) ID',
      'Go to Certificates & secrets > New client secret — copy the value',
      'Go to the Subscription > Access control (IAM) > Add role assignment',
      'Assign the Reader role to the App registration for the target subscription',
    ],
    permissions: 'Required: Reader role on the subscription. For Security Center: Security Reader',
    docsUrl: 'https://learn.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app',
  },
  gcp: {
    title: 'GCP Service Account Setup',
    steps: [
      'Go to GCP Console > IAM & Admin > Service Accounts > Create Service Account',
      'Grant the Viewer role (roles/viewer) to the service account',
      'Go to Keys > Add Key > Create new key > JSON',
      'Download the JSON key file and paste its contents below',
      'Note the Project ID from the GCP Console dashboard',
    ],
    permissions: 'Required: roles/viewer (Viewer). For GKE: roles/container.clusterViewer',
    docsUrl: 'https://cloud.google.com/iam/docs/service-accounts-create',
  },
  oci: {
    title: 'OCI API Key Setup',
    steps: [
      'Go to OCI Console > Identity & Security > Users > Your user > API Keys',
      'Click Add API Key > Generate API Key Pair > Download Private Key',
      'Note the Tenancy OCID (Administration > Tenancy details)',
      'Note the User OCID (Profile > My profile)',
      'Copy the fingerprint displayed after adding the key',
    ],
    permissions: 'Required: Inspector or Auditor group membership in IAM policies',
    docsUrl: 'https://docs.oracle.com/en-us/iaas/Content/API/Concepts/apisigningkey.htm',
  },
  alibaba: {
    title: 'Alibaba Cloud RAM Setup',
    steps: [
      'Go to Alibaba Cloud Console > RAM > Users > Create User',
      'Enable Programmatic Access to generate an AccessKey',
      'Attach the AliyunReadOnlyAccess system policy',
      'Copy the AccessKey ID and AccessKey Secret (shown only once)',
    ],
    permissions: 'Required: AliyunReadOnlyAccess or custom read-only policy',
    docsUrl: 'https://www.alibabacloud.com/help/en/ram/user-guide/create-a-ram-user',
  },
  ibm_cloud: {
    title: 'IBM Cloud IAM Setup',
    steps: [
      'Go to IBM Cloud Console > Manage > Access (IAM) > API keys',
      'Click Create an IBM Cloud API key and provide a name/description',
      'Copy the API key (shown only once — save it securely)',
      'Note your Account ID from Manage > Account > Account settings',
      'Ensure the API key owner has Viewer and Service Reader roles on target services',
    ],
    permissions: 'Required: Viewer and Service Reader roles on target services. For enterprise: Enterprise Reader',
    docsUrl: 'https://cloud.ibm.com/docs/account?topic=account-userapikey',
  },
  kubernetes: {
    title: 'Kubernetes Kubeconfig Setup',
    steps: [
      'Run: kubectl config view --raw > kubeconfig.yaml',
      'Ensure the context in the kubeconfig has cluster-reader or view ClusterRole',
      'For EKS: aws eks update-kubeconfig --name <cluster>',
      'For GKE: gcloud container clusters get-credentials <cluster>',
      'For AKS: az aks get-credentials --resource-group <rg> --name <cluster>',
    ],
    permissions: 'Required: ClusterRole with get/list/watch on pods, services, namespaces, RBAC',
    docsUrl: 'https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/',
  },
}

export default function ProvidersPage() {
  const router = useRouter()
  const [providers, setProviders] = useState<any[]>([])
  const [childAccounts, setChildAccounts] = useState<Record<string, any[]>>({})
  const [loading, setLoading] = useState(true)
  const [showModal, setShowModal] = useState(false)
  const [wizardStep, setWizardStep] = useState(0) // 0=select, 1=instructions, 2=credentials
  const [showEditModal, setShowEditModal] = useState(false)
  const [editingProvider, setEditingProvider] = useState<any>(null)
  const [editForm, setEditForm] = useState<any>({})
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
    ibm_api_key: '',
    ibm_account_id: '',
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
        case 'ibm_cloud':
          credentials = {
            api_key: form.ibm_api_key,
            account_id: form.ibm_account_id || undefined,
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

  const openEditModal = (provider: any) => {
    setEditingProvider(provider)
    setEditForm({
      alias: provider.alias || '',
      region: provider.region || '',
      // Credential fields start empty — only filled values will be sent
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
      alibaba_access_key_id: '',
      alibaba_access_key_secret: '',
      ibm_api_key: '',
      ibm_account_id: '',
    })
    setShowEditModal(true)
  }

  const handleEdit = async () => {
    if (!editingProvider) return
    try {
      const update: any = { alias: editForm.alias, region: editForm.region || undefined }

      // Only include credentials if the user filled in any credential field
      let credentials: any = {}
      let hasCredentials = false
      switch (editingProvider.provider_type) {
        case 'aws':
          if (editForm.access_key_id && editForm.secret_access_key) {
            credentials = {
              access_key_id: editForm.access_key_id,
              secret_access_key: editForm.secret_access_key,
              session_token: editForm.session_token || undefined,
            }
            hasCredentials = true
          }
          break
        case 'azure':
          if (editForm.client_id && editForm.client_secret) {
            credentials = {
              subscription_id: editForm.subscription_id,
              tenant_id: editForm.tenant_id,
              client_id: editForm.client_id,
              client_secret: editForm.client_secret,
            }
            hasCredentials = true
          }
          break
        case 'gcp':
          if (editForm.project_id || editForm.service_account_key) {
            credentials = {
              project_id: editForm.project_id,
              service_account_key: editForm.service_account_key,
            }
            hasCredentials = true
          }
          break
        case 'oci':
          if (editForm.tenancy_ocid && editForm.private_key) {
            credentials = {
              tenancy_ocid: editForm.tenancy_ocid,
              user_ocid: editForm.user_ocid,
              fingerprint: editForm.fingerprint,
              private_key: editForm.private_key,
            }
            hasCredentials = true
          }
          break
        case 'alibaba':
          if (editForm.alibaba_access_key_id && editForm.alibaba_access_key_secret) {
            credentials = {
              access_key_id: editForm.alibaba_access_key_id,
              access_key_secret: editForm.alibaba_access_key_secret,
            }
            hasCredentials = true
          }
          break
        case 'ibm_cloud':
          if (editForm.ibm_api_key) {
            credentials = {
              api_key: editForm.ibm_api_key,
              account_id: editForm.ibm_account_id || undefined,
            }
            hasCredentials = true
          }
          break
        case 'kubernetes':
          if (editForm.kubeconfig) {
            credentials = { kubeconfig: editForm.kubeconfig }
            hasCredentials = true
          }
          break
      }
      if (hasCredentials) update.credentials = credentials

      await api.updateProvider(editingProvider.id, update)
      toast.success('Provider updated!')
      setShowEditModal(false)
      setEditingProvider(null)
      loadProviders()
    } catch (err: any) {
      toast.error(err.message || 'Failed to update provider')
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
          <button onClick={() => { setShowModal(true); setWizardStep(0) }} className="btn-primary flex items-center gap-2">
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
          <button onClick={() => { setShowModal(true); setWizardStep(0) }} className="btn-primary">Add your first provider</button>
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
                    <div className="flex items-center gap-1">
                      <button onClick={() => router.push(`/darca/providers/${p.id}/dashboard`)} className="p-1.5 rounded-lg hover:bg-green-50 text-brand-gray-400 hover:text-brand-green" title="Account dashboard">
                        <ChartBarSquareIcon className="w-4 h-4" />
                      </button>
                      <button onClick={() => openEditModal(p)} className="p-1.5 rounded-lg hover:bg-blue-50 text-brand-gray-400 hover:text-blue-500" title="Edit provider">
                        <PencilSquareIcon className="w-4 h-4" />
                      </button>
                      <button onClick={() => handleDelete(p.id)} className="p-1.5 rounded-lg hover:bg-red-50 text-brand-gray-400 hover:text-red-500" title="Delete provider">
                        <TrashIcon className="w-4 h-4" />
                      </button>
                    </div>
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

      {/* Add Provider Wizard */}
      {showModal && (
        <div className="modal-backdrop">
          <div className="bg-white rounded-xl shadow-xl p-6 w-full max-w-lg max-h-[90vh] overflow-y-auto">
            {/* Wizard progress */}
            <div className="flex items-center gap-2 mb-6">
              {['Select Provider', 'Setup Guide', 'Credentials'].map((label, idx) => (
                <div key={label} className="flex items-center gap-2 flex-1">
                  <div className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold ${
                    idx < wizardStep ? 'bg-brand-green text-white' :
                    idx === wizardStep ? 'bg-brand-navy text-white' :
                    'bg-brand-gray-200 text-brand-gray-400'
                  }`}>
                    {idx < wizardStep ? '\u2713' : idx + 1}
                  </div>
                  <span className={`text-xs font-medium ${idx === wizardStep ? 'text-brand-navy' : 'text-brand-gray-400'}`}>{label}</span>
                  {idx < 2 && <div className="flex-1 h-px bg-brand-gray-200" />}
                </div>
              ))}
            </div>

            {/* Step 0: Select Provider */}
            {wizardStep === 0 && (
              <div>
                <h3 className="text-lg font-semibold text-brand-navy mb-2">Select Cloud Provider</h3>
                <p className="text-sm text-brand-gray-400 mb-4">Choose the cloud platform you want to connect for security scanning.</p>
                <div className="grid grid-cols-2 gap-3">
                  {PROVIDER_TYPES.map((t) => (
                    <button
                      key={t.id}
                      onClick={() => { setForm({ ...form, provider_type: t.id }); setWizardStep(1) }}
                      className={`p-4 rounded-lg border-2 text-left transition-all hover:shadow-md ${
                        form.provider_type === t.id ? 'border-brand-green bg-brand-green/5' : 'border-brand-gray-200 hover:border-brand-gray-300'
                      }`}
                    >
                      <div className={`w-10 h-10 rounded-lg ${t.color} flex items-center justify-center mb-2`}>
                        <span className="text-white font-bold text-sm">{t.id.slice(0, 3).toUpperCase()}</span>
                      </div>
                      <span className="text-sm font-medium text-brand-navy">{t.name}</span>
                    </button>
                  ))}
                </div>
                <div className="flex gap-3 mt-6">
                  <button onClick={() => { setShowModal(false); setWizardStep(0) }} className="flex-1 btn-outline">Cancel</button>
                </div>
              </div>
            )}

            {/* Step 1: Setup Instructions */}
            {wizardStep === 1 && (() => {
              const instructions = SETUP_INSTRUCTIONS[form.provider_type]
              return (
                <div>
                  <h3 className="text-lg font-semibold text-brand-navy mb-2">{instructions?.title || 'Setup Guide'}</h3>
                  <p className="text-sm text-brand-gray-400 mb-4">Follow these steps to prepare your credentials before connecting.</p>

                  <div className="space-y-3 mb-4">
                    {instructions?.steps.map((step, idx) => (
                      <div key={idx} className="flex gap-3 items-start">
                        <div className="w-6 h-6 rounded-full bg-brand-navy/10 flex items-center justify-center flex-shrink-0 mt-0.5">
                          <span className="text-xs font-bold text-brand-navy">{idx + 1}</span>
                        </div>
                        <p className="text-sm text-brand-gray-700">{step}</p>
                      </div>
                    ))}
                  </div>

                  {instructions?.permissions && (
                    <div className="bg-amber-50 border border-amber-200 rounded-lg p-3 mb-4">
                      <p className="text-xs font-semibold text-amber-700 mb-1">Required Permissions</p>
                      <p className="text-xs text-amber-600">{instructions.permissions}</p>
                    </div>
                  )}

                  {instructions?.docsUrl && (
                    <a
                      href={instructions.docsUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 text-sm text-brand-green hover:underline mb-4"
                    >
                      View official documentation &rarr;
                    </a>
                  )}

                  <div className="flex gap-3 mt-6">
                    <button onClick={() => setWizardStep(0)} className="flex-1 btn-outline">Back</button>
                    <button onClick={() => setWizardStep(2)} className="flex-1 btn-primary">I have my credentials</button>
                  </div>
                </div>
              )
            })()}

            {/* Step 2: Credentials */}
            {wizardStep === 2 && (
              <div>
                <h3 className="text-lg font-semibold text-brand-navy mb-4">Enter Credentials</h3>

                <div className="space-y-4">
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

                  {form.provider_type === 'ibm_cloud' && (
                    <>
                      <div>
                        <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">API Key</label>
                        <input type="password" value={form.ibm_api_key} onChange={(e) => setForm({ ...form, ibm_api_key: e.target.value })} className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm" />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Account ID <span className="text-brand-gray-400 font-normal">(optional)</span></label>
                        <input type="text" value={form.ibm_account_id} onChange={(e) => setForm({ ...form, ibm_account_id: e.target.value })} className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm" />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Region</label>
                        <input type="text" value={form.region} onChange={(e) => setForm({ ...form, region: e.target.value })} placeholder="us-south" className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm" />
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
                  <button onClick={() => setWizardStep(1)} className="flex-1 btn-outline">Back</button>
                  <button onClick={handleCreate} disabled={!form.alias} className="flex-1 btn-primary disabled:opacity-50">Add Provider</button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Edit Provider Modal */}
      {showEditModal && editingProvider && (
        <div className="modal-backdrop">
          <div className="bg-white rounded-xl shadow-xl p-6 w-full max-w-lg max-h-[90vh] overflow-y-auto">
            <h3 className="text-lg font-semibold text-brand-navy mb-1">Edit Provider</h3>
            <p className="text-xs text-brand-gray-400 mb-4">
              Update alias, region, or credentials for <strong>{editingProvider.alias}</strong> ({editingProvider.provider_type?.toUpperCase()}).
              Leave credential fields empty to keep existing values.
            </p>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Alias</label>
                <input
                  type="text"
                  value={editForm.alias}
                  onChange={(e) => setEditForm({ ...editForm, alias: e.target.value })}
                  className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm"
                />
              </div>

              {editingProvider.provider_type === 'aws' && (
                <>
                  <div>
                    <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Access Key ID <span className="text-brand-gray-400 font-normal">(leave empty to keep)</span></label>
                    <input type="text" value={editForm.access_key_id} onChange={(e) => setEditForm({ ...editForm, access_key_id: e.target.value })} className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm" placeholder="••••••••" />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Secret Access Key <span className="text-brand-gray-400 font-normal">(leave empty to keep)</span></label>
                    <input type="password" value={editForm.secret_access_key} onChange={(e) => setEditForm({ ...editForm, secret_access_key: e.target.value })} className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm" placeholder="••••••••" />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Region</label>
                    <input type="text" value={editForm.region} onChange={(e) => setEditForm({ ...editForm, region: e.target.value })} placeholder="us-east-1" className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm" />
                  </div>
                </>
              )}

              {editingProvider.provider_type === 'azure' && (
                <>
                  <div>
                    <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Subscription ID</label>
                    <input type="text" value={editForm.subscription_id} onChange={(e) => setEditForm({ ...editForm, subscription_id: e.target.value })} className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm" placeholder="Leave empty to keep" />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Tenant ID</label>
                    <input type="text" value={editForm.tenant_id} onChange={(e) => setEditForm({ ...editForm, tenant_id: e.target.value })} className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm" placeholder="Leave empty to keep" />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Client ID</label>
                    <input type="text" value={editForm.client_id} onChange={(e) => setEditForm({ ...editForm, client_id: e.target.value })} className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm" placeholder="Leave empty to keep" />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Client Secret</label>
                    <input type="password" value={editForm.client_secret} onChange={(e) => setEditForm({ ...editForm, client_secret: e.target.value })} className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm" placeholder="Leave empty to keep" />
                  </div>
                </>
              )}

              {editingProvider.provider_type === 'gcp' && (
                <>
                  <div>
                    <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Project ID</label>
                    <input type="text" value={editForm.project_id} onChange={(e) => setEditForm({ ...editForm, project_id: e.target.value })} className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm" placeholder="Leave empty to keep" />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Service Account Key (JSON)</label>
                    <textarea value={editForm.service_account_key} onChange={(e) => setEditForm({ ...editForm, service_account_key: e.target.value })} rows={4} className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm font-mono" placeholder="Leave empty to keep" />
                  </div>
                </>
              )}

              {editingProvider.provider_type === 'oci' && (
                <>
                  <div>
                    <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Tenancy OCID</label>
                    <input type="text" value={editForm.tenancy_ocid} onChange={(e) => setEditForm({ ...editForm, tenancy_ocid: e.target.value })} className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm" placeholder="Leave empty to keep" />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">User OCID</label>
                    <input type="text" value={editForm.user_ocid} onChange={(e) => setEditForm({ ...editForm, user_ocid: e.target.value })} className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm" placeholder="Leave empty to keep" />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">API Key Fingerprint</label>
                    <input type="text" value={editForm.fingerprint} onChange={(e) => setEditForm({ ...editForm, fingerprint: e.target.value })} className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm" placeholder="Leave empty to keep" />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Private Key (PEM)</label>
                    <textarea value={editForm.private_key} onChange={(e) => setEditForm({ ...editForm, private_key: e.target.value })} rows={4} className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm font-mono" placeholder="Leave empty to keep" />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Region</label>
                    <input type="text" value={editForm.region} onChange={(e) => setEditForm({ ...editForm, region: e.target.value })} placeholder="us-ashburn-1" className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm" />
                  </div>
                </>
              )}

              {editingProvider.provider_type === 'alibaba' && (
                <>
                  <div>
                    <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Access Key ID</label>
                    <input type="text" value={editForm.alibaba_access_key_id} onChange={(e) => setEditForm({ ...editForm, alibaba_access_key_id: e.target.value })} className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm" placeholder="Leave empty to keep" />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Access Key Secret</label>
                    <input type="password" value={editForm.alibaba_access_key_secret} onChange={(e) => setEditForm({ ...editForm, alibaba_access_key_secret: e.target.value })} className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm" placeholder="Leave empty to keep" />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Region</label>
                    <input type="text" value={editForm.region} onChange={(e) => setEditForm({ ...editForm, region: e.target.value })} placeholder="cn-hangzhou" className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm" />
                  </div>
                </>
              )}

              {editingProvider.provider_type === 'ibm_cloud' && (
                <>
                  <div>
                    <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">API Key <span className="text-brand-gray-400 font-normal">(leave empty to keep)</span></label>
                    <input type="password" value={editForm.ibm_api_key} onChange={(e) => setEditForm({ ...editForm, ibm_api_key: e.target.value })} className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm" placeholder="••••••••" />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Account ID</label>
                    <input type="text" value={editForm.ibm_account_id} onChange={(e) => setEditForm({ ...editForm, ibm_account_id: e.target.value })} className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm" placeholder="Leave empty to keep" />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Region</label>
                    <input type="text" value={editForm.region} onChange={(e) => setEditForm({ ...editForm, region: e.target.value })} placeholder="us-south" className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm" />
                  </div>
                </>
              )}

              {editingProvider.provider_type === 'kubernetes' && (
                <div>
                  <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Kubeconfig (YAML)</label>
                  <textarea value={editForm.kubeconfig} onChange={(e) => setEditForm({ ...editForm, kubeconfig: e.target.value })} rows={6} className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm font-mono" placeholder="Leave empty to keep current" />
                </div>
              )}
            </div>

            <div className="flex gap-3 mt-6">
              <button onClick={() => { setShowEditModal(false); setEditingProvider(null) }} className="flex-1 btn-outline">Cancel</button>
              <button onClick={handleEdit} disabled={!editForm.alias} className="flex-1 btn-primary disabled:opacity-50">Save Changes</button>
            </div>
          </div>
        </div>
      )}

      {/* Discover Accounts Modal */}
      {showDiscoverModal && (
        <div className="modal-backdrop">
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
