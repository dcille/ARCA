'use client'

import { useState } from 'react'
import { XMarkIcon, ArrowRightIcon, ArrowLeftIcon, CheckCircleIcon } from '@heroicons/react/24/outline'
import { api } from '@/lib/api'
import RegistryCheckSelector from './RegistryCheckSelector'
import toast from 'react-hot-toast'

const ALL_PROVIDERS = [
  'aws', 'azure', 'gcp', 'oci', 'alibaba', 'ibm_cloud', 'kubernetes',
  'm365', 'github', 'google_workspace', 'salesforce', 'servicenow',
  'snowflake', 'cloudflare', 'openstack',
]

interface Props {
  onClose: () => void
  onCreated: (fw: any) => void
}

export default function CreateFrameworkWizard({ onClose, onCreated }: Props) {
  const [step, setStep] = useState(0)
  const [creating, setCreating] = useState(false)

  // Step 0: Metadata
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [version, setVersion] = useState('1.0')
  const [selectedProviders, setSelectedProviders] = useState<Set<string>>(new Set())

  // Step 1: Check selection
  const [selectedCheckIds, setSelectedCheckIds] = useState<Set<string>>(new Set())

  const canProceedStep0 = name.trim().length > 0 && selectedProviders.size > 0
  const canProceedStep1 = true // Allow creating with 0 checks

  const toggleProvider = (p: string) => {
    const next = new Set(selectedProviders)
    if (next.has(p)) next.delete(p)
    else next.add(p)
    setSelectedProviders(next)
  }

  const handleCreate = async () => {
    setCreating(true)
    try {
      const fw = await api.createCustomFramework({
        name: name.trim(),
        description: description.trim() || undefined,
        version: version.trim() || '1.0',
        providers: Array.from(selectedProviders),
        selected_check_ids: Array.from(selectedCheckIds),
      })
      toast.success('Custom framework created!')
      onCreated(fw)
    } catch (err: any) {
      toast.error(err.message || 'Failed to create framework')
    } finally {
      setCreating(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ background: 'rgba(0,0,0,0.4)', backdropFilter: 'blur(4px)' }}>
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-5xl max-h-[90vh] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-brand-gray-200">
          <div>
            <h2 className="text-lg font-bold text-brand-gray-900">Create Custom Framework</h2>
            <div className="flex gap-2 mt-2">
              {['Metadata', 'Select Checks', 'Review'].map((label, i) => (
                <div key={i} className="flex items-center gap-1">
                  <div className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-medium ${
                    i < step ? 'bg-brand-green text-white' : i === step ? 'bg-brand-green/20 text-brand-green border border-brand-green' : 'bg-brand-gray-100 text-brand-gray-400'
                  }`}>
                    {i < step ? <CheckCircleIcon className="w-4 h-4" /> : i + 1}
                  </div>
                  <span className={`text-xs ${i === step ? 'text-brand-green font-medium' : 'text-brand-gray-400'}`}>{label}</span>
                  {i < 2 && <span className="text-brand-gray-300 mx-1">&rarr;</span>}
                </div>
              ))}
            </div>
          </div>
          <button onClick={onClose} className="p-2 hover:bg-brand-gray-100 rounded-lg">
            <XMarkIcon className="w-5 h-5 text-brand-gray-500" />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6">
          {step === 0 && (
            <div className="max-w-2xl space-y-5">
              <div>
                <label className="block text-sm font-medium text-brand-gray-700 mb-1">Framework Name *</label>
                <input
                  value={name}
                  onChange={e => setName(e.target.value)}
                  placeholder="e.g., Internal Security Policy v2"
                  className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-brand-green/40 focus:border-brand-green outline-none"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-brand-gray-700 mb-1">Description</label>
                <textarea
                  value={description}
                  onChange={e => setDescription(e.target.value)}
                  rows={3}
                  placeholder="Describe the purpose of this framework..."
                  className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-brand-green/40 focus:border-brand-green outline-none resize-none"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-brand-gray-700 mb-1">Version</label>
                <input
                  value={version}
                  onChange={e => setVersion(e.target.value)}
                  placeholder="1.0"
                  className="w-48 px-3 py-2 border border-brand-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-brand-green/40 focus:border-brand-green outline-none"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-brand-gray-700 mb-2">Applicable Providers *</label>
                <div className="flex flex-wrap gap-2">
                  {ALL_PROVIDERS.map(p => (
                    <button
                      key={p}
                      onClick={() => toggleProvider(p)}
                      className={`px-3 py-1.5 rounded-lg text-sm border transition-colors ${
                        selectedProviders.has(p)
                          ? 'border-brand-green bg-brand-green/10 text-brand-green font-medium'
                          : 'border-brand-gray-300 text-brand-gray-600 hover:border-brand-gray-400'
                      }`}
                    >
                      {p.toUpperCase().replace('_', ' ')}
                    </button>
                  ))}
                </div>
                <div className="flex gap-2 mt-2">
                  <button onClick={() => setSelectedProviders(new Set(ALL_PROVIDERS))} className="text-xs text-brand-green hover:underline">
                    Select all
                  </button>
                  <button onClick={() => setSelectedProviders(new Set())} className="text-xs text-brand-gray-500 hover:underline">
                    Clear
                  </button>
                </div>
              </div>
            </div>
          )}

          {step === 1 && (
            <div className="h-[500px]">
              <RegistryCheckSelector
                selectedCheckIds={selectedCheckIds}
                onSelectionChange={setSelectedCheckIds}
                providers={Array.from(selectedProviders)}
              />
            </div>
          )}

          {step === 2 && (
            <div className="max-w-2xl space-y-4">
              <h3 className="text-base font-semibold text-brand-gray-800">Review your framework</h3>
              <div className="grid grid-cols-2 gap-4">
                <div className="card-static p-4">
                  <p className="text-xs text-brand-gray-500 mb-1">Name</p>
                  <p className="font-medium text-brand-gray-900">{name}</p>
                </div>
                <div className="card-static p-4">
                  <p className="text-xs text-brand-gray-500 mb-1">Version</p>
                  <p className="font-medium text-brand-gray-900">{version}</p>
                </div>
                <div className="card-static p-4 col-span-2">
                  <p className="text-xs text-brand-gray-500 mb-1">Description</p>
                  <p className="text-sm text-brand-gray-700">{description || 'No description'}</p>
                </div>
                <div className="card-static p-4">
                  <p className="text-xs text-brand-gray-500 mb-1">Providers</p>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {Array.from(selectedProviders).map(p => (
                      <span key={p} className="text-xs bg-brand-gray-100 text-brand-gray-700 px-2 py-0.5 rounded">{p}</span>
                    ))}
                  </div>
                </div>
                <div className="card-static p-4">
                  <p className="text-xs text-brand-gray-500 mb-1">Selected Checks</p>
                  <p className="text-2xl font-bold text-brand-green">{selectedCheckIds.size}</p>
                  <p className="text-xs text-brand-gray-400">from the registry</p>
                </div>
              </div>
              <p className="text-xs text-brand-gray-400">
                You can add more checks and create custom controls after creating the framework.
              </p>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between px-6 py-4 border-t border-brand-gray-200">
          <button
            onClick={() => step === 0 ? onClose() : setStep(step - 1)}
            className="flex items-center gap-1 px-4 py-2 text-sm text-brand-gray-600 hover:text-brand-gray-800"
          >
            <ArrowLeftIcon className="w-4 h-4" />
            {step === 0 ? 'Cancel' : 'Back'}
          </button>

          {step < 2 ? (
            <button
              disabled={step === 0 && !canProceedStep0}
              onClick={() => setStep(step + 1)}
              className="flex items-center gap-1 btn-primary px-6 py-2 text-sm disabled:opacity-40"
            >
              Next
              <ArrowRightIcon className="w-4 h-4" />
            </button>
          ) : (
            <button
              disabled={creating}
              onClick={handleCreate}
              className="btn-primary px-6 py-2 text-sm disabled:opacity-60"
            >
              {creating ? 'Creating...' : 'Create Framework'}
            </button>
          )}
        </div>
      </div>
    </div>
  )
}
