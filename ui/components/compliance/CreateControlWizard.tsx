'use client'

import { useState, useEffect } from 'react'
import { XMarkIcon, CogIcon, EyeIcon } from '@heroicons/react/24/outline'
import { api } from '@/lib/api'
import toast from 'react-hot-toast'

const ALL_PROVIDERS = [
  'aws', 'azure', 'gcp', 'oci', 'alibaba', 'ibm_cloud', 'kubernetes',
  'm365', 'github', 'google_workspace', 'salesforce', 'servicenow',
  'snowflake', 'cloudflare', 'openstack',
]

const CATEGORIES = [
  'Identity', 'Encryption', 'Storage', 'Networking', 'Logging', 'Compute',
  'Database', 'Container', 'Serverless', 'Data Protection', 'Backup',
  'Compliance', 'Threat Detection', 'Governance', 'Email Security',
  'Collaboration', 'DevOps', 'API Security', 'CDN', 'DNS', 'Analytics',
]

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational']

interface Props {
  frameworkId: string
  onClose: () => void
  onCreated: (ctrl: any) => void
}

export default function CreateControlWizard({ frameworkId, onClose, onCreated }: Props) {
  const [creating, setCreating] = useState(false)
  const [form, setForm] = useState({
    check_id: '',
    title: '',
    description: '',
    severity: 'medium',
    provider: 'aws',
    service: 'custom',
    category: 'Compliance',
    risks: '',
    remediation: '',
    scanner_check_ids: '',
    tags: '',
  })

  const assessmentType = form.scanner_check_ids.trim() ? 'automated' : 'manual'

  const update = (field: string, value: string) => setForm(prev => ({ ...prev, [field]: value }))

  const handleCreate = async () => {
    if (!form.check_id.trim() || !form.title.trim()) {
      toast.error('Check ID and Title are required')
      return
    }

    setCreating(true)
    try {
      const scannerIds = form.scanner_check_ids.trim()
        ? form.scanner_check_ids.split(',').map(s => s.trim()).filter(Boolean)
        : []
      const tags = form.tags.trim()
        ? form.tags.split(',').map(s => s.trim()).filter(Boolean)
        : []

      const ctrl = await api.createCustomControl(frameworkId, {
        check_id: form.check_id.trim(),
        title: form.title.trim(),
        description: form.description.trim() || undefined,
        severity: form.severity,
        provider: form.provider,
        service: form.service.trim() || 'custom',
        category: form.category,
        risks: form.risks.trim() || undefined,
        remediation: form.remediation.trim() || undefined,
        scanner_check_ids: scannerIds,
        tags,
      })

      if (ctrl.warnings?.length) {
        ctrl.warnings.forEach((w: string) => toast(w, { icon: '\u26a0\ufe0f' }))
      }

      toast.success('Custom control created!')
      onCreated(ctrl)
    } catch (err: any) {
      toast.error(err.message || 'Failed to create control')
    } finally {
      setCreating(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ background: 'rgba(0,0,0,0.4)', backdropFilter: 'blur(4px)' }}>
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-2xl max-h-[90vh] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-brand-gray-200">
          <h2 className="text-lg font-bold text-brand-gray-900">Create New Control</h2>
          <button onClick={onClose} className="p-2 hover:bg-brand-gray-100 rounded-lg">
            <XMarkIcon className="w-5 h-5 text-brand-gray-500" />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-brand-gray-700 mb-1">Check ID *</label>
              <input
                value={form.check_id}
                onChange={e => update('check_id', e.target.value)}
                placeholder="e.g., custom_sec_001"
                className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-brand-green/40 focus:border-brand-green outline-none"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-brand-gray-700 mb-1">Provider *</label>
              <select
                value={form.provider}
                onChange={e => update('provider', e.target.value)}
                className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-brand-green/40 focus:border-brand-green outline-none bg-white"
              >
                {ALL_PROVIDERS.map(p => (
                  <option key={p} value={p}>{p.toUpperCase().replace('_', ' ')}</option>
                ))}
              </select>
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-brand-gray-700 mb-1">Title *</label>
            <input
              value={form.title}
              onChange={e => update('title', e.target.value)}
              placeholder="e.g., Ensure MFA is enabled for all IAM users"
              className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-brand-green/40 focus:border-brand-green outline-none"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-brand-gray-700 mb-1">Description</label>
            <textarea
              value={form.description}
              onChange={e => update('description', e.target.value)}
              rows={3}
              className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-brand-green/40 focus:border-brand-green outline-none resize-none"
            />
          </div>

          <div className="grid grid-cols-3 gap-4">
            <div>
              <label className="block text-sm font-medium text-brand-gray-700 mb-1">Severity</label>
              <select
                value={form.severity}
                onChange={e => update('severity', e.target.value)}
                className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm bg-white focus:ring-2 focus:ring-brand-green/40 focus:border-brand-green outline-none"
              >
                {SEVERITIES.map(s => (
                  <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-brand-gray-700 mb-1">Category</label>
              <select
                value={form.category}
                onChange={e => update('category', e.target.value)}
                className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm bg-white focus:ring-2 focus:ring-brand-green/40 focus:border-brand-green outline-none"
              >
                {CATEGORIES.map(c => (
                  <option key={c} value={c}>{c}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-brand-gray-700 mb-1">Service</label>
              <input
                value={form.service}
                onChange={e => update('service', e.target.value)}
                placeholder="custom"
                className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-brand-green/40 focus:border-brand-green outline-none"
              />
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-brand-gray-700 mb-1">
              Mapped Scanner Check IDs
              <span className="text-brand-gray-400 font-normal ml-1">(comma-separated)</span>
            </label>
            <input
              value={form.scanner_check_ids}
              onChange={e => update('scanner_check_ids', e.target.value)}
              placeholder="e.g., aws_iam_mfa_enabled, azure_ad_mfa_status"
              className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-brand-green/40 focus:border-brand-green outline-none"
            />
            <div className="flex items-center gap-2 mt-1">
              {assessmentType === 'automated' ? (
                <span className="flex items-center gap-1 text-xs text-green-600">
                  <CogIcon className="w-3.5 h-3.5" /> Automated
                </span>
              ) : (
                <span className="flex items-center gap-1 text-xs text-blue-600">
                  <EyeIcon className="w-3.5 h-3.5" /> Manual Review
                </span>
              )}
              <span className="text-[11px] text-brand-gray-400">
                {assessmentType === 'automated'
                  ? 'This control will be evaluated automatically via scanner results'
                  : 'No scanner mapping \u2014 this control requires manual assessment'}
              </span>
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-brand-gray-700 mb-1">Risks</label>
            <textarea
              value={form.risks}
              onChange={e => update('risks', e.target.value)}
              rows={2}
              placeholder="Describe the risks if this control is not implemented..."
              className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-brand-green/40 focus:border-brand-green outline-none resize-none"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-brand-gray-700 mb-1">Remediation</label>
            <textarea
              value={form.remediation}
              onChange={e => update('remediation', e.target.value)}
              rows={2}
              placeholder="Steps to remediate..."
              className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-brand-green/40 focus:border-brand-green outline-none resize-none"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-brand-gray-700 mb-1">
              Tags
              <span className="text-brand-gray-400 font-normal ml-1">(comma-separated)</span>
            </label>
            <input
              value={form.tags}
              onChange={e => update('tags', e.target.value)}
              placeholder="e.g., internal-policy, pci-dss, hipaa"
              className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-brand-green/40 focus:border-brand-green outline-none"
            />
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-brand-gray-200">
          <button onClick={onClose} className="px-4 py-2 text-sm text-brand-gray-600 hover:text-brand-gray-800">
            Cancel
          </button>
          <button
            disabled={creating || !form.check_id.trim() || !form.title.trim()}
            onClick={handleCreate}
            className="btn-primary px-6 py-2 text-sm disabled:opacity-40"
          >
            {creating ? 'Creating...' : 'Create Control'}
          </button>
        </div>
      </div>
    </div>
  )
}
