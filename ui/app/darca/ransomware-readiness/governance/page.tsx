'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import Header from '@/components/layout/Header'
import { api } from '@/lib/api'
import { ArrowLeftIcon, CheckCircleIcon, ArrowPathIcon } from '@heroicons/react/24/outline'
import toast from 'react-hot-toast'

interface GovField {
  key: string
  label: string
  description: string
  type: 'boolean' | 'date' | 'percentage'
  rule: string
  domain: string
}

const FIELDS: GovField[] = [
  { key: 'ransomware_response_plan', label: 'Ransomware Response Plan', description: 'A documented incident response plan specific to ransomware exists, including containment, eradication, and recovery procedures.', type: 'boolean', rule: 'RR-GOV-001', domain: 'D7' },
  { key: 'last_tabletop_exercise_date', label: 'Last Tabletop Exercise Date', description: 'Date of the most recent ransomware tabletop simulation exercise. Must be within the last 6 months.', type: 'date', rule: 'RR-GOV-002', domain: 'D7' },
  { key: 'security_training_completion', label: 'Security Training Completion (%)', description: 'Percentage of staff who completed security awareness training including phishing and ransomware identification in the last 12 months. Target: ≥90%.', type: 'percentage', rule: 'RR-GOV-003', domain: 'D7' },
  { key: 'ir_roles_defined', label: 'IR Roles & Responsibilities Defined', description: 'Incident response roles (Incident Commander, Technical Lead, Communications Lead, Legal) are clearly defined with up-to-date contact information.', type: 'boolean', rule: 'RR-GOV-004', domain: 'D7' },
  { key: 'communication_plan_exists', label: 'Communication Plan for Ransomware', description: 'A pre-approved communication plan with templates for internal stakeholders, customers, regulators, and media.', type: 'boolean', rule: 'RR-GOV-005', domain: 'D7' },
  { key: 'rto_rpo_documented', label: 'RTO/RPO Documented & Validated', description: 'Recovery Time Objective and Recovery Point Objective are documented per service and backup configurations meet those objectives.', type: 'boolean', rule: 'RR-BKP-015', domain: 'D3' },
  { key: 'backup_restore_tested', label: 'Backup Restore Tests Performed', description: 'Backup restoration drills have been performed at least quarterly, restoring to a test environment to validate data integrity.', type: 'boolean', rule: 'RR-BKP-016', domain: 'D3' },
  { key: 'dr_plan_documented', label: 'Disaster Recovery Plan Documented', description: 'A disaster recovery plan exists that includes specific procedures for ransomware recovery scenarios.', type: 'boolean', rule: 'RR-BKP-017', domain: 'D3' },
  { key: 'iac_scanning_integrated', label: 'IaC Scanning in CI/CD Pipeline', description: 'Infrastructure as Code scanning tools (Checkov, tfsec, etc.) are integrated in CI/CD pipelines to detect misconfigurations before deployment.', type: 'boolean', rule: 'RR-HDN-015', domain: 'D5' },
  { key: 'siem_integration_configured', label: 'SIEM Integration Configured', description: 'Cloud logs are integrated with a SIEM platform (Splunk, Sentinel, Chronicle, etc.) for correlation and incident detection.', type: 'boolean', rule: 'RR-LOG-009', domain: 'D6' },
]

export default function GovernancePage() {
  const [data, setData] = useState<Record<string, any>>({})
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    api.getRRGovernance()
      .then(setData)
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [])

  async function handleSave() {
    setSaving(true)
    try {
      await api.updateRRGovernance(data)
      toast.success('Governance data saved successfully')
    } catch (e) {
      toast.error('Failed to save governance data')
    }
    setSaving(false)
  }

  function updateField(key: string, value: any) {
    setData(prev => ({ ...prev, [key]: value }))
  }

  if (loading) {
    return (
      <div className="space-y-6">
        <Header title="Governance & Awareness" subtitle="Loading..." />
        <div className="flex items-center justify-center py-20">
          <ArrowPathIcon className="w-8 h-8 animate-spin text-brand-gray-300" />
        </div>
      </div>
    )
  }

  const completedCount = FIELDS.filter(f => {
    const v = data[f.key]
    if (f.type === 'boolean') return v === true
    if (f.type === 'date') return !!v
    if (f.type === 'percentage') return v !== null && v !== undefined
    return false
  }).length

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Link href="/darca/ransomware-readiness" className="p-2 rounded-lg hover:bg-brand-gray-100 transition-colors">
          <ArrowLeftIcon className="w-5 h-5 text-brand-gray-400" />
        </Link>
        <Header
          title="Governance & Awareness Inputs"
          subtitle={`Manual assessment inputs for D3, D5, D6, D7 domains — ${completedCount}/${FIELDS.length} completed`}
        />
      </div>

      <div className="bg-amber-50 border border-amber-200 rounded-xl p-4">
        <p className="text-sm text-amber-800">
          These controls cannot be auto-scanned from cloud APIs. Complete this questionnaire to include
          governance, backup testing, and organizational readiness in your Ransomware Readiness Score.
          Re-run the assessment after saving to update scores.
        </p>
      </div>

      <div className="space-y-4">
        {FIELDS.map(field => (
          <div key={field.key} className="bg-white border border-brand-gray-200 rounded-xl p-5">
            <div className="flex items-start gap-4">
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-xs font-mono text-brand-gray-400">{field.rule}</span>
                  <span className="text-xs bg-brand-gray-100 text-brand-gray-500 px-1.5 py-0.5 rounded">{field.domain}</span>
                </div>
                <h3 className="text-sm font-semibold text-brand-navy">{field.label}</h3>
                <p className="text-xs text-brand-gray-500 mt-1">{field.description}</p>
              </div>

              <div className="flex-shrink-0 w-48">
                {field.type === 'boolean' && (
                  <button
                    onClick={() => updateField(field.key, !data[field.key])}
                    className={`w-full flex items-center justify-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                      data[field.key]
                        ? 'bg-emerald-100 text-emerald-700 border border-emerald-300'
                        : 'bg-red-50 text-red-600 border border-red-200'
                    }`}
                  >
                    {data[field.key] ? (
                      <>
                        <CheckCircleIcon className="w-4 h-4" />
                        Yes — Implemented
                      </>
                    ) : (
                      'No — Not implemented'
                    )}
                  </button>
                )}
                {field.type === 'date' && (
                  <input
                    type="date"
                    value={data[field.key] ? data[field.key].split('T')[0] : ''}
                    onChange={e => updateField(field.key, e.target.value || null)}
                    className="w-full border border-brand-gray-200 rounded-lg px-3 py-2 text-sm focus:border-brand-blue focus:ring-1 focus:ring-brand-blue outline-none"
                  />
                )}
                {field.type === 'percentage' && (
                  <div className="flex items-center gap-2">
                    <input
                      type="number"
                      min={0} max={100} step={1}
                      value={data[field.key] ?? ''}
                      onChange={e => updateField(field.key, e.target.value ? parseFloat(e.target.value) : null)}
                      placeholder="0-100"
                      className="w-full border border-brand-gray-200 rounded-lg px-3 py-2 text-sm focus:border-brand-blue focus:ring-1 focus:ring-brand-blue outline-none"
                    />
                    <span className="text-sm text-brand-gray-400">%</span>
                  </div>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Notes */}
      <div className="bg-white border border-brand-gray-200 rounded-xl p-5">
        <h3 className="text-sm font-semibold text-brand-navy mb-2">Additional Notes</h3>
        <textarea
          value={data.notes || ''}
          onChange={e => updateField('notes', e.target.value || null)}
          rows={3}
          placeholder="Additional context, links to documentation, or notes for auditors..."
          className="w-full border border-brand-gray-200 rounded-lg px-3 py-2 text-sm focus:border-brand-blue focus:ring-1 focus:ring-brand-blue outline-none resize-none"
        />
      </div>

      {/* Save */}
      <div className="flex items-center gap-4">
        <button
          onClick={handleSave}
          disabled={saving}
          className="px-6 py-2.5 bg-brand-navy text-white rounded-lg hover:bg-brand-navy/90 disabled:opacity-50 text-sm font-medium transition-colors"
        >
          {saving ? 'Saving...' : 'Save Governance Data'}
        </button>
        {data.updated_at && (
          <p className="text-xs text-brand-gray-400">
            Last updated: {new Date(data.updated_at).toLocaleString()}
          </p>
        )}
      </div>
    </div>
  )
}
