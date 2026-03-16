'use client'

import { useEffect, useState } from 'react'
import Header from '@/components/layout/Header'
import { api } from '@/lib/api'
import { cn, formatDate } from '@/lib/utils'
import {
  PaperAirplaneIcon,
  TrashIcon,
  PauseCircleIcon,
  PlayCircleIcon,
  BoltIcon,
  PlusIcon,
} from '@heroicons/react/24/outline'
import toast from 'react-hot-toast'

const INTEGRATION_TYPES = [
  { value: 'slack', label: 'Slack', description: 'Send alerts to a Slack channel via webhook', placeholder: 'https://hooks.slack.com/services/...' },
  { value: 'teams', label: 'Microsoft Teams', description: 'Send alerts to a Teams channel via webhook', placeholder: 'https://outlook.office.com/webhook/...' },
  { value: 'jira', label: 'Jira', description: 'Create Jira tickets for findings', placeholder: 'https://your-instance.atlassian.net/...' },
  { value: 'webhook', label: 'Generic Webhook', description: 'Send JSON payloads to any HTTP endpoint', placeholder: 'https://your-endpoint.com/webhook' },
]

const EVENT_TYPES = [
  { value: 'scan_complete', label: 'Scan Complete' },
  { value: 'critical_finding', label: 'Critical Finding' },
  { value: 'high_finding', label: 'High Finding' },
  { value: 'schedule_triggered', label: 'Schedule Triggered' },
]

export default function IntegrationsPage() {
  const [integrations, setIntegrations] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [showModal, setShowModal] = useState(false)
  const [form, setForm] = useState({
    name: '',
    type: 'slack',
    webhook_url: '',
    events: ['scan_complete', 'critical_finding'],
    min_severity: 'high',
  })

  const loadData = async () => {
    setLoading(true)
    try {
      setIntegrations(await api.getIntegrations())
    } catch (err) { console.error(err) }
    finally { setLoading(false) }
  }

  useEffect(() => { loadData() }, [])

  const selectedType = INTEGRATION_TYPES.find(t => t.value === form.type)

  const handleCreate = async () => {
    try {
      await api.createIntegration(form)
      toast.success('Integration created!')
      setShowModal(false)
      setForm({ name: '', type: 'slack', webhook_url: '', events: ['scan_complete', 'critical_finding'], min_severity: 'high' })
      loadData()
    } catch (err: any) { toast.error(err.message) }
  }

  const handleTest = async (id: string) => {
    try {
      const result = await api.testIntegration(id)
      if (result.success) toast.success(result.message)
      else toast.error(result.message)
    } catch (err: any) { toast.error(err.message) }
  }

  return (
    <div>
      <Header
        title="Integrations"
        subtitle="Connect ARCA alerts to Slack, Teams, Jira, and other tools"
        actions={
          <button onClick={() => setShowModal(true)} className="btn-primary flex items-center gap-2">
            <PlusIcon className="w-4 h-4" /> Add Integration
          </button>
        }
      />

      {loading ? (
        <div className="space-y-4">{[...Array(2)].map((_, i) => <div key={i} className="card animate-pulse"><div className="h-20 bg-brand-gray-100 rounded" /></div>)}</div>
      ) : integrations.length === 0 ? (
        <div className="card text-center py-16">
          <BoltIcon className="w-16 h-16 mx-auto text-brand-gray-300 mb-4" />
          <h3 className="text-lg font-semibold text-brand-navy mb-2">No Integrations</h3>
          <p className="text-sm text-brand-gray-400 mb-6">Connect ARCA to your team's tools to receive security alerts in real-time.</p>
          <button onClick={() => setShowModal(true)} className="btn-primary">Add Integration</button>
        </div>
      ) : (
        <div className="space-y-4">
          {integrations.map((intg) => (
            <div key={intg.id} className="card">
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-4">
                  <div className={cn(
                    'w-10 h-10 rounded-lg flex items-center justify-center text-white font-bold text-sm',
                    intg.type === 'slack' ? 'bg-[#4A154B]' :
                    intg.type === 'teams' ? 'bg-[#6264A7]' :
                    intg.type === 'jira' ? 'bg-[#0052CC]' : 'bg-brand-gray-500'
                  )}>
                    {intg.type.charAt(0).toUpperCase()}
                  </div>
                  <div>
                    <h3 className="text-sm font-bold text-brand-navy">{intg.name}</h3>
                    <p className="text-xs text-brand-gray-400">
                      {intg.type.charAt(0).toUpperCase() + intg.type.slice(1)} &middot;
                      Min: {intg.min_severity} &middot;
                      Events: {intg.events?.join(', ')}
                    </p>
                    {intg.last_triggered_at && (
                      <p className="text-xs text-brand-gray-400">Last triggered: {formatDate(intg.last_triggered_at)}</p>
                    )}
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <span className={cn(
                    'text-xs px-2 py-0.5 rounded-full font-medium',
                    intg.enabled ? 'bg-green-50 text-green-700' : 'bg-brand-gray-100 text-brand-gray-500'
                  )}>
                    {intg.enabled ? 'Active' : 'Paused'}
                  </span>
                  <button onClick={() => handleTest(intg.id)} className="p-1.5 rounded-lg hover:bg-brand-gray-100 text-brand-gray-400" title="Send test">
                    <PaperAirplaneIcon className="w-4 h-4" />
                  </button>
                  <button
                    onClick={async () => {
                      await api.updateIntegration(intg.id, { enabled: !intg.enabled })
                      toast.success(intg.enabled ? 'Paused' : 'Resumed')
                      loadData()
                    }}
                    className="p-1.5 rounded-lg hover:bg-brand-gray-100 text-brand-gray-400" title={intg.enabled ? 'Pause' : 'Resume'}
                  >
                    {intg.enabled ? <PauseCircleIcon className="w-4 h-4" /> : <PlayCircleIcon className="w-4 h-4" />}
                  </button>
                  <button
                    onClick={async () => {
                      await api.deleteIntegration(intg.id)
                      toast.success('Deleted')
                      loadData()
                    }}
                    className="p-1.5 rounded-lg hover:bg-red-50 text-brand-gray-400 hover:text-red-500" title="Delete"
                  >
                    <TrashIcon className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Create Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="bg-white rounded-xl shadow-xl p-6 w-full max-w-lg">
            <h3 className="text-lg font-semibold text-brand-navy mb-4">Add Integration</h3>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Name</label>
                <input type="text" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="e.g., Security Alerts Channel" className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm" />
              </div>
              <div>
                <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Type</label>
                <div className="grid grid-cols-2 gap-2">
                  {INTEGRATION_TYPES.map(t => (
                    <button key={t.value} onClick={() => setForm({ ...form, type: t.value })}
                      className={cn('p-3 rounded-lg border-2 text-left transition-colors', form.type === t.value ? 'border-brand-green bg-brand-green/5' : 'border-brand-gray-200')}
                    >
                      <p className="text-sm font-medium text-brand-navy">{t.label}</p>
                      <p className="text-xs text-brand-gray-400">{t.description}</p>
                    </button>
                  ))}
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Webhook URL</label>
                <input type="url" value={form.webhook_url} onChange={(e) => setForm({ ...form, webhook_url: e.target.value })} placeholder={selectedType?.placeholder} className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm" />
              </div>
              <div>
                <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Trigger Events</label>
                <div className="flex flex-wrap gap-2">
                  {EVENT_TYPES.map(ev => (
                    <button key={ev.value} onClick={() => {
                      const events = form.events.includes(ev.value) ? form.events.filter(e => e !== ev.value) : [...form.events, ev.value]
                      setForm({ ...form, events })
                    }}
                      className={cn('px-3 py-1 rounded-full text-xs font-medium border transition-colors',
                        form.events.includes(ev.value) ? 'bg-brand-green text-white border-brand-green' : 'bg-white text-brand-gray-500 border-brand-gray-300'
                      )}
                    >{ev.label}</button>
                  ))}
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Minimum Severity</label>
                <select value={form.min_severity} onChange={(e) => setForm({ ...form, min_severity: e.target.value })} className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm">
                  <option value="critical">Critical only</option>
                  <option value="high">High and above</option>
                  <option value="medium">Medium and above</option>
                  <option value="low">All severities</option>
                </select>
              </div>
            </div>
            <div className="flex gap-3 mt-6">
              <button onClick={() => setShowModal(false)} className="flex-1 btn-outline">Cancel</button>
              <button onClick={handleCreate} disabled={!form.name || !form.webhook_url} className="flex-1 btn-primary disabled:opacity-50">Create Integration</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
