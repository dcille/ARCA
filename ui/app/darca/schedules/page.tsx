'use client'

import { useEffect, useState } from 'react'
import Header from '@/components/layout/Header'
import { api } from '@/lib/api'
import toast from 'react-hot-toast'
import {
  ClockIcon,
  PlusIcon,
  TrashIcon,
  PauseIcon,
  PlayIcon,
  PencilIcon,
} from '@heroicons/react/24/outline'

interface Schedule {
  id: string
  name: string
  scan_type: string
  frequency: string
  enabled: boolean
  provider_id: string | null
  connection_id: string | null
  services: string[] | null
  regions: string[] | null
  last_run_at: string | null
  next_run_at: string | null
  created_at: string
}

export default function SchedulesPage() {
  const [schedules, setSchedules] = useState<Schedule[]>([])
  const [providers, setProviders] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [showCreate, setShowCreate] = useState(false)
  const [editId, setEditId] = useState<string | null>(null)
  const [form, setForm] = useState({
    name: '',
    scan_type: 'cloud',
    frequency: 'daily',
    provider_id: '',
    services: '',
    regions: '',
  })

  const load = async () => {
    try {
      const [s, p] = await Promise.all([api.getSchedules(), api.getProviders()])
      setSchedules(s)
      setProviders(p)
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const resetForm = () => {
    setForm({ name: '', scan_type: 'cloud', frequency: 'daily', provider_id: '', services: '', regions: '' })
    setShowCreate(false)
    setEditId(null)
  }

  const handleCreate = async () => {
    try {
      const payload: any = {
        name: form.name,
        scan_type: form.scan_type,
        frequency: form.frequency,
      }
      if (form.provider_id) payload.provider_id = form.provider_id
      if (form.services.trim()) payload.services = form.services.split(',').map(s => s.trim()).filter(Boolean)
      if (form.regions.trim()) payload.regions = form.regions.split(',').map(s => s.trim()).filter(Boolean)

      await api.createSchedule(payload)
      toast.success('Schedule created')
      resetForm()
      load()
    } catch (err: any) {
      toast.error(err.message || 'Failed to create schedule')
    }
  }

  const handleUpdate = async () => {
    if (!editId) return
    try {
      const payload: any = { name: form.name, frequency: form.frequency }
      if (form.services.trim()) payload.services = form.services.split(',').map(s => s.trim()).filter(Boolean)
      if (form.regions.trim()) payload.regions = form.regions.split(',').map(s => s.trim()).filter(Boolean)
      await api.updateSchedule(editId, payload)
      toast.success('Schedule updated')
      resetForm()
      load()
    } catch (err: any) {
      toast.error(err.message || 'Failed to update schedule')
    }
  }

  const handleToggle = async (s: Schedule) => {
    try {
      await api.updateSchedule(s.id, { enabled: !s.enabled })
      toast.success(s.enabled ? 'Schedule paused' : 'Schedule enabled')
      load()
    } catch (err: any) {
      toast.error(err.message)
    }
  }

  const handleDelete = async (id: string) => {
    if (!confirm('Delete this schedule?')) return
    try {
      await api.deleteSchedule(id)
      toast.success('Schedule deleted')
      load()
    } catch (err: any) {
      toast.error(err.message)
    }
  }

  const startEdit = (s: Schedule) => {
    setEditId(s.id)
    setForm({
      name: s.name,
      scan_type: s.scan_type,
      frequency: s.frequency,
      provider_id: s.provider_id || '',
      services: s.services?.join(', ') || '',
      regions: s.regions?.join(', ') || '',
    })
    setShowCreate(true)
  }

  const freqLabel: Record<string, string> = {
    daily: 'Daily',
    weekly: 'Weekly',
    monthly: 'Monthly',
  }

  const freqColor: Record<string, string> = {
    daily: 'bg-blue-100 text-blue-700',
    weekly: 'bg-purple-100 text-purple-700',
    monthly: 'bg-amber-100 text-amber-700',
  }

  if (loading) {
    return (
      <div>
        <Header title="Scan Schedules" subtitle="Automate recurring security scans" />
        <div className="card animate-pulse"><div className="h-48 bg-brand-gray-100 rounded" /></div>
      </div>
    )
  }

  return (
    <div>
      <Header title="Scan Schedules" subtitle="Automate recurring security scans across your cloud and SaaS environments" />

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <div className="card text-center">
          <p className="text-2xl font-bold text-brand-navy">{schedules.length}</p>
          <p className="text-xs text-brand-gray-400 uppercase font-semibold mt-1">Total Schedules</p>
        </div>
        <div className="card text-center">
          <p className="text-2xl font-bold text-brand-green">{schedules.filter(s => s.enabled).length}</p>
          <p className="text-xs text-brand-gray-400 uppercase font-semibold mt-1">Active</p>
        </div>
        <div className="card text-center">
          <p className="text-2xl font-bold text-brand-gray-400">{schedules.filter(s => !s.enabled).length}</p>
          <p className="text-xs text-brand-gray-400 uppercase font-semibold mt-1">Paused</p>
        </div>
        <div className="card text-center">
          <p className="text-2xl font-bold text-blue-600">{schedules.filter(s => s.frequency === 'daily').length}</p>
          <p className="text-xs text-brand-gray-400 uppercase font-semibold mt-1">Daily Scans</p>
        </div>
      </div>

      {/* Create/Edit Button */}
      <div className="flex justify-end mb-4">
        <button
          onClick={() => { resetForm(); setShowCreate(true) }}
          className="btn-primary flex items-center gap-2"
        >
          <PlusIcon className="w-4 h-4" />
          New Schedule
        </button>
      </div>

      {/* Create/Edit Modal */}
      {showCreate && (
        <div className="modal-backdrop">
          <div className="bg-white rounded-xl shadow-xl p-6 w-full max-w-lg">
            <h3 className="text-lg font-semibold text-brand-navy mb-4">
              {editId ? 'Edit Schedule' : 'Create Schedule'}
            </h3>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Schedule Name</label>
                <input
                  type="text"
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm"
                  placeholder="e.g., Nightly AWS Scan"
                />
              </div>

              {!editId && (
                <>
                  <div>
                    <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Scan Type</label>
                    <select
                      value={form.scan_type}
                      onChange={(e) => setForm({ ...form, scan_type: e.target.value })}
                      className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm"
                    >
                      <option value="cloud">Cloud Infrastructure</option>
                      <option value="saas">SaaS Applications</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Provider (optional)</label>
                    <select
                      value={form.provider_id}
                      onChange={(e) => setForm({ ...form, provider_id: e.target.value })}
                      className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm"
                    >
                      <option value="">All Providers</option>
                      {providers.map(p => (
                        <option key={p.id} value={p.id}>{p.alias} ({p.provider_type.toUpperCase()})</option>
                      ))}
                    </select>
                  </div>
                </>
              )}

              <div>
                <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Frequency</label>
                <select
                  value={form.frequency}
                  onChange={(e) => setForm({ ...form, frequency: e.target.value })}
                  className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm"
                >
                  <option value="daily">Daily</option>
                  <option value="weekly">Weekly</option>
                  <option value="monthly">Monthly</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Services (comma-separated, optional)</label>
                <input
                  type="text"
                  value={form.services}
                  onChange={(e) => setForm({ ...form, services: e.target.value })}
                  className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm"
                  placeholder="e.g., iam, s3, ec2"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Regions (comma-separated, optional)</label>
                <input
                  type="text"
                  value={form.regions}
                  onChange={(e) => setForm({ ...form, regions: e.target.value })}
                  className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm"
                  placeholder="e.g., us-east-1, eu-west-1"
                />
              </div>
            </div>
            <div className="flex gap-3 mt-6">
              <button onClick={resetForm} className="flex-1 btn-outline">Cancel</button>
              <button
                onClick={editId ? handleUpdate : handleCreate}
                disabled={!form.name}
                className="flex-1 btn-primary disabled:opacity-50"
              >
                {editId ? 'Update' : 'Create'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Schedule List */}
      {schedules.length === 0 ? (
        <div className="card text-center py-16">
          <ClockIcon className="w-12 h-12 text-brand-gray-300 mx-auto mb-4" />
          <h3 className="text-lg font-semibold text-brand-navy mb-2">No Schedules Yet</h3>
          <p className="text-brand-gray-400 mb-6">
            Create automated schedules to run security scans on a recurring basis.
          </p>
          <button onClick={() => setShowCreate(true)} className="btn-primary">
            Create Your First Schedule
          </button>
        </div>
      ) : (
        <div className="space-y-3">
          {schedules.map((s) => (
            <div key={s.id} className={`card hover:shadow-md transition-shadow ${!s.enabled ? 'opacity-60' : ''}`}>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <div className={`p-2.5 rounded-lg ${s.enabled ? 'bg-brand-green/10' : 'bg-brand-gray-100'}`}>
                    <ClockIcon className={`w-5 h-5 ${s.enabled ? 'text-brand-green' : 'text-brand-gray-400'}`} />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <h4 className="text-sm font-semibold text-brand-navy">{s.name}</h4>
                      <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold ${freqColor[s.frequency] || 'bg-brand-gray-100 text-brand-gray-600'}`}>
                        {freqLabel[s.frequency] || s.frequency}
                      </span>
                      <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-brand-gray-100 text-brand-gray-600">
                        {s.scan_type === 'cloud' ? 'Cloud' : 'SaaS'}
                      </span>
                    </div>
                    <div className="flex items-center gap-4 mt-1 text-xs text-brand-gray-400">
                      {s.last_run_at && (
                        <span>Last run: {new Date(s.last_run_at).toLocaleDateString()}</span>
                      )}
                      {s.next_run_at && (
                        <span>Next run: {new Date(s.next_run_at).toLocaleDateString()}</span>
                      )}
                      {s.services && s.services.length > 0 && (
                        <span>Services: {s.services.join(', ')}</span>
                      )}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleToggle(s)}
                    className="p-2 rounded-lg hover:bg-brand-gray-100 text-brand-gray-400 hover:text-brand-navy transition-colors"
                    title={s.enabled ? 'Pause' : 'Resume'}
                  >
                    {s.enabled ? <PauseIcon className="w-4 h-4" /> : <PlayIcon className="w-4 h-4" />}
                  </button>
                  <button
                    onClick={() => startEdit(s)}
                    className="p-2 rounded-lg hover:bg-brand-gray-100 text-brand-gray-400 hover:text-brand-navy transition-colors"
                    title="Edit"
                  >
                    <PencilIcon className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => handleDelete(s.id)}
                    className="p-2 rounded-lg hover:bg-red-50 text-brand-gray-400 hover:text-red-500 transition-colors"
                    title="Delete"
                  >
                    <TrashIcon className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
