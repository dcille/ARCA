'use client'

import { useEffect, useState, useRef, useCallback } from 'react'
import Header from '@/components/layout/Header'
import DataTable from '@/components/ui/DataTable'
import Badge from '@/components/ui/Badge'
import { api } from '@/lib/api'
import { formatDate, cn } from '@/lib/utils'
import toast from 'react-hot-toast'
import {
  ClockIcon,
  TrashIcon,
  PauseCircleIcon,
  PlayCircleIcon,
  PauseIcon,
  PlayIcon,
  PencilIcon,
  PlusIcon,
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

export default function ScansPage() {
  const [scans, setScans] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [providers, setProviders] = useState<any[]>([])
  const [connections, setConnections] = useState<any[]>([])
  const [showModal, setShowModal] = useState(false)
  const [schedules, setSchedules] = useState<Schedule[]>([])
  const [scanType, setScanType] = useState('cloud')
  const [selectedProvider, setSelectedProvider] = useState('')
  const [selectedConnection, setSelectedConnection] = useState('')
  const [filterType, setFilterType] = useState('')
  const [filterStatus, setFilterStatus] = useState('')
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  // Schedule form state
  const [showScheduleModal, setShowScheduleModal] = useState(false)
  const [editScheduleId, setEditScheduleId] = useState<string | null>(null)
  const [scheduleForm, setScheduleForm] = useState({
    name: '',
    scan_type: 'cloud',
    frequency: 'daily',
    provider_id: '',
    services: '',
    regions: '',
  })

  const hasActiveScans = useCallback(
    (scanList: any[]) => scanList.some((s) => s.status === 'pending' || s.status === 'running'),
    []
  )

  const loadData = async (silent = false) => {
    if (!silent) setLoading(true)
    try {
      const params: Record<string, string> = {}
      if (filterType) params.scan_type = filterType
      const [s, p, c, sch] = await Promise.all([
        api.getScans(filterType || undefined),
        api.getProviders(),
        api.getSaaSConnections(),
        api.getSchedules().catch(() => []),
      ])
      setSchedules(sch)
      let filtered = s
      if (filterStatus) {
        filtered = s.filter((scan: any) => scan.status === filterStatus)
      }
      setScans(filtered)
      setProviders(p)
      setConnections(c)

      // Start or stop polling based on active scans
      if (hasActiveScans(s) && !pollRef.current) {
        pollRef.current = setInterval(() => loadData(true), 5000)
      } else if (!hasActiveScans(s) && pollRef.current) {
        clearInterval(pollRef.current)
        pollRef.current = null
      }
    } catch (err) {
      console.error(err)
    } finally {
      if (!silent) setLoading(false)
    }
  }

  useEffect(() => {
    loadData()
    return () => {
      if (pollRef.current) clearInterval(pollRef.current)
    }
  }, [filterType, filterStatus])

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

  // Schedule handlers
  const resetScheduleForm = () => {
    setScheduleForm({ name: '', scan_type: 'cloud', frequency: 'daily', provider_id: '', services: '', regions: '' })
    setShowScheduleModal(false)
    setEditScheduleId(null)
  }

  const handleCreateSchedule = async () => {
    try {
      const payload: any = {
        name: scheduleForm.name,
        scan_type: scheduleForm.scan_type,
        frequency: scheduleForm.frequency,
      }
      if (scheduleForm.provider_id) payload.provider_id = scheduleForm.provider_id
      if (scheduleForm.services.trim()) payload.services = scheduleForm.services.split(',').map(s => s.trim()).filter(Boolean)
      if (scheduleForm.regions.trim()) payload.regions = scheduleForm.regions.split(',').map(s => s.trim()).filter(Boolean)

      await api.createSchedule(payload)
      toast.success('Schedule created')
      resetScheduleForm()
      loadData()
    } catch (err: any) {
      toast.error(err.message || 'Failed to create schedule')
    }
  }

  const handleUpdateSchedule = async () => {
    if (!editScheduleId) return
    try {
      const payload: any = { name: scheduleForm.name, frequency: scheduleForm.frequency }
      if (scheduleForm.services.trim()) payload.services = scheduleForm.services.split(',').map(s => s.trim()).filter(Boolean)
      if (scheduleForm.regions.trim()) payload.regions = scheduleForm.regions.split(',').map(s => s.trim()).filter(Boolean)
      await api.updateSchedule(editScheduleId, payload)
      toast.success('Schedule updated')
      resetScheduleForm()
      loadData()
    } catch (err: any) {
      toast.error(err.message || 'Failed to update schedule')
    }
  }

  const handleToggleSchedule = async (s: Schedule) => {
    try {
      await api.updateSchedule(s.id, { enabled: !s.enabled })
      toast.success(s.enabled ? 'Schedule paused' : 'Schedule enabled')
      loadData()
    } catch (err: any) {
      toast.error(err.message)
    }
  }

  const handleDeleteSchedule = async (id: string) => {
    if (!confirm('Delete this schedule?')) return
    try {
      await api.deleteSchedule(id)
      toast.success('Schedule deleted')
      loadData()
    } catch (err: any) {
      toast.error(err.message)
    }
  }

  const startEditSchedule = (s: Schedule) => {
    setEditScheduleId(s.id)
    setScheduleForm({
      name: s.name,
      scan_type: s.scan_type,
      frequency: s.frequency,
      provider_id: s.provider_id || '',
      services: s.services?.join(', ') || '',
      regions: s.regions?.join(', ') || '',
    })
    setShowScheduleModal(true)
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
      render: (item: any) => (
        <div className="flex items-center gap-2">
          <Badge type="status" value={item.status} />
          {(item.status === 'pending' || item.status === 'running') && (
            <span className="relative flex h-2.5 w-2.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-brand-green opacity-75" />
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-brand-green" />
            </span>
          )}
        </div>
      ),
    },
    {
      key: 'progress',
      header: 'Progress',
      render: (item: any) => (
        <div className="flex items-center gap-2">
          <div className="w-24 bg-brand-gray-100 rounded-full h-2">
            <div
              className={`h-2 rounded-full transition-all duration-500 ${
                item.status === 'failed' ? 'bg-status-fail' : 'bg-brand-green'
              }`}
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
        breadcrumbs={[{ label: 'Scans' }]}
        actions={
          <button onClick={() => setShowModal(true)} className="btn-primary">
            New Scan
          </button>
        }
      />

      {/* Filters */}
      <div className="flex flex-wrap gap-3 mb-6">
        <select
          value={filterType}
          onChange={(e) => setFilterType(e.target.value)}
          className="select-field"
        >
          <option value="">All Types</option>
          <option value="cloud">Cloud</option>
          <option value="saas">SaaS</option>
        </select>

        <select
          value={filterStatus}
          onChange={(e) => setFilterStatus(e.target.value)}
          className="select-field"
        >
          <option value="">All Statuses</option>
          <option value="pending">Pending</option>
          <option value="running">Running</option>
          <option value="completed">Completed</option>
          <option value="failed">Failed</option>
        </select>

        {hasActiveScans(scans) && (
          <span className="flex items-center gap-2 text-xs text-brand-gray-400">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-brand-green opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-brand-green" />
            </span>
            Auto-refreshing
          </span>
        )}
      </div>

      <DataTable
        columns={columns}
        data={scans}
        loading={loading}
        emptyMessage="No scans yet. Click 'New Scan' to get started."
      />

      {/* Scheduled Scans */}
      <div className="mt-8">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-brand-navy flex items-center gap-2">
            <ClockIcon className="w-5 h-5" />
            Scheduled Scans
          </h3>
          <button
            onClick={() => { resetScheduleForm(); setShowScheduleModal(true) }}
            className="btn-primary flex items-center gap-2 text-sm"
          >
            <PlusIcon className="w-4 h-4" />
            New Schedule
          </button>
        </div>

        {/* Schedule Stats */}
        {schedules.length > 0 && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
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
        )}

        {/* Schedule List */}
        {schedules.length > 0 ? (
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
                      onClick={() => handleToggleSchedule(s)}
                      className="p-2 rounded-lg hover:bg-brand-gray-100 text-brand-gray-400 hover:text-brand-navy transition-colors"
                      title={s.enabled ? 'Pause' : 'Resume'}
                    >
                      {s.enabled ? <PauseIcon className="w-4 h-4" /> : <PlayIcon className="w-4 h-4" />}
                    </button>
                    <button
                      onClick={() => startEditSchedule(s)}
                      className="p-2 rounded-lg hover:bg-brand-gray-100 text-brand-gray-400 hover:text-brand-navy transition-colors"
                      title="Edit"
                    >
                      <PencilIcon className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => handleDeleteSchedule(s.id)}
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
        ) : (
          <div className="card text-center py-16">
            <ClockIcon className="w-12 h-12 text-brand-gray-300 mx-auto mb-4" />
            <h3 className="text-lg font-semibold text-brand-navy mb-2">No Schedules Yet</h3>
            <p className="text-brand-gray-400 mb-6">
              Create automated schedules to run security scans on a recurring basis.
            </p>
            <button onClick={() => setShowScheduleModal(true)} className="btn-primary">
              Create Your First Schedule
            </button>
          </div>
        )}
      </div>

      {/* Schedule Create/Edit Modal */}
      {showScheduleModal && (
        <div className="modal-backdrop">
          <div className="bg-white rounded-xl shadow-xl p-6 w-full max-w-lg">
            <h3 className="text-lg font-semibold text-brand-navy mb-4">
              {editScheduleId ? 'Edit Schedule' : 'Create Schedule'}
            </h3>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Schedule Name</label>
                <input
                  type="text"
                  value={scheduleForm.name}
                  onChange={(e) => setScheduleForm({ ...scheduleForm, name: e.target.value })}
                  className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm"
                  placeholder="e.g., Nightly AWS Scan"
                />
              </div>

              {!editScheduleId && (
                <>
                  <div>
                    <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Scan Type</label>
                    <select
                      value={scheduleForm.scan_type}
                      onChange={(e) => setScheduleForm({ ...scheduleForm, scan_type: e.target.value })}
                      className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm"
                    >
                      <option value="cloud">Cloud Infrastructure</option>
                      <option value="saas">SaaS Applications</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Provider (optional)</label>
                    <select
                      value={scheduleForm.provider_id}
                      onChange={(e) => setScheduleForm({ ...scheduleForm, provider_id: e.target.value })}
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
                  value={scheduleForm.frequency}
                  onChange={(e) => setScheduleForm({ ...scheduleForm, frequency: e.target.value })}
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
                  value={scheduleForm.services}
                  onChange={(e) => setScheduleForm({ ...scheduleForm, services: e.target.value })}
                  className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm"
                  placeholder="e.g., iam, s3, ec2"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Regions (comma-separated, optional)</label>
                <input
                  type="text"
                  value={scheduleForm.regions}
                  onChange={(e) => setScheduleForm({ ...scheduleForm, regions: e.target.value })}
                  className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm"
                  placeholder="e.g., us-east-1, eu-west-1"
                />
              </div>
            </div>
            <div className="flex gap-3 mt-6">
              <button onClick={resetScheduleForm} className="flex-1 btn-outline">Cancel</button>
              <button
                onClick={editScheduleId ? handleUpdateSchedule : handleCreateSchedule}
                disabled={!scheduleForm.name}
                className="flex-1 btn-primary disabled:opacity-50"
              >
                {editScheduleId ? 'Update' : 'Create'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* New Scan Modal */}
      {showModal && (
        <div className="modal-backdrop">
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
