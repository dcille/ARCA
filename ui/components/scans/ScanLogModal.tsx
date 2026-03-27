'use client'

import { useEffect, useState } from 'react'
import { api } from '@/lib/api'
import {
  XMarkIcon,
  CheckCircleIcon,
  ExclamationTriangleIcon,
  CommandLineIcon,
  ClockIcon,
  CpuChipIcon,
  ServerIcon,
} from '@heroicons/react/24/outline'
import { cn } from '@/lib/utils'

interface ScanLogModalProps {
  scanId: string
  onClose: () => void
}

const EVENT_ICONS: Record<string, string> = {
  phase_start: '🔵',
  phase_end: '🟢',
  module_start: '▶️',
  module_end: '✅',
  api_call: '🔗',
  error: '❌',
}

const STATUS_COLORS: Record<string, string> = {
  success: 'text-green-600 bg-green-50',
  error: 'text-red-600 bg-red-50',
  running: 'text-blue-600 bg-blue-50',
  skipped: 'text-gray-500 bg-gray-50',
}

export default function ScanLogModal({ scanId, onClose }: ScanLogModalProps) {
  const [logData, setLogData] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [activeTab, setActiveTab] = useState<'summary' | 'entries'>('summary')

  useEffect(() => {
    const fetchLogs = async () => {
      try {
        const data = await api.getScanLogs(scanId)
        setLogData(data)
      } catch (err: any) {
        setError(err.message || 'Failed to load scan logs')
      } finally {
        setLoading(false)
      }
    }
    fetchLogs()
  }, [scanId])

  const formatDuration = (ms: number) => {
    if (ms < 1000) return `${Math.round(ms)}ms`
    if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`
    return `${(ms / 60000).toFixed(1)}m`
  }

  const formatTimestamp = (ts: string) => {
    try {
      const d = new Date(ts)
      return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
    } catch {
      return ts
    }
  }

  const summary = logData?.scan_log?.summary
  const entries = logData?.scan_log?.entries || []

  return (
    <div className="modal-backdrop" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="bg-white rounded-xl shadow-xl w-full max-w-3xl max-h-[85vh] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-brand-gray-100">
          <div>
            <h3 className="text-lg font-semibold text-brand-navy">Scan Logs</h3>
            <p className="text-xs text-brand-gray-400 mt-0.5">
              Scan ID: {scanId.slice(0, 8)}...
              {logData && (
                <span className={cn(
                  'ml-2 px-2 py-0.5 rounded-full text-[10px] font-semibold',
                  logData.status === 'completed' ? 'bg-green-100 text-green-700' :
                  logData.status === 'failed' ? 'bg-red-100 text-red-700' :
                  'bg-blue-100 text-blue-700'
                )}>
                  {logData.status}
                </span>
              )}
            </p>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-lg hover:bg-brand-gray-100 text-brand-gray-400 hover:text-brand-navy transition-colors"
          >
            <XMarkIcon className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-auto">
          {loading ? (
            <div className="flex items-center justify-center py-20">
              <div className="animate-spin rounded-full h-8 w-8 border-2 border-brand-green border-t-transparent" />
              <span className="ml-3 text-brand-gray-400">Loading logs...</span>
            </div>
          ) : error ? (
            <div className="flex flex-col items-center justify-center py-20">
              <ExclamationTriangleIcon className="w-10 h-10 text-red-400 mb-3" />
              <p className="text-red-600 font-medium">{error}</p>
            </div>
          ) : !logData?.scan_log ? (
            <div className="flex flex-col items-center justify-center py-20">
              <CommandLineIcon className="w-10 h-10 text-brand-gray-300 mb-3" />
              <p className="text-brand-gray-400 font-medium">No logs available for this scan</p>
              <p className="text-brand-gray-300 text-sm mt-1">Logs are generated when the scan completes</p>
            </div>
          ) : (
            <>
              {/* Tabs */}
              <div className="flex border-b border-brand-gray-100 px-6">
                <button
                  onClick={() => setActiveTab('summary')}
                  className={cn(
                    'px-4 py-2.5 text-sm font-medium border-b-2 transition-colors',
                    activeTab === 'summary'
                      ? 'border-brand-green text-brand-green'
                      : 'border-transparent text-brand-gray-400 hover:text-brand-navy'
                  )}
                >
                  Summary
                </button>
                <button
                  onClick={() => setActiveTab('entries')}
                  className={cn(
                    'px-4 py-2.5 text-sm font-medium border-b-2 transition-colors',
                    activeTab === 'entries'
                      ? 'border-brand-green text-brand-green'
                      : 'border-transparent text-brand-gray-400 hover:text-brand-navy'
                  )}
                >
                  Execution Log ({entries.length})
                </button>
              </div>

              {activeTab === 'summary' && summary && (
                <div className="p-6 space-y-6">
                  {/* Stats */}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div className="bg-brand-gray-50 rounded-lg p-4 text-center">
                      <ClockIcon className="w-5 h-5 text-brand-gray-400 mx-auto mb-1" />
                      <p className="text-lg font-bold text-brand-navy">{formatDuration(summary.total_duration_ms)}</p>
                      <p className="text-[10px] text-brand-gray-400 uppercase font-semibold">Duration</p>
                    </div>
                    <div className="bg-brand-gray-50 rounded-lg p-4 text-center">
                      <CpuChipIcon className="w-5 h-5 text-brand-gray-400 mx-auto mb-1" />
                      <p className="text-lg font-bold text-brand-navy">{summary.total_steps}</p>
                      <p className="text-[10px] text-brand-gray-400 uppercase font-semibold">Steps</p>
                    </div>
                    <div className="bg-brand-gray-50 rounded-lg p-4 text-center">
                      <ServerIcon className="w-5 h-5 text-brand-gray-400 mx-auto mb-1" />
                      <p className="text-lg font-bold text-brand-navy">{summary.total_api_calls}</p>
                      <p className="text-[10px] text-brand-gray-400 uppercase font-semibold">API Calls</p>
                    </div>
                    <div className="bg-brand-gray-50 rounded-lg p-4 text-center">
                      <ExclamationTriangleIcon className="w-5 h-5 text-brand-gray-400 mx-auto mb-1" />
                      <p className="text-lg font-bold text-brand-navy">{summary.errors?.length || 0}</p>
                      <p className="text-[10px] text-brand-gray-400 uppercase font-semibold">Errors</p>
                    </div>
                  </div>

                  {/* Phases */}
                  {summary.phases?.length > 0 && (
                    <div>
                      <h4 className="text-sm font-semibold text-brand-navy mb-3">Phases</h4>
                      <div className="space-y-2">
                        {summary.phases.map((phase: any, i: number) => (
                          <div key={i} className="flex items-center justify-between bg-brand-gray-50 rounded-lg px-4 py-3">
                            <div className="flex items-center gap-3">
                              <CheckCircleIcon className="w-4 h-4 text-green-500" />
                              <span className="text-sm font-medium text-brand-navy">{phase.phase}</span>
                            </div>
                            <div className="flex items-center gap-4 text-xs text-brand-gray-400">
                              <span>{phase.results} results</span>
                              <span className="font-mono">{formatDuration(phase.duration_ms)}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Modules */}
                  {summary.modules_executed?.length > 0 && (
                    <div>
                      <h4 className="text-sm font-semibold text-brand-navy mb-3">Modules Executed</h4>
                      <div className="flex flex-wrap gap-2">
                        {summary.modules_executed.map((mod: string, i: number) => (
                          <span key={i} className="px-2.5 py-1 bg-brand-blue/10 text-brand-blue rounded-full text-xs font-medium">
                            {mod}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Errors */}
                  {summary.errors?.length > 0 && (
                    <div>
                      <h4 className="text-sm font-semibold text-red-600 mb-3">Errors</h4>
                      <div className="space-y-2">
                        {summary.errors.map((err: any, i: number) => (
                          <div key={i} className="bg-red-50 rounded-lg px-4 py-3 border border-red-100">
                            <p className="text-xs font-mono text-red-500 mb-1">{err.module}</p>
                            <p className="text-sm text-red-700">{err.detail}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {activeTab === 'entries' && (
                <div className="p-6">
                  <div className="space-y-1">
                    {entries.map((entry: any, i: number) => (
                      <div
                        key={i}
                        className={cn(
                          'flex items-start gap-3 px-3 py-2 rounded-lg text-sm hover:bg-brand-gray-50 transition-colors',
                          entry.event === 'error' && 'bg-red-50/50'
                        )}
                      >
                        <span className="text-xs mt-0.5 flex-shrink-0 w-5 text-center">
                          {EVENT_ICONS[entry.event] || '•'}
                        </span>
                        <span className="text-[10px] text-brand-gray-300 font-mono mt-0.5 flex-shrink-0 w-16">
                          {formatTimestamp(entry.timestamp)}
                        </span>
                        <div className="flex-1 min-w-0">
                          <span className="text-brand-gray-700">{entry.detail}</span>
                          {entry.module && entry.event !== 'phase_start' && entry.event !== 'phase_end' && (
                            <span className="ml-2 text-[10px] text-brand-gray-300 font-mono">{entry.module}</span>
                          )}
                        </div>
                        <div className="flex items-center gap-2 flex-shrink-0">
                          {entry.duration_ms != null && (
                            <span className="text-[10px] font-mono text-brand-gray-300">{formatDuration(entry.duration_ms)}</span>
                          )}
                          {entry.status && (
                            <span className={cn(
                              'px-1.5 py-0.5 rounded text-[10px] font-medium',
                              STATUS_COLORS[entry.status] || 'text-brand-gray-500 bg-brand-gray-50'
                            )}>
                              {entry.status}
                            </span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-brand-gray-100 flex justify-end">
          <button onClick={onClose} className="btn-outline text-sm">
            Close
          </button>
        </div>
      </div>
    </div>
  )
}
