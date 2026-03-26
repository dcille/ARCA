'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import { MagnifyingGlassIcon, FunnelIcon, CheckIcon, XMarkIcon } from '@heroicons/react/24/outline'
import { api } from '@/lib/api'

interface Check {
  check_id: string
  title: string
  description: string
  provider: string
  service: string
  category: string
  severity: string
  assessment_type: string
  source: string
  cis_id: string | null
  has_scanner: boolean
  tags: string[]
}

interface Props {
  selectedCheckIds: Set<string>
  onSelectionChange: (ids: Set<string>) => void
  providers?: string[]
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-100 text-red-700',
  high: 'bg-orange-100 text-orange-700',
  medium: 'bg-amber-100 text-amber-700',
  low: 'bg-blue-100 text-blue-700',
  informational: 'bg-gray-100 text-gray-600',
}

const SOURCE_COLORS: Record<string, string> = {
  cis: 'bg-indigo-100 text-indigo-700',
  scanner: 'bg-teal-100 text-teal-700',
  custom: 'bg-purple-100 text-purple-700',
}

export default function RegistryCheckSelector({ selectedCheckIds, onSelectionChange, providers }: Props) {
  const [checks, setChecks] = useState<Check[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(false)
  const [search, setSearch] = useState('')
  const [filterProvider, setFilterProvider] = useState('')
  const [filterCategory, setFilterCategory] = useState('')
  const [filterSeverity, setFilterSeverity] = useState('')
  const [filterSource, setFilterSource] = useState('')
  const [showFilters, setShowFilters] = useState(false)
  const [offset, setOffset] = useState(0)
  const [stats, setStats] = useState<any>(null)
  const limit = 50
  const searchRef = useRef<ReturnType<typeof setTimeout>>()

  const fetchChecks = useCallback(async () => {
    setLoading(true)
    try {
      const params: Record<string, string> = {
        limit: String(limit),
        offset: String(offset),
      }
      if (search) params.search = search
      if (filterProvider) params.provider = filterProvider
      if (filterCategory) params.category = filterCategory
      if (filterSeverity) params.severity = filterSeverity
      if (filterSource) params.source = filterSource

      const data = await api.getAvailableChecks(params)
      setChecks(data.items || [])
      setTotal(data.total || 0)
    } catch (err) {
      console.error('Failed to fetch checks:', err)
    } finally {
      setLoading(false)
    }
  }, [search, filterProvider, filterCategory, filterSeverity, filterSource, offset])

  useEffect(() => {
    fetchChecks()
  }, [fetchChecks])

  useEffect(() => {
    api.getRegistryStats().then(setStats).catch(() => {})
  }, [])

  const handleSearchChange = (value: string) => {
    if (searchRef.current) clearTimeout(searchRef.current)
    searchRef.current = setTimeout(() => {
      setSearch(value)
      setOffset(0)
    }, 300)
  }

  const toggleCheck = (checkId: string) => {
    const next = new Set(selectedCheckIds)
    if (next.has(checkId)) {
      next.delete(checkId)
    } else {
      next.add(checkId)
    }
    onSelectionChange(next)
  }

  const selectAllVisible = () => {
    const next = new Set(selectedCheckIds)
    checks.forEach(c => next.add(c.check_id))
    onSelectionChange(next)
  }

  const clearAll = () => {
    onSelectionChange(new Set())
  }

  const totalPages = Math.ceil(total / limit)
  const currentPage = Math.floor(offset / limit)

  return (
    <div className="flex gap-4 h-full">
      {/* Left panel: catalog */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Search bar */}
        <div className="flex gap-2 mb-3">
          <div className="relative flex-1">
            <MagnifyingGlassIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-brand-gray-400" />
            <input
              type="text"
              placeholder="Search checks by ID, title, service, tags..."
              onChange={e => handleSearchChange(e.target.value)}
              className="w-full pl-10 pr-3 py-2 border border-brand-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-brand-green/40 focus:border-brand-green outline-none"
            />
          </div>
          <button
            onClick={() => setShowFilters(!showFilters)}
            className={`px-3 py-2 border rounded-lg text-sm flex items-center gap-1 ${showFilters ? 'border-brand-green text-brand-green bg-brand-green/5' : 'border-brand-gray-300 text-brand-gray-600'}`}
          >
            <FunnelIcon className="w-4 h-4" />
            Filters
          </button>
        </div>

        {/* Filter bar */}
        {showFilters && (
          <div className="flex flex-wrap gap-2 mb-3 p-3 bg-brand-gray-50 rounded-lg">
            <select
              value={filterProvider}
              onChange={e => { setFilterProvider(e.target.value); setOffset(0) }}
              className="px-2 py-1 border border-brand-gray-300 rounded text-sm bg-white"
            >
              <option value="">All Providers</option>
              {stats?.providers && Object.keys(stats.providers).sort().map((p: string) => (
                <option key={p} value={p}>{p.toUpperCase()} ({stats.providers[p]})</option>
              ))}
            </select>
            <select
              value={filterCategory}
              onChange={e => { setFilterCategory(e.target.value); setOffset(0) }}
              className="px-2 py-1 border border-brand-gray-300 rounded text-sm bg-white"
            >
              <option value="">All Categories</option>
              {stats?.categories && Object.keys(stats.categories).sort().map((c: string) => (
                <option key={c} value={c}>{c} ({stats.categories[c]})</option>
              ))}
            </select>
            <select
              value={filterSeverity}
              onChange={e => { setFilterSeverity(e.target.value); setOffset(0) }}
              className="px-2 py-1 border border-brand-gray-300 rounded text-sm bg-white"
            >
              <option value="">All Severities</option>
              {['critical', 'high', 'medium', 'low', 'informational'].map(s => (
                <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
              ))}
            </select>
            <select
              value={filterSource}
              onChange={e => { setFilterSource(e.target.value); setOffset(0) }}
              className="px-2 py-1 border border-brand-gray-300 rounded text-sm bg-white"
            >
              <option value="">All Sources</option>
              <option value="cis">CIS</option>
              <option value="scanner">Scanner</option>
              <option value="custom">Custom</option>
            </select>
            <button
              onClick={() => { setFilterProvider(''); setFilterCategory(''); setFilterSeverity(''); setFilterSource(''); setOffset(0) }}
              className="px-2 py-1 text-sm text-brand-gray-500 hover:text-brand-gray-700"
            >
              Clear filters
            </button>
          </div>
        )}

        {/* Results header */}
        <div className="flex items-center justify-between mb-2 text-sm text-brand-gray-600">
          <span>{total.toLocaleString()} checks found</span>
          <div className="flex gap-2">
            <button onClick={selectAllVisible} className="text-brand-green hover:underline text-xs">
              Select page
            </button>
            <span className="text-brand-gray-300">|</span>
            <button onClick={clearAll} className="text-brand-gray-500 hover:underline text-xs">
              Clear all
            </button>
          </div>
        </div>

        {/* Check list */}
        <div className="flex-1 overflow-y-auto border border-brand-gray-200 rounded-lg">
          {loading ? (
            <div className="p-4 space-y-3">
              {[...Array(8)].map((_, i) => (
                <div key={i} className="h-12 skeleton-shimmer rounded" />
              ))}
            </div>
          ) : checks.length === 0 ? (
            <div className="p-8 text-center text-brand-gray-400">
              No checks found matching your criteria
            </div>
          ) : (
            <div className="divide-y divide-brand-gray-100">
              {checks.map(check => {
                const selected = selectedCheckIds.has(check.check_id)
                return (
                  <div
                    key={check.check_id}
                    onClick={() => toggleCheck(check.check_id)}
                    className={`px-3 py-2 cursor-pointer hover:bg-brand-gray-50 flex items-start gap-3 transition-colors ${selected ? 'bg-brand-green/5' : ''}`}
                  >
                    <div className={`w-4 h-4 mt-0.5 rounded border flex items-center justify-center flex-shrink-0 ${
                      selected ? 'bg-brand-green border-brand-green' : 'border-brand-gray-300'
                    }`}>
                      {selected && <CheckIcon className="w-3 h-3 text-white" />}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-xs font-mono text-brand-gray-500 truncate max-w-[200px]">{check.check_id}</span>
                        <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${SOURCE_COLORS[check.source] || 'bg-gray-100 text-gray-600'}`}>
                          {check.source.toUpperCase()}
                        </span>
                        <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${SEVERITY_COLORS[check.severity] || ''}`}>
                          {check.severity}
                        </span>
                        {check.has_scanner && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-green-100 text-green-700">Auto</span>
                        )}
                      </div>
                      <p className="text-sm text-brand-gray-800 mt-0.5 line-clamp-1">{check.title}</p>
                      <div className="flex gap-2 mt-0.5 text-[11px] text-brand-gray-400">
                        <span>{check.provider}</span>
                        <span>/</span>
                        <span>{check.service}</span>
                        <span>/</span>
                        <span>{check.category}</span>
                      </div>
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between mt-2 text-sm">
            <button
              disabled={currentPage === 0}
              onClick={() => setOffset(Math.max(0, offset - limit))}
              className="px-3 py-1 border border-brand-gray-300 rounded text-sm disabled:opacity-40"
            >
              Previous
            </button>
            <span className="text-brand-gray-500">
              Page {currentPage + 1} of {totalPages}
            </span>
            <button
              disabled={currentPage >= totalPages - 1}
              onClick={() => setOffset(offset + limit)}
              className="px-3 py-1 border border-brand-gray-300 rounded text-sm disabled:opacity-40"
            >
              Next
            </button>
          </div>
        )}
      </div>

      {/* Right panel: selected summary */}
      <div className="w-64 flex-shrink-0 border border-brand-gray-200 rounded-lg p-3 bg-brand-gray-50">
        <h4 className="font-semibold text-sm text-brand-gray-800 mb-2">
          Selected ({selectedCheckIds.size})
        </h4>
        {selectedCheckIds.size === 0 ? (
          <p className="text-xs text-brand-gray-400">No checks selected yet. Click checks from the list to add them.</p>
        ) : (
          <div className="space-y-1 max-h-[400px] overflow-y-auto">
            {Array.from(selectedCheckIds).slice(0, 50).map(id => (
              <div key={id} className="flex items-center justify-between bg-white rounded px-2 py-1 text-xs">
                <span className="truncate mr-1 text-brand-gray-700 font-mono">{id}</span>
                <button
                  onClick={e => { e.stopPropagation(); toggleCheck(id) }}
                  className="text-brand-gray-400 hover:text-red-500 flex-shrink-0"
                >
                  <XMarkIcon className="w-3 h-3" />
                </button>
              </div>
            ))}
            {selectedCheckIds.size > 50 && (
              <p className="text-xs text-brand-gray-400 text-center">...and {selectedCheckIds.size - 50} more</p>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
