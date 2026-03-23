'use client'

import { useState, useMemo } from 'react'
import { cn } from '@/lib/utils'
import { ChevronLeftIcon, ChevronRightIcon } from '@heroicons/react/24/outline'

interface Column<T> {
  key: string
  header: string
  render?: (item: T) => React.ReactNode
  className?: string
  sortable?: boolean
}

interface DataTableProps<T> {
  columns: Column<T>[]
  data: T[]
  emptyMessage?: string
  emptyIcon?: React.ReactNode
  loading?: boolean
  pageSize?: number
  onRowClick?: (item: T) => void
  rowClassName?: (item: T) => string
}

export default function DataTable<T extends Record<string, any>>({
  columns,
  data,
  emptyMessage = 'No data available',
  emptyIcon,
  loading,
  pageSize = 20,
  onRowClick,
  rowClassName,
}: DataTableProps<T>) {
  const [page, setPage] = useState(0)
  const [sortKey, setSortKey] = useState<string | null>(null)
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc')

  const sortedData = useMemo(() => {
    if (!sortKey) return data
    const col = columns.find(c => c.key === sortKey)
    if (!col) return data
    return [...data].sort((a, b) => {
      const va = a[sortKey]
      const vb = b[sortKey]
      if (va == null && vb == null) return 0
      if (va == null) return 1
      if (vb == null) return -1
      const cmp = typeof va === 'number' ? va - vb : String(va).localeCompare(String(vb))
      return sortDir === 'asc' ? cmp : -cmp
    })
  }, [data, sortKey, sortDir, columns])

  const totalPages = Math.max(1, Math.ceil(sortedData.length / pageSize))
  const pageData = sortedData.slice(page * pageSize, (page + 1) * pageSize)

  const handleSort = (key: string) => {
    if (sortKey === key) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    } else {
      setSortKey(key)
      setSortDir('asc')
    }
    setPage(0)
  }

  if (loading) {
    return (
      <div className="card-static">
        <div className="space-y-3">
          <div className="h-10 skeleton-shimmer rounded" />
          {[...Array(5)].map((_, i) => (
            <div key={i} className="h-12 skeleton-shimmer rounded" />
          ))}
        </div>
      </div>
    )
  }

  return (
    <div className="card-static overflow-hidden p-0">
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-brand-gray-200">
          <thead>
            <tr className="bg-brand-gray-50/80">
              {columns.map((col) => (
                <th
                  key={col.key}
                  onClick={col.sortable ? () => handleSort(col.key) : undefined}
                  className={cn(
                    'px-6 py-3 text-left text-xs font-semibold text-brand-gray-500 uppercase tracking-wider',
                    col.sortable && 'cursor-pointer hover:text-brand-gray-700 select-none',
                    col.className
                  )}
                >
                  <span className="flex items-center gap-1">
                    {col.header}
                    {col.sortable && sortKey === col.key && (
                      <span className="text-brand-green">
                        {sortDir === 'asc' ? '\u2191' : '\u2193'}
                      </span>
                    )}
                  </span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-brand-gray-100">
            {pageData.length === 0 ? (
              <tr>
                <td
                  colSpan={columns.length}
                  className="px-6 py-16 text-center"
                >
                  <div className="flex flex-col items-center gap-3">
                    {emptyIcon && (
                      <div className="text-brand-gray-300">
                        {emptyIcon}
                      </div>
                    )}
                    <p className="text-brand-gray-400 text-sm">{emptyMessage}</p>
                  </div>
                </td>
              </tr>
            ) : (
              pageData.map((item, idx) => (
                <tr
                  key={idx}
                  onClick={onRowClick ? () => onRowClick(item) : undefined}
                  className={cn(
                    'hover:bg-brand-gray-50 transition-colors',
                    onRowClick && 'cursor-pointer',
                    rowClassName?.(item)
                  )}
                >
                  {columns.map((col) => (
                    <td key={col.key} className={cn('px-6 py-4 text-sm', col.className)}>
                      {col.render ? col.render(item) : item[col.key]}
                    </td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {sortedData.length > pageSize && (
        <div className="flex items-center justify-between px-6 py-3 border-t border-brand-gray-200 bg-brand-gray-50/50">
          <p className="text-xs text-brand-gray-400">
            Showing {page * pageSize + 1}–{Math.min((page + 1) * pageSize, sortedData.length)} of {sortedData.length}
          </p>
          <div className="flex items-center gap-1">
            <button
              onClick={() => setPage(p => Math.max(0, p - 1))}
              disabled={page === 0}
              className="p-1.5 rounded-lg hover:bg-brand-gray-200 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
            >
              <ChevronLeftIcon className="w-4 h-4 text-brand-gray-600" />
            </button>
            {Array.from({ length: Math.min(totalPages, 7) }, (_, i) => {
              let pageNum: number
              if (totalPages <= 7) {
                pageNum = i
              } else if (page < 3) {
                pageNum = i
              } else if (page > totalPages - 4) {
                pageNum = totalPages - 7 + i
              } else {
                pageNum = page - 3 + i
              }
              return (
                <button
                  key={pageNum}
                  onClick={() => setPage(pageNum)}
                  className={cn(
                    'w-8 h-8 rounded-lg text-xs font-medium transition-colors',
                    page === pageNum
                      ? 'bg-brand-green text-white'
                      : 'text-brand-gray-500 hover:bg-brand-gray-200'
                  )}
                >
                  {pageNum + 1}
                </button>
              )
            })}
            <button
              onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
              disabled={page >= totalPages - 1}
              className="p-1.5 rounded-lg hover:bg-brand-gray-200 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
            >
              <ChevronRightIcon className="w-4 h-4 text-brand-gray-600" />
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
