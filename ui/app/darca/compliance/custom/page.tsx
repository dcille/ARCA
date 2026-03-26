'use client'

import { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import Header from '@/components/layout/Header'
import {
  PlusIcon,
  DocumentDuplicateIcon,
  TrashIcon,
  ShieldCheckIcon,
  ChevronRightIcon,
} from '@heroicons/react/24/outline'
import { api } from '@/lib/api'
import toast from 'react-hot-toast'
import CreateFrameworkWizard from '@/components/compliance/CreateFrameworkWizard'

export default function CustomFrameworksPage() {
  const router = useRouter()
  const [frameworks, setFrameworks] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [showWizard, setShowWizard] = useState(false)

  const fetchFrameworks = async () => {
    try {
      const data = await api.getCustomFrameworks()
      setFrameworks(data)
    } catch (err) {
      console.error('Failed to fetch frameworks:', err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchFrameworks() }, [])

  const handleDelete = async (id: string, name: string) => {
    if (!confirm(`Delete framework "${name}"? This cannot be undone.`)) return
    try {
      await api.deleteCustomFramework(id)
      toast.success('Framework deleted')
      fetchFrameworks()
    } catch (err: any) {
      toast.error(err.message || 'Failed to delete')
    }
  }

  const handleClone = async (id: string) => {
    try {
      await api.cloneCustomFramework(id)
      toast.success('Framework cloned')
      fetchFrameworks()
    } catch (err: any) {
      toast.error(err.message || 'Failed to clone')
    }
  }

  return (
    <div>
      <Header
        title="Custom Frameworks"
        subtitle="Create and manage your own compliance frameworks"
        breadcrumbs={[
          { label: 'Compliance', href: '/darca/compliance' },
          { label: 'Custom Frameworks' },
        ]}
        actions={
          <button
            onClick={() => setShowWizard(true)}
            className="btn-primary px-4 py-2 text-sm flex items-center gap-2"
          >
            <PlusIcon className="w-4 h-4" />
            Create Framework
          </button>
        }
      />

      <div className="p-6 animate-fade-in">
        {loading ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {[...Array(3)].map((_, i) => (
              <div key={i} className="card-static p-6">
                <div className="h-5 w-48 skeleton-shimmer rounded mb-3" />
                <div className="h-4 w-full skeleton-shimmer rounded mb-2" />
                <div className="h-4 w-32 skeleton-shimmer rounded" />
              </div>
            ))}
          </div>
        ) : frameworks.length === 0 ? (
          <div className="card-static p-12 text-center">
            <ShieldCheckIcon className="w-16 h-16 mx-auto text-brand-gray-300 mb-4" />
            <h3 className="text-lg font-semibold text-brand-gray-700 mb-2">No custom frameworks yet</h3>
            <p className="text-sm text-brand-gray-500 mb-6 max-w-md mx-auto">
              Create your own compliance framework by selecting checks from the registry
              (1,600+ CIS and scanner checks) or defining your own custom controls.
            </p>
            <button
              onClick={() => setShowWizard(true)}
              className="btn-primary px-6 py-2 text-sm inline-flex items-center gap-2"
            >
              <PlusIcon className="w-4 h-4" />
              Create Your First Framework
            </button>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {frameworks.map(fw => (
              <div
                key={fw.id}
                className="card p-5 cursor-pointer group"
                onClick={() => router.push(`/darca/compliance/custom/${fw.id}`)}
              >
                <div className="flex items-start justify-between mb-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <h3 className="text-base font-semibold text-brand-gray-900 truncate">{fw.name}</h3>
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-purple-100 text-purple-700 font-medium flex-shrink-0">
                        CUSTOM
                      </span>
                    </div>
                    <p className="text-xs text-brand-gray-500 mt-0.5">v{fw.version}</p>
                  </div>
                  <ChevronRightIcon className="w-5 h-5 text-brand-gray-400 group-hover:text-brand-green transition-colors flex-shrink-0" />
                </div>

                {fw.description && (
                  <p className="text-sm text-brand-gray-600 mb-3 line-clamp-2">{fw.description}</p>
                )}

                <div className="flex flex-wrap gap-1 mb-3">
                  {(fw.providers || []).slice(0, 5).map((p: string) => (
                    <span key={p} className="text-[10px] px-1.5 py-0.5 bg-brand-gray-100 text-brand-gray-600 rounded">
                      {p}
                    </span>
                  ))}
                  {(fw.providers || []).length > 5 && (
                    <span className="text-[10px] px-1.5 py-0.5 bg-brand-gray-100 text-brand-gray-600 rounded">
                      +{fw.providers.length - 5}
                    </span>
                  )}
                </div>

                <div className="flex items-center justify-between text-xs text-brand-gray-500 border-t border-brand-gray-100 pt-3">
                  <div className="flex gap-3">
                    <span>{fw.total_checks} registry checks</span>
                    <span>{fw.total_custom_controls} custom controls</span>
                  </div>
                  <div className="flex gap-1" onClick={e => e.stopPropagation()}>
                    <button
                      onClick={() => handleClone(fw.id)}
                      className="p-1.5 hover:bg-brand-gray-100 rounded"
                      title="Clone"
                    >
                      <DocumentDuplicateIcon className="w-3.5 h-3.5 text-brand-gray-400" />
                    </button>
                    <button
                      onClick={() => handleDelete(fw.id, fw.name)}
                      className="p-1.5 hover:bg-red-50 rounded"
                      title="Delete"
                    >
                      <TrashIcon className="w-3.5 h-3.5 text-brand-gray-400 hover:text-red-500" />
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {showWizard && (
        <CreateFrameworkWizard
          onClose={() => setShowWizard(false)}
          onCreated={(fw) => {
            setShowWizard(false)
            fetchFrameworks()
            router.push(`/darca/compliance/custom/${fw.id}`)
          }}
        />
      )}
    </div>
  )
}
