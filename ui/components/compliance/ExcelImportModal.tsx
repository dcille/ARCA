'use client'

import { useState, useRef } from 'react'
import { XMarkIcon, ArrowUpTrayIcon, DocumentArrowDownIcon, CheckCircleIcon, ExclamationTriangleIcon, XCircleIcon } from '@heroicons/react/24/outline'
import { api } from '@/lib/api'
import toast from 'react-hot-toast'

interface Props {
  frameworkId: string
  onClose: () => void
  onImported: () => void
}

export default function ExcelImportModal({ frameworkId, onClose, onImported }: Props) {
  const [step, setStep] = useState<'upload' | 'preview' | 'done'>('upload')
  const [uploading, setUploading] = useState(false)
  const [confirming, setConfirming] = useState(false)
  const [preview, setPreview] = useState<any>(null)
  const fileRef = useRef<HTMLInputElement>(null)

  const handleDownloadTemplate = async () => {
    try {
      await api.downloadFrameworkTemplate(frameworkId)
      toast.success('Template downloaded')
    } catch (err: any) {
      toast.error(err.message || 'Failed to download template')
    }
  }

  const handleFileUpload = async (file: File) => {
    setUploading(true)
    try {
      const result = await api.importExcelPreview(frameworkId, file)
      setPreview(result)
      setStep('preview')
    } catch (err: any) {
      toast.error(err.message || 'Failed to parse Excel file')
    } finally {
      setUploading(false)
    }
  }

  const handleConfirm = async () => {
    if (!preview?.valid?.length) return
    setConfirming(true)
    try {
      const result = await api.importExcelConfirm(frameworkId, preview.valid)
      toast.success(`Imported ${result.imported} controls`)
      setStep('done')
      setTimeout(() => {
        onImported()
        onClose()
      }, 1500)
    } catch (err: any) {
      toast.error(err.message || 'Import failed')
    } finally {
      setConfirming(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ background: 'rgba(0,0,0,0.4)', backdropFilter: 'blur(4px)' }}>
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-2xl max-h-[80vh] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-brand-gray-200">
          <h2 className="text-lg font-bold text-brand-gray-900">Import Controls from Excel</h2>
          <button onClick={onClose} className="p-2 hover:bg-brand-gray-100 rounded-lg">
            <XMarkIcon className="w-5 h-5 text-brand-gray-500" />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6">
          {step === 'upload' && (
            <div className="space-y-6">
              <div className="card-static p-4 flex items-center gap-4">
                <DocumentArrowDownIcon className="w-8 h-8 text-brand-green flex-shrink-0" />
                <div className="flex-1">
                  <p className="text-sm font-medium text-brand-gray-800">Download Template</p>
                  <p className="text-xs text-brand-gray-500">
                    Get the Excel template with reference data from the registry (all scanner check IDs, categories, etc.)
                  </p>
                </div>
                <button onClick={handleDownloadTemplate} className="btn-outline px-4 py-2 text-sm">
                  Download
                </button>
              </div>

              <div
                className="border-2 border-dashed border-brand-gray-300 rounded-xl p-8 text-center cursor-pointer hover:border-brand-green transition-colors"
                onClick={() => fileRef.current?.click()}
                onDragOver={e => e.preventDefault()}
                onDrop={e => {
                  e.preventDefault()
                  const file = e.dataTransfer.files[0]
                  if (file) handleFileUpload(file)
                }}
              >
                <ArrowUpTrayIcon className="w-10 h-10 mx-auto text-brand-gray-400 mb-3" />
                <p className="text-sm font-medium text-brand-gray-700">
                  {uploading ? 'Uploading...' : 'Drop your Excel file here or click to browse'}
                </p>
                <p className="text-xs text-brand-gray-400 mt-1">.xlsx files only</p>
                <input
                  ref={fileRef}
                  type="file"
                  accept=".xlsx,.xls"
                  className="hidden"
                  onChange={e => {
                    const file = e.target.files?.[0]
                    if (file) handleFileUpload(file)
                  }}
                />
              </div>
            </div>
          )}

          {step === 'preview' && preview && (
            <div className="space-y-4">
              <div className="grid grid-cols-3 gap-3">
                <div className="card-static p-3 text-center">
                  <CheckCircleIcon className="w-6 h-6 mx-auto text-green-500 mb-1" />
                  <p className="text-lg font-bold text-green-600">{preview.valid?.length || 0}</p>
                  <p className="text-xs text-brand-gray-500">Valid</p>
                </div>
                <div className="card-static p-3 text-center">
                  <ExclamationTriangleIcon className="w-6 h-6 mx-auto text-amber-500 mb-1" />
                  <p className="text-lg font-bold text-amber-600">{preview.warnings?.length || 0}</p>
                  <p className="text-xs text-brand-gray-500">Warnings</p>
                </div>
                <div className="card-static p-3 text-center">
                  <XCircleIcon className="w-6 h-6 mx-auto text-red-500 mb-1" />
                  <p className="text-lg font-bold text-red-600">{preview.errors?.length || 0}</p>
                  <p className="text-xs text-brand-gray-500">Errors</p>
                </div>
              </div>

              {preview.errors?.length > 0 && (
                <div className="bg-red-50 rounded-lg p-3">
                  <h4 className="text-sm font-medium text-red-700 mb-2">Errors (will not be imported)</h4>
                  <div className="space-y-1 max-h-32 overflow-y-auto">
                    {preview.errors.map((err: any, i: number) => (
                      <p key={i} className="text-xs text-red-600">Row {err.row}: {err.message}</p>
                    ))}
                  </div>
                </div>
              )}

              {preview.warnings?.length > 0 && (
                <div className="bg-amber-50 rounded-lg p-3">
                  <h4 className="text-sm font-medium text-amber-700 mb-2">Warnings</h4>
                  <div className="space-y-1 max-h-32 overflow-y-auto">
                    {preview.warnings.map((w: any, i: number) => (
                      <p key={i} className="text-xs text-amber-600">Row {w.row}: {w.message}</p>
                    ))}
                  </div>
                </div>
              )}

              {preview.valid?.length > 0 && (
                <div className="bg-green-50 rounded-lg p-3">
                  <h4 className="text-sm font-medium text-green-700 mb-2">Ready to import ({preview.valid.length} controls)</h4>
                  <div className="space-y-1 max-h-48 overflow-y-auto">
                    {preview.valid.map((ctrl: any, i: number) => (
                      <div key={i} className="flex items-center gap-2 text-xs text-green-700">
                        <CheckCircleIcon className="w-3.5 h-3.5 flex-shrink-0" />
                        <span className="font-mono">{ctrl.check_id}</span>
                        <span className="text-green-600">{ctrl.title}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {step === 'done' && (
            <div className="text-center py-8">
              <CheckCircleIcon className="w-16 h-16 mx-auto text-brand-green mb-4" />
              <h3 className="text-lg font-semibold text-brand-gray-800">Import Complete!</h3>
              <p className="text-sm text-brand-gray-500 mt-1">Controls have been added to your framework</p>
            </div>
          )}
        </div>

        {/* Footer */}
        {step === 'preview' && (
          <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-brand-gray-200">
            <button onClick={() => { setStep('upload'); setPreview(null) }} className="px-4 py-2 text-sm text-brand-gray-600">
              Upload different file
            </button>
            <button
              disabled={confirming || !preview?.valid?.length}
              onClick={handleConfirm}
              className="btn-primary px-6 py-2 text-sm disabled:opacity-40"
            >
              {confirming ? 'Importing...' : `Import ${preview?.valid?.length || 0} Controls`}
            </button>
          </div>
        )}
      </div>
    </div>
  )
}
