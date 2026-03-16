'use client'

import { useEffect, useState } from 'react'
import Header from '@/components/layout/Header'
import { api } from '@/lib/api'
import { useAuthStore } from '@/store/auth'
import toast from 'react-hot-toast'
import {
  UserCircleIcon,
  ShieldCheckIcon,
  KeyIcon,
} from '@heroicons/react/24/outline'

export default function SettingsPage() {
  const { user } = useAuthStore()
  const [profile, setProfile] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [stats, setStats] = useState<{ providers: number; scans: number; findings: number }>({
    providers: 0,
    scans: 0,
    findings: 0,
  })

  useEffect(() => {
    const loadData = async () => {
      try {
        const [me, overview] = await Promise.all([
          api.getMe(),
          api.getDashboardOverview().catch(() => null),
        ])
        setProfile(me)
        if (overview) {
          setStats({
            providers: overview.total_cloud_providers + overview.total_saas_connections,
            scans: overview.total_scans,
            findings: overview.total_findings,
          })
        }
      } catch (err) {
        console.error(err)
      } finally {
        setLoading(false)
      }
    }
    loadData()
  }, [])

  if (loading) {
    return (
      <div>
        <Header title="Settings" subtitle="Manage your account and preferences" />
        <div className="card animate-pulse">
          <div className="h-48 bg-brand-gray-100 rounded" />
        </div>
      </div>
    )
  }

  return (
    <div>
      <Header title="Settings" subtitle="Manage your account and preferences" />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Profile Card */}
        <div className="lg:col-span-2 card">
          <div className="flex items-start gap-4">
            <div className="w-16 h-16 rounded-full bg-brand-green/20 flex items-center justify-center flex-shrink-0">
              <span className="text-brand-green text-2xl font-bold">
                {profile?.name?.charAt(0)?.toUpperCase() || 'U'}
              </span>
            </div>
            <div>
              <h3 className="text-xl font-semibold text-brand-navy">{profile?.name || 'User'}</h3>
              <p className="text-sm text-brand-gray-400">{profile?.email}</p>
              <span className="inline-flex items-center gap-1 mt-2 px-2.5 py-0.5 rounded-full text-xs font-medium bg-brand-green/10 text-brand-green">
                <ShieldCheckIcon className="w-3.5 h-3.5" />
                {profile?.role || 'admin'}
              </span>
            </div>
          </div>

          <div className="mt-6 grid grid-cols-3 gap-4 pt-6 border-t border-brand-gray-200">
            <div className="text-center">
              <p className="text-2xl font-bold text-brand-navy">{stats.providers}</p>
              <p className="text-xs text-brand-gray-400 uppercase font-semibold mt-1">Connections</p>
            </div>
            <div className="text-center">
              <p className="text-2xl font-bold text-brand-navy">{stats.scans}</p>
              <p className="text-xs text-brand-gray-400 uppercase font-semibold mt-1">Scans Run</p>
            </div>
            <div className="text-center">
              <p className="text-2xl font-bold text-brand-navy">{stats.findings}</p>
              <p className="text-xs text-brand-gray-400 uppercase font-semibold mt-1">Findings</p>
            </div>
          </div>
        </div>

        {/* Quick Info */}
        <div className="card">
          <h4 className="text-sm font-semibold text-brand-navy mb-4">Account Details</h4>
          <dl className="space-y-3 text-sm">
            <div className="flex items-start gap-3">
              <UserCircleIcon className="w-5 h-5 text-brand-gray-400 flex-shrink-0 mt-0.5" />
              <div>
                <dt className="text-brand-gray-400 text-xs uppercase font-semibold">Name</dt>
                <dd className="text-brand-gray-700">{profile?.name || '-'}</dd>
              </div>
            </div>
            <div className="flex items-start gap-3">
              <KeyIcon className="w-5 h-5 text-brand-gray-400 flex-shrink-0 mt-0.5" />
              <div>
                <dt className="text-brand-gray-400 text-xs uppercase font-semibold">Email</dt>
                <dd className="text-brand-gray-700">{profile?.email || '-'}</dd>
              </div>
            </div>
            <div className="flex items-start gap-3">
              <ShieldCheckIcon className="w-5 h-5 text-brand-gray-400 flex-shrink-0 mt-0.5" />
              <div>
                <dt className="text-brand-gray-400 text-xs uppercase font-semibold">Role</dt>
                <dd className="text-brand-gray-700 capitalize">{profile?.role || '-'}</dd>
              </div>
            </div>
          </dl>
        </div>
      </div>

      {/* Platform Info */}
      <div className="card mt-6">
        <h4 className="text-sm font-semibold text-brand-navy mb-4">Platform Information</h4>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
          <div className="flex justify-between py-2 border-b border-brand-gray-100">
            <span className="text-brand-gray-400">Version</span>
            <span className="text-brand-gray-700 font-medium">1.0.0</span>
          </div>
          <div className="flex justify-between py-2 border-b border-brand-gray-100">
            <span className="text-brand-gray-400">Cloud Providers</span>
            <span className="text-brand-gray-700 font-medium">AWS, Azure, GCP, K8s, OCI</span>
          </div>
          <div className="flex justify-between py-2 border-b border-brand-gray-100">
            <span className="text-brand-gray-400">SaaS Integrations</span>
            <span className="text-brand-gray-700 font-medium">ServiceNow, M365, Salesforce, Snowflake</span>
          </div>
        </div>
      </div>
    </div>
  )
}
