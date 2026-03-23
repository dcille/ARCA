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
  BuildingOffice2Icon,
  UserPlusIcon,
  TrashIcon,
} from '@heroicons/react/24/outline'

type Tab = 'profile' | 'organization'

export default function SettingsPage() {
  const { user } = useAuthStore()
  const [tab, setTab] = useState<Tab>('profile')
  const [profile, setProfile] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [stats, setStats] = useState<{ providers: number; scans: number; findings: number }>({
    providers: 0,
    scans: 0,
    findings: 0,
  })

  // Organization state
  const [org, setOrg] = useState<any>(null)
  const [members, setMembers] = useState<any[]>([])
  const [orgLoading, setOrgLoading] = useState(false)
  const [showCreateOrg, setShowCreateOrg] = useState(false)
  const [showInvite, setShowInvite] = useState(false)
  const [orgForm, setOrgForm] = useState({ name: '', slug: '' })
  const [inviteEmail, setInviteEmail] = useState('')
  const [inviteRole, setInviteRole] = useState('member')

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

  const loadOrg = async () => {
    setOrgLoading(true)
    try {
      const [orgData, membersData] = await Promise.all([
        api.getCurrentOrganization().catch(() => null),
        api.getOrganizationMembers().catch(() => []),
      ])
      setOrg(orgData)
      setMembers(membersData)
    } catch (err) {
      console.error(err)
    } finally {
      setOrgLoading(false)
    }
  }

  useEffect(() => {
    if (tab === 'organization') loadOrg()
  }, [tab])

  const handleCreateOrg = async () => {
    try {
      await api.createOrganization(orgForm)
      toast.success('Organization created!')
      setShowCreateOrg(false)
      setOrgForm({ name: '', slug: '' })
      loadOrg()
    } catch (err: any) {
      toast.error(err.message || 'Failed to create organization')
    }
  }

  const handleInvite = async () => {
    try {
      await api.inviteMember(inviteEmail, inviteRole)
      toast.success('Member invited!')
      setShowInvite(false)
      setInviteEmail('')
      loadOrg()
    } catch (err: any) {
      toast.error(err.message || 'Failed to invite member')
    }
  }

  const handleRemoveMember = async (userId: string) => {
    if (!confirm('Remove this member from the organization?')) return
    try {
      await api.removeMember(userId)
      toast.success('Member removed')
      loadOrg()
    } catch (err: any) {
      toast.error(err.message)
    }
  }

  const handleChangeRole = async (userId: string, role: string) => {
    try {
      await api.updateMemberRole(userId, role)
      toast.success('Role updated')
      loadOrg()
    } catch (err: any) {
      toast.error(err.message)
    }
  }

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

      {/* Tab navigation */}
      <div className="flex gap-1 mb-6 bg-brand-gray-100 rounded-lg p-1 w-fit">
        {([
          { id: 'profile' as Tab, label: 'Profile' },
          { id: 'organization' as Tab, label: 'Organization' },
        ]).map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
              tab === t.id
                ? 'bg-white text-brand-navy shadow-sm'
                : 'text-brand-gray-500 hover:text-brand-gray-700'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Profile Tab */}
      {tab === 'profile' && (
        <>
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
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

          <div className="card mt-6">
            <h4 className="text-sm font-semibold text-brand-navy mb-4">Platform Information</h4>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
              <div className="flex justify-between py-2 border-b border-brand-gray-100">
                <span className="text-brand-gray-400">Version</span>
                <span className="text-brand-gray-700 font-medium">1.0.0</span>
              </div>
              <div className="flex justify-between py-2 border-b border-brand-gray-100">
                <span className="text-brand-gray-400">Cloud Providers</span>
                <span className="text-brand-gray-700 font-medium">AWS, Azure, GCP, K8s, OCI, Alibaba</span>
              </div>
              <div className="flex justify-between py-2 border-b border-brand-gray-100">
                <span className="text-brand-gray-400">SaaS Integrations</span>
                <span className="text-brand-gray-700 font-medium">8 providers</span>
              </div>
            </div>
          </div>
        </>
      )}

      {/* Organization Tab */}
      {tab === 'organization' && (
        <div className="space-y-6">
          {orgLoading ? (
            <div className="card animate-pulse">
              <div className="h-32 bg-brand-gray-100 rounded" />
            </div>
          ) : !org ? (
            <div className="card text-center py-12">
              <BuildingOffice2Icon className="w-12 h-12 text-brand-gray-300 mx-auto mb-4" />
              <h3 className="text-lg font-semibold text-brand-navy mb-2">No Organization</h3>
              <p className="text-brand-gray-400 mb-6">Create an organization to collaborate with your team.</p>
              <button
                onClick={() => setShowCreateOrg(true)}
                className="btn-primary"
              >
                Create Organization
              </button>
            </div>
          ) : (
            <>
              {/* Org Info Card */}
              <div className="card">
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-4">
                    <div className="w-14 h-14 rounded-lg bg-brand-navy flex items-center justify-center">
                      <span className="text-brand-green font-bold text-xl">
                        {org.name?.charAt(0)?.toUpperCase() || 'O'}
                      </span>
                    </div>
                    <div>
                      <h3 className="text-lg font-semibold text-brand-navy">{org.name}</h3>
                      <p className="text-sm text-brand-gray-400">/{org.slug}</p>
                    </div>
                  </div>
                  <span className="px-3 py-1 rounded-full text-xs font-medium bg-brand-blue/10 text-brand-blue capitalize">
                    {org.plan} plan
                  </span>
                </div>
              </div>

              {/* Members */}
              <div className="card">
                <div className="flex items-center justify-between mb-6">
                  <h4 className="text-sm font-semibold text-brand-navy">
                    Team Members ({members.length})
                  </h4>
                  <button
                    onClick={() => setShowInvite(true)}
                    className="btn-primary flex items-center gap-2 text-sm"
                  >
                    <UserPlusIcon className="w-4 h-4" />
                    Invite Member
                  </button>
                </div>

                <div className="space-y-3">
                  {members.map((m) => (
                    <div key={m.id} className="flex items-center justify-between py-3 border-b border-brand-gray-100 last:border-0">
                      <div className="flex items-center gap-3">
                        <div className="w-8 h-8 rounded-full bg-brand-green/20 flex items-center justify-center">
                          <span className="text-brand-green text-sm font-semibold">
                            {m.name?.charAt(0)?.toUpperCase() || 'U'}
                          </span>
                        </div>
                        <div>
                          <p className="text-sm font-medium text-brand-navy">{m.name}</p>
                          <p className="text-xs text-brand-gray-400">{m.email}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-3">
                        <select
                          value={m.org_role}
                          onChange={(e) => handleChangeRole(m.id, e.target.value)}
                          className="px-2 py-1 text-xs border border-brand-gray-200 rounded-lg"
                          disabled={m.org_role === 'owner'}
                        >
                          <option value="owner">Owner</option>
                          <option value="admin">Admin</option>
                          <option value="member">Member</option>
                          <option value="viewer">Viewer</option>
                        </select>
                        {m.org_role !== 'owner' && m.id !== profile?.id && (
                          <button
                            onClick={() => handleRemoveMember(m.id)}
                            className="p-1.5 rounded-lg hover:bg-red-50 text-brand-gray-400 hover:text-red-500"
                          >
                            <TrashIcon className="w-4 h-4" />
                          </button>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </>
          )}

          {/* Create Organization Modal */}
          {showCreateOrg && (
            <div className="modal-backdrop">
              <div className="bg-white rounded-xl shadow-xl p-6 w-full max-w-md">
                <h3 className="text-lg font-semibold text-brand-navy mb-4">Create Organization</h3>
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Organization Name</label>
                    <input
                      type="text"
                      value={orgForm.name}
                      onChange={(e) => setOrgForm({
                        name: e.target.value,
                        slug: e.target.value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, ''),
                      })}
                      className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm"
                      placeholder="My Company"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">URL Slug</label>
                    <input
                      type="text"
                      value={orgForm.slug}
                      onChange={(e) => setOrgForm({ ...orgForm, slug: e.target.value })}
                      className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm font-mono"
                      placeholder="my-company"
                    />
                  </div>
                </div>
                <div className="flex gap-3 mt-6">
                  <button onClick={() => setShowCreateOrg(false)} className="flex-1 btn-outline">Cancel</button>
                  <button
                    onClick={handleCreateOrg}
                    disabled={!orgForm.name || !orgForm.slug}
                    className="flex-1 btn-primary disabled:opacity-50"
                  >
                    Create
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Invite Member Modal */}
          {showInvite && (
            <div className="modal-backdrop">
              <div className="bg-white rounded-xl shadow-xl p-6 w-full max-w-md">
                <h3 className="text-lg font-semibold text-brand-navy mb-4">Invite Team Member</h3>
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Email Address</label>
                    <input
                      type="email"
                      value={inviteEmail}
                      onChange={(e) => setInviteEmail(e.target.value)}
                      className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm"
                      placeholder="colleague@company.com"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">Role</label>
                    <select
                      value={inviteRole}
                      onChange={(e) => setInviteRole(e.target.value)}
                      className="w-full px-3 py-2 border border-brand-gray-300 rounded-lg text-sm"
                    >
                      <option value="admin">Admin</option>
                      <option value="member">Member</option>
                      <option value="viewer">Viewer</option>
                    </select>
                  </div>
                </div>
                <div className="flex gap-3 mt-6">
                  <button onClick={() => setShowInvite(false)} className="flex-1 btn-outline">Cancel</button>
                  <button
                    onClick={handleInvite}
                    disabled={!inviteEmail}
                    className="flex-1 btn-primary disabled:opacity-50"
                  >
                    Send Invite
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
