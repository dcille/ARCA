'use client'

import { useEffect, useState } from 'react'
import Header from '@/components/layout/Header'
import { api } from '@/lib/api'
import toast from 'react-hot-toast'
import {
  BellIcon,
  BellSlashIcon,
  CheckCircleIcon,
  ExclamationTriangleIcon,
  InformationCircleIcon,
  ShieldExclamationIcon,
  CheckIcon,
} from '@heroicons/react/24/outline'
import Link from 'next/link'

interface Notification {
  id: string
  title: string
  message: string
  type: string
  severity: string | null
  read: boolean
  link: string | null
  created_at: string
}

export default function NotificationsPage() {
  const [notifications, setNotifications] = useState<Notification[]>([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState<'all' | 'unread'>('all')

  const load = async () => {
    try {
      const data = await api.getNotifications(filter === 'unread')
      setNotifications(data)
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [filter])

  const handleMarkRead = async (id: string) => {
    try {
      await api.markNotificationRead(id)
      setNotifications(prev =>
        prev.map(n => n.id === id ? { ...n, read: true } : n)
      )
    } catch (err: any) {
      toast.error(err.message)
    }
  }

  const handleMarkAllRead = async () => {
    try {
      await api.markAllNotificationsRead()
      setNotifications(prev => prev.map(n => ({ ...n, read: true })))
      toast.success('All notifications marked as read')
    } catch (err: any) {
      toast.error(err.message)
    }
  }

  const unreadCount = notifications.filter(n => !n.read).length

  const getIcon = (type: string, severity: string | null) => {
    if (severity === 'critical' || severity === 'high') {
      return <ShieldExclamationIcon className="w-5 h-5 text-red-500" />
    }
    if (type === 'scan_complete') {
      return <CheckCircleIcon className="w-5 h-5 text-brand-green" />
    }
    if (type === 'critical_finding') {
      return <ExclamationTriangleIcon className="w-5 h-5 text-orange-500" />
    }
    return <InformationCircleIcon className="w-5 h-5 text-blue-500" />
  }

  const timeAgo = (dateStr: string) => {
    const diff = Date.now() - new Date(dateStr).getTime()
    const mins = Math.floor(diff / 60000)
    if (mins < 1) return 'Just now'
    if (mins < 60) return `${mins}m ago`
    const hours = Math.floor(mins / 60)
    if (hours < 24) return `${hours}h ago`
    const days = Math.floor(hours / 24)
    if (days < 7) return `${days}d ago`
    return new Date(dateStr).toLocaleDateString()
  }

  if (loading) {
    return (
      <div>
        <Header title="Notifications" subtitle="Stay updated on scans, findings, and system events" />
        <div className="card animate-pulse"><div className="h-48 bg-brand-gray-100 rounded" /></div>
      </div>
    )
  }

  return (
    <div>
      <Header title="Notifications" subtitle="Stay updated on scans, findings, and system events" />

      {/* Actions bar */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex gap-1 bg-brand-gray-100 rounded-lg p-1">
          {(['all', 'unread'] as const).map(f => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                filter === f
                  ? 'bg-white text-brand-navy shadow-sm'
                  : 'text-brand-gray-500 hover:text-brand-gray-700'
              }`}
            >
              {f === 'all' ? 'All' : `Unread (${unreadCount})`}
            </button>
          ))}
        </div>

        {unreadCount > 0 && (
          <button
            onClick={handleMarkAllRead}
            className="flex items-center gap-2 text-sm text-brand-gray-500 hover:text-brand-navy transition-colors"
          >
            <CheckIcon className="w-4 h-4" />
            Mark all as read
          </button>
        )}
      </div>

      {/* Notifications list */}
      {notifications.length === 0 ? (
        <div className="card text-center py-16">
          <BellSlashIcon className="w-12 h-12 text-brand-gray-300 mx-auto mb-4" />
          <h3 className="text-lg font-semibold text-brand-navy mb-2">
            {filter === 'unread' ? 'No Unread Notifications' : 'No Notifications'}
          </h3>
          <p className="text-brand-gray-400">
            {filter === 'unread'
              ? 'You\'re all caught up! Switch to "All" to see previous notifications.'
              : 'Notifications will appear here when scans complete, critical findings are detected, or system events occur.'}
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {notifications.map((n) => (
            <div
              key={n.id}
              className={`card hover:shadow-md transition-shadow cursor-pointer ${
                !n.read ? 'border-l-4 border-l-brand-green bg-brand-green/[0.02]' : ''
              }`}
              onClick={() => !n.read && handleMarkRead(n.id)}
            >
              <div className="flex items-start gap-3">
                <div className="flex-shrink-0 mt-0.5">
                  {getIcon(n.type, n.severity)}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <h4 className={`text-sm ${!n.read ? 'font-semibold text-brand-navy' : 'font-medium text-brand-gray-600'}`}>
                      {n.title}
                    </h4>
                    {!n.read && (
                      <span className="w-2 h-2 rounded-full bg-brand-green flex-shrink-0" />
                    )}
                  </div>
                  <p className="text-sm text-brand-gray-500 mt-0.5 line-clamp-2">{n.message}</p>
                  <div className="flex items-center gap-3 mt-2">
                    <span className="text-xs text-brand-gray-400">{timeAgo(n.created_at)}</span>
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-brand-gray-100 text-brand-gray-500">
                      {n.type.replace(/_/g, ' ')}
                    </span>
                    {n.severity && (
                      <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold ${
                        n.severity === 'critical' ? 'bg-red-100 text-red-700' :
                        n.severity === 'high' ? 'bg-orange-100 text-orange-700' :
                        n.severity === 'medium' ? 'bg-yellow-100 text-yellow-700' :
                        'bg-blue-100 text-blue-700'
                      }`}>
                        {n.severity}
                      </span>
                    )}
                    {n.link && (
                      <Link
                        href={n.link}
                        className="text-xs text-brand-green hover:text-brand-green/80 font-medium"
                        onClick={(e) => e.stopPropagation()}
                      >
                        View details
                      </Link>
                    )}
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
