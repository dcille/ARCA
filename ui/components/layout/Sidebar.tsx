'use client'

import { useState, useEffect } from 'react'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { cn } from '@/lib/utils'
import {
  HomeIcon,
  ShieldCheckIcon,
  MagnifyingGlassIcon,
  CloudIcon,
  DocumentChartBarIcon,
  ServerStackIcon,
  Cog6ToothIcon,
  ArrowRightOnRectangleIcon,
  GlobeAltIcon,
  MapIcon,
  DocumentArrowDownIcon,
  CubeIcon,
  BellIcon,
} from '@heroicons/react/24/outline'
import { useAuthStore } from '@/store/auth'
import { api } from '@/lib/api'

const navigation = [
  { name: 'Overview', href: '/darca/overview', icon: HomeIcon },
  { name: 'Attack Paths', href: '/darca/attack-paths', icon: MapIcon },
  { name: 'Findings', href: '/darca/findings', icon: MagnifyingGlassIcon },
  { name: 'Compliance', href: '/darca/compliance', icon: DocumentChartBarIcon },
  { name: 'Inventory', href: '/darca/inventory', icon: CubeIcon },
  { name: 'Scans', href: '/darca/scans', icon: ShieldCheckIcon },
  { name: 'Cloud Providers', href: '/darca/providers', icon: CloudIcon },
  { name: 'SaaS Security', href: '/darca/saas-security', icon: GlobeAltIcon },
  { name: 'Reports', href: '/darca/reports', icon: DocumentArrowDownIcon },
  { name: 'Settings', href: '/darca/settings', icon: Cog6ToothIcon },
]

export default function Sidebar() {
  const pathname = usePathname()
  const { user, logout } = useAuthStore()
  const [unreadCount, setUnreadCount] = useState(0)

  useEffect(() => {
    api.getNotificationCount()
      .then(d => setUnreadCount(d.unread_count))
      .catch(() => {})
    const interval = setInterval(() => {
      api.getNotificationCount()
        .then(d => setUnreadCount(d.unread_count))
        .catch(() => {})
    }, 30000)
    return () => clearInterval(interval)
  }, [])

  return (
    <aside className="fixed inset-y-0 left-0 z-50 w-64 bg-white border-r border-brand-gray-200 flex flex-col">
      {/* Logo */}
      <div className="flex items-center gap-3 px-6 py-5 border-b border-brand-gray-200">
        <div className="w-10 h-10 rounded-lg bg-brand-navy flex items-center justify-center">
          <span className="text-brand-green font-bold text-lg">D</span>
        </div>
        <div>
          <h1 className="text-lg font-bold text-brand-navy tracking-tight">D-ARCA</h1>
          <p className="text-[10px] text-brand-gray-400 uppercase tracking-widest leading-none">
            Asset Risk & Cloud Analysis
          </p>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        <p className="px-4 text-xs font-semibold text-brand-gray-400 uppercase tracking-wider mb-2">
          Security
        </p>
        {navigation.map((item) => {
          const isActive = pathname?.startsWith(item.href)
          return (
            <Link
              key={item.name}
              href={item.href}
              className={cn(
                'sidebar-link',
                isActive ? 'sidebar-link-active' : 'sidebar-link-inactive'
              )}
            >
              <item.icon className="w-5 h-5 flex-shrink-0" />
              {item.name}
            </Link>
          )
        })}
      </nav>

      {/* User section */}
      <div className="border-t border-brand-gray-200 p-4">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-full bg-brand-green/20 flex items-center justify-center">
            <span className="text-brand-green text-sm font-semibold">
              {user?.name?.charAt(0)?.toUpperCase() || 'U'}
            </span>
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-sm font-medium text-brand-gray-700 truncate">
              {user?.name || 'User'}
            </p>
            <p className="text-xs text-brand-gray-400 truncate">
              {user?.email || ''}
            </p>
          </div>
          <Link
            href="/darca/settings"
            className="p-1.5 rounded-lg hover:bg-brand-gray-100 text-brand-gray-400 hover:text-brand-gray-600 relative"
            title="Notifications"
          >
            <BellIcon className="w-5 h-5" />
            {unreadCount > 0 && (
              <span className="absolute -top-1 -right-1 w-4 h-4 bg-red-500 text-white text-[9px] font-bold rounded-full flex items-center justify-center">
                {unreadCount > 9 ? '9+' : unreadCount}
              </span>
            )}
          </Link>
          <button
            onClick={() => {
              logout()
              window.location.href = '/auth/sign-in'
            }}
            className="p-1.5 rounded-lg hover:bg-brand-gray-100 text-brand-gray-400 hover:text-brand-gray-600"
            title="Sign out"
          >
            <ArrowRightOnRectangleIcon className="w-5 h-5" />
          </button>
        </div>
      </div>
    </aside>
  )
}
