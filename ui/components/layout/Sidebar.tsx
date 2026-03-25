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
  BoltIcon,
  TableCellsIcon,
  Bars3Icon,
  XMarkIcon,
  ChevronDoubleLeftIcon,
  ChevronDoubleRightIcon,
  ShieldExclamationIcon,
  ClipboardDocumentListIcon,
} from '@heroicons/react/24/outline'
import { useAuthStore } from '@/store/auth'
import { api } from '@/lib/api'

interface NavSection {
  label: string
  items: { name: string; href: string; icon: any }[]
}

const sections: NavSection[] = [
  {
    label: 'Posture',
    items: [
      { name: 'Overview', href: '/darca/overview', icon: HomeIcon },
      { name: 'Attack Paths', href: '/darca/attack-paths', icon: MapIcon },
      { name: 'Findings', href: '/darca/findings', icon: MagnifyingGlassIcon },
      { name: 'Compliance', href: '/darca/compliance', icon: DocumentChartBarIcon },
      { name: 'MITRE ATT&CK', href: '/darca/mitre-attack', icon: TableCellsIcon },
      { name: 'Ransomware Readiness', href: '/darca/ransomware-readiness', icon: ShieldExclamationIcon },
    ],
  },
  {
    label: 'Assets',
    items: [
      { name: 'Security Graph', href: '/darca/security-graph', icon: GlobeAltIcon },
      { name: 'Inventory', href: '/darca/inventory', icon: CubeIcon },
      { name: 'Cloud Providers', href: '/darca/providers', icon: CloudIcon },
      { name: 'Data Security', href: '/darca/dspm', icon: ServerStackIcon },
      { name: 'SaaS Security', href: '/darca/saas-security', icon: GlobeAltIcon },
    ],
  },
  {
    label: 'Operations',
    items: [
      { name: 'Scans', href: '/darca/scans', icon: ShieldCheckIcon },
      { name: 'Notifications', href: '/darca/notifications', icon: BellIcon },
      { name: 'Reports', href: '/darca/reports', icon: DocumentArrowDownIcon },
      { name: 'Integrations', href: '/darca/integrations', icon: BoltIcon },
      { name: 'Audit Log', href: '/darca/audit-log', icon: ClipboardDocumentListIcon },
      { name: 'Settings', href: '/darca/settings', icon: Cog6ToothIcon },
    ],
  },
]

export default function Sidebar() {
  const pathname = usePathname()
  const { user, logout } = useAuthStore()
  const [unreadCount, setUnreadCount] = useState(0)
  const [criticalCount, setCriticalCount] = useState(0)
  const [mobileOpen, setMobileOpen] = useState(false)
  const [collapsed, setCollapsed] = useState(false)

  useEffect(() => {
    const fetchCounts = () => {
      api.getNotificationCount()
        .then(d => setUnreadCount(d.unread_count))
        .catch(() => {})
      api.getFindingsStats()
        .then((d: any) => setCriticalCount(d?.severity_breakdown?.critical || 0))
        .catch(() => {})
    }
    fetchCounts()
    const interval = setInterval(fetchCounts, 30000)
    return () => clearInterval(interval)
  }, [])

  // Close mobile sidebar on route change
  useEffect(() => {
    setMobileOpen(false)
  }, [pathname])

  const sidebarContent = (
    <>
      {/* Logo */}
      <div className="flex items-center gap-3 px-4 py-5 border-b border-brand-gray-200">
        <div className="w-10 h-10 rounded-lg bg-brand-navy flex items-center justify-center flex-shrink-0">
          <span className="text-brand-green font-bold text-lg">D</span>
        </div>
        {!collapsed && (
          <div className="animate-fade-in">
            <h1 className="text-lg font-bold text-brand-navy tracking-tight">D-ARCA</h1>
            <p className="text-[10px] text-brand-gray-400 uppercase tracking-widest leading-none">
              Asset Risk & Cloud Analysis
            </p>
          </div>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4 space-y-5 overflow-y-auto scrollbar-thin">
        {sections.map((section) => (
          <div key={section.label}>
            {!collapsed && (
              <p className="px-4 text-[10px] font-semibold text-brand-gray-400 uppercase tracking-widest mb-1.5">
                {section.label}
              </p>
            )}
            {collapsed && (
              <div className="w-8 mx-auto border-t border-brand-gray-200 mb-2" />
            )}
            <div className="space-y-0.5">
              {section.items.map((item) => {
                const isActive = pathname?.startsWith(item.href)
                return (
                  <Link
                    key={item.name}
                    href={item.href}
                    title={collapsed ? item.name : undefined}
                    className={cn(
                      'sidebar-link',
                      collapsed && 'justify-center px-2',
                      isActive ? 'sidebar-link-active' : 'sidebar-link-inactive'
                    )}
                  >
                    <item.icon className="w-5 h-5 flex-shrink-0" />
                    {!collapsed && <span className="flex-1">{item.name}</span>}
                    {!collapsed && item.name === 'Findings' && criticalCount > 0 && (
                      <span className="ml-auto inline-flex items-center justify-center min-w-[20px] h-5 px-1.5 rounded-full bg-severity-critical text-white text-[10px] font-bold">
                        {criticalCount > 99 ? '99+' : criticalCount}
                      </span>
                    )}
                  </Link>
                )
              })}
            </div>
          </div>
        ))}
      </nav>

      {/* Collapse toggle - desktop only */}
      <div className="hidden lg:block border-t border-brand-gray-200 px-3 py-2">
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="w-full flex items-center justify-center gap-2 px-4 py-2 rounded-lg text-brand-gray-400 hover:text-brand-gray-600 hover:bg-brand-gray-100 transition-colors text-sm"
        >
          {collapsed ? (
            <ChevronDoubleRightIcon className="w-4 h-4" />
          ) : (
            <>
              <ChevronDoubleLeftIcon className="w-4 h-4" />
              <span>Collapse</span>
            </>
          )}
        </button>
      </div>

      {/* User section */}
      <div className="border-t border-brand-gray-200 p-4">
        <div className={cn('flex items-center', collapsed ? 'flex-col gap-2' : 'gap-3')}>
          <div className="w-8 h-8 rounded-full bg-brand-green/20 flex items-center justify-center flex-shrink-0">
            <span className="text-brand-green text-sm font-semibold">
              {user?.name?.charAt(0)?.toUpperCase() || 'U'}
            </span>
          </div>
          {!collapsed && (
            <div className="flex-1 min-w-0 animate-fade-in">
              <p className="text-sm font-medium text-brand-gray-700 truncate">
                {user?.name || 'User'}
              </p>
              <p className="text-xs text-brand-gray-400 truncate">
                {user?.email || ''}
              </p>
            </div>
          )}
          <div className={cn('flex', collapsed ? 'flex-col gap-1' : 'gap-1')}>
            <Link
              href="/darca/notifications"
              className="p-1.5 rounded-lg hover:bg-brand-gray-100 text-brand-gray-400 hover:text-brand-gray-600 relative transition-colors"
              title="Notifications"
            >
              <BellIcon className="w-5 h-5" />
              {unreadCount > 0 && (
                <span className="absolute -top-1 -right-1 w-4 h-4 bg-red-500 text-white text-[9px] font-bold rounded-full flex items-center justify-center animate-scale-in">
                  {unreadCount > 9 ? '9+' : unreadCount}
                </span>
              )}
            </Link>
            <button
              onClick={() => {
                logout()
                window.location.href = '/auth/sign-in'
              }}
              className="p-1.5 rounded-lg hover:bg-brand-gray-100 text-brand-gray-400 hover:text-brand-gray-600 transition-colors"
              title="Sign out"
            >
              <ArrowRightOnRectangleIcon className="w-5 h-5" />
            </button>
          </div>
        </div>
      </div>
    </>
  )

  return (
    <>
      {/* Mobile hamburger */}
      <button
        onClick={() => setMobileOpen(true)}
        className="lg:hidden fixed top-4 left-4 z-40 p-2 rounded-lg bg-white shadow-md border border-brand-gray-200 text-brand-gray-600 hover:text-brand-navy transition-colors"
        aria-label="Open menu"
      >
        <Bars3Icon className="w-6 h-6" />
      </button>

      {/* Mobile overlay */}
      {mobileOpen && (
        <div
          className="lg:hidden fixed inset-0 z-50 bg-black/30 backdrop-blur-sm"
          onClick={() => setMobileOpen(false)}
        />
      )}

      {/* Mobile sidebar */}
      <aside
        className={cn(
          'lg:hidden fixed inset-y-0 left-0 z-50 w-64 bg-white border-r border-brand-gray-200 flex flex-col transform transition-transform duration-300 ease-in-out',
          mobileOpen ? 'translate-x-0' : '-translate-x-full'
        )}
      >
        <button
          onClick={() => setMobileOpen(false)}
          className="absolute top-4 right-4 p-1 rounded-lg text-brand-gray-400 hover:text-brand-gray-600"
          aria-label="Close menu"
        >
          <XMarkIcon className="w-5 h-5" />
        </button>
        {sidebarContent}
      </aside>

      {/* Desktop sidebar */}
      <aside
        className={cn(
          'hidden lg:flex fixed inset-y-0 left-0 z-50 bg-white border-r border-brand-gray-200 flex-col transition-all duration-300 ease-in-out',
          collapsed ? 'w-[4.5rem]' : 'w-64'
        )}
      >
        {sidebarContent}
      </aside>
    </>
  )
}
