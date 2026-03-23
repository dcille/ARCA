'use client'

import Link from 'next/link'
import { ChevronRightIcon } from '@heroicons/react/24/outline'

interface Breadcrumb {
  label: string
  href?: string
}

interface HeaderProps {
  title: string
  subtitle?: string
  actions?: React.ReactNode
  breadcrumbs?: Breadcrumb[]
}

export default function Header({ title, subtitle, actions, breadcrumbs }: HeaderProps) {
  return (
    <header className="mb-8 animate-fade-in">
      {breadcrumbs && breadcrumbs.length > 0 && (
        <nav className="flex items-center gap-1.5 text-sm mb-3">
          <Link href="/darca/overview" className="text-brand-gray-400 hover:text-brand-green transition-colors">
            Home
          </Link>
          {breadcrumbs.map((crumb, i) => (
            <span key={i} className="flex items-center gap-1.5">
              <ChevronRightIcon className="w-3.5 h-3.5 text-brand-gray-300" />
              {crumb.href ? (
                <Link href={crumb.href} className="text-brand-gray-400 hover:text-brand-green transition-colors">
                  {crumb.label}
                </Link>
              ) : (
                <span className="text-brand-gray-600 font-medium">{crumb.label}</span>
              )}
            </span>
          ))}
        </nav>
      )}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-brand-navy">{title}</h1>
          {subtitle && (
            <p className="text-sm text-brand-gray-500 mt-1">{subtitle}</p>
          )}
        </div>
        {actions && <div className="flex items-center gap-3">{actions}</div>}
      </div>
    </header>
  )
}
