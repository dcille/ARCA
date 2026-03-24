'use client'

import Link from 'next/link'

interface Props {
  id: string
  name: string
  score: number
  weight: number
  checks_passed: number
  checks_failed: number
  checks_warning?: number
  critical_fails: number
  nist_csf: string
}

function barColor(score: number): string {
  if (score >= 90) return 'bg-emerald-500'
  if (score >= 70) return 'bg-emerald-400'
  if (score >= 50) return 'bg-amber-400'
  if (score >= 30) return 'bg-orange-400'
  return 'bg-red-500'
}

export default function DomainCard({ id, name, score, weight, checks_passed, checks_failed, checks_warning = 0, critical_fails, nist_csf }: Props) {
  const total = checks_passed + checks_failed
  const pct = total > 0 ? Math.round((score / 100) * 100) : 0

  return (
    <Link
      href={`/darca/ransomware-readiness/domains/${id}`}
      className="block bg-white border border-brand-gray-200 rounded-xl p-4 hover:shadow-md hover:border-brand-blue/30 transition-all"
    >
      <div className="flex items-start justify-between mb-2">
        <div>
          <p className="text-xs text-brand-gray-400 font-medium">{id} &middot; {nist_csf}</p>
          <p className="text-sm font-semibold text-brand-navy mt-0.5">{name}</p>
        </div>
        <span className="text-2xl font-bold text-brand-navy tabular-nums">{Math.round(score)}</span>
      </div>
      <div className="w-full bg-gray-100 rounded-full h-2 mb-2">
        <div className={`h-2 rounded-full transition-all duration-700 ${barColor(score)}`} style={{ width: `${pct}%` }} />
      </div>
      <div className="flex items-center gap-3 text-xs text-brand-gray-400">
        <span className="text-emerald-600 font-medium">{checks_passed} passed</span>
        <span className="text-red-500 font-medium">{checks_failed} failed</span>
        {checks_warning > 0 && (
          <span className="text-amber-600 font-medium">{checks_warning} warning</span>
        )}
        {critical_fails > 0 && (
          <span className="text-red-600 font-bold">{critical_fails} critical</span>
        )}
        <span className="ml-auto">Weight: {Math.round(weight * 100)}%</span>
      </div>
    </Link>
  )
}
