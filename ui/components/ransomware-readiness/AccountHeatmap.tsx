'use client'

import Link from 'next/link'

interface Account {
  id: string
  provider: string
  alias: string
  score: number
  domain_scores: Record<string, { final_score?: number }>
}

const DOMAINS = ['D1', 'D2', 'D3', 'D4', 'D5', 'D6', 'D7']
const DOMAIN_SHORT = { D1: 'IAM', D2: 'Encrypt', D3: 'Backup', D4: 'Network', D5: 'Harden', D6: 'Logging', D7: 'Gov' }

function scoreColor(score: number): string {
  if (score >= 90) return 'bg-emerald-500 text-white'
  if (score >= 70) return 'bg-emerald-400 text-white'
  if (score >= 50) return 'bg-amber-400 text-white'
  if (score >= 30) return 'bg-orange-400 text-white'
  return 'bg-red-500 text-white'
}

export default function AccountHeatmap({ accounts }: { accounts: Account[] }) {
  if (!accounts.length) {
    return <p className="text-sm text-brand-gray-400 py-4">No accounts evaluated yet.</p>
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-xs text-brand-gray-400 uppercase">
            <th className="text-left py-2 px-2 font-semibold">Account</th>
            <th className="text-center py-2 px-1 font-semibold">Score</th>
            {DOMAINS.map(d => (
              <th key={d} className="text-center py-2 px-1 font-semibold">
                {DOMAIN_SHORT[d as keyof typeof DOMAIN_SHORT]}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {accounts.map(a => (
            <tr key={a.id} className="border-t border-brand-gray-100 hover:bg-brand-gray-50">
              <td className="py-2 px-2">
                <Link
                  href={`/darca/ransomware-readiness/accounts/${a.id}`}
                  className="text-brand-blue hover:underline font-medium"
                >
                  {a.alias || a.id}
                </Link>
                <span className="ml-2 text-xs text-brand-gray-400 uppercase">{a.provider}</span>
              </td>
              <td className="text-center py-2 px-1">
                <span className={`inline-block w-10 py-0.5 rounded text-xs font-bold ${scoreColor(a.score)}`}>
                  {a.score}
                </span>
              </td>
              {DOMAINS.map(d => {
                const ds = a.domain_scores?.[d]
                const s = ds?.final_score ?? 0
                return (
                  <td key={d} className="text-center py-2 px-1">
                    <span className={`inline-block w-10 py-0.5 rounded text-xs font-bold ${scoreColor(s)}`}>
                      {Math.round(s)}
                    </span>
                  </td>
                )
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
