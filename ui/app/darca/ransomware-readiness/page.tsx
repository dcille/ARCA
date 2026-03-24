'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import Header from '@/components/layout/Header'
import ScoreGauge from '@/components/ransomware-readiness/ScoreGauge'
import DomainRadarChart from '@/components/ransomware-readiness/DomainRadarChart'
import AccountHeatmap from '@/components/ransomware-readiness/AccountHeatmap'
import DomainCard from '@/components/ransomware-readiness/DomainCard'
import Badge from '@/components/ui/Badge'
import { api } from '@/lib/api'
import KnowledgeBasePanel from '@/components/ransomware-readiness/KnowledgeBasePanel'
import {
  ShieldExclamationIcon,
  ArrowPathIcon,
  ChartBarIcon,
  DocumentArrowDownIcon,
  ClipboardDocumentListIcon,
  BookOpenIcon,
} from '@heroicons/react/24/outline'
import {
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip,
  LineChart, Line, XAxis, YAxis, CartesianGrid,
} from 'recharts'

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#DC2626',
  high: '#EA580C',
  medium: '#D97706',
  low: '#6B7280',
}

export default function RansomwareReadinessPage() {
  const [score, setScore] = useState<any>(null)
  const [domains, setDomains] = useState<any[]>([])
  const [accounts, setAccounts] = useState<any[]>([])
  const [findings, setFindings] = useState<any>(null)
  const [history, setHistory] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [evaluating, setEvaluating] = useState(false)
  const [kbOpen, setKbOpen] = useState(false)

  useEffect(() => {
    loadData()
  }, [])

  async function loadData() {
    setLoading(true)
    try {
      const [scoreData, domainsData, accountsData, findingsData, historyData] = await Promise.all([
        api.getRRScore().catch(() => null),
        api.getRRDomains().catch(() => []),
        api.getRRAccounts().catch(() => []),
        api.getRRFindings({ status: 'fail', page_size: '10' }).catch(() => ({ items: [], total: 0 })),
        api.getRRScoreHistory(90).catch(() => []),
      ])
      setScore(scoreData)
      setDomains(domainsData)
      setAccounts(accountsData)
      setFindings(findingsData)
      setHistory(historyData)
    } catch (e) {
      console.error('Failed to load RR data:', e)
    }
    setLoading(false)
  }

  async function handleEvaluate() {
    setEvaluating(true)
    try {
      await api.triggerRREvaluation()
      setTimeout(loadData, 5000)
    } catch (e) {
      console.error('Evaluation failed:', e)
    }
    setEvaluating(false)
  }

  if (loading) {
    return (
      <div className="space-y-6">
        <Header title="Ransomware Readiness" subtitle="Loading assessment data..." />
        <div className="flex items-center justify-center py-20">
          <ArrowPathIcon className="w-8 h-8 animate-spin text-brand-gray-300" />
        </div>
      </div>
    )
  }

  const globalScore = score?.global_score ?? 0
  const level = score?.level ?? 'Critico'
  const trend = score?.trend_30d ?? null
  const summary = score?.summary ?? { total_checks: 0, passed: 0, failed: 0, warning: 0, critical_findings: 0 }

  // Donut chart data
  const donutData = [
    { name: 'Passed', value: summary.passed, color: '#2D8B4E' },
    { name: 'Failed', value: summary.failed, color: '#DC2626' },
    { name: 'Warning', value: summary.warning, color: '#F39C12' },
  ].filter(d => d.value > 0)

  return (
    <div className="space-y-6">
      <Header
        title="Ransomware Readiness"
        subtitle="NIST CSF 2.0 | NISTIR 8374 — Cloud ransomware preparedness assessment"
      />

      {/* Action bar */}
      <div className="flex items-center gap-3 flex-wrap">
        <button
          onClick={handleEvaluate}
          disabled={evaluating}
          className="inline-flex items-center gap-2 px-4 py-2 bg-brand-navy text-white rounded-lg hover:bg-brand-navy/90 disabled:opacity-50 text-sm font-medium transition-colors"
        >
          <ArrowPathIcon className={`w-4 h-4 ${evaluating ? 'animate-spin' : ''}`} />
          {evaluating ? 'Evaluating...' : 'Run Assessment'}
        </button>
        <Link
          href="/darca/ransomware-readiness/governance"
          className="inline-flex items-center gap-2 px-4 py-2 border border-brand-gray-200 rounded-lg hover:bg-brand-gray-50 text-sm font-medium text-brand-gray-600 transition-colors"
        >
          <ClipboardDocumentListIcon className="w-4 h-4" />
          Governance Inputs
        </Link>
        <button
          onClick={() => setKbOpen(true)}
          className="inline-flex items-center gap-2 px-4 py-2 border border-brand-blue/30 bg-brand-blue/5 rounded-lg hover:bg-brand-blue/10 text-sm font-medium text-brand-blue transition-colors"
        >
          <BookOpenIcon className="w-4 h-4" />
          Knowledge Base
        </button>
      </div>

      {/* Main score + radar */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Score gauge */}
        <div className="bg-white border border-brand-gray-200 rounded-xl p-6">
          <h2 className="text-sm font-semibold text-brand-gray-400 uppercase tracking-wide mb-4">
            Global Ransomware Readiness Score
          </h2>
          <div className="flex items-center gap-8">
            <ScoreGauge score={globalScore} level={level} trend={trend} size="lg" />
            <div className="space-y-3 flex-1">
              <div className="grid grid-cols-2 gap-3">
                <div className="bg-emerald-50 rounded-lg p-3 text-center">
                  <p className="text-2xl font-bold text-emerald-700">{summary.passed}</p>
                  <p className="text-xs text-emerald-600 font-medium">Passed</p>
                </div>
                <div className="bg-red-50 rounded-lg p-3 text-center">
                  <p className="text-2xl font-bold text-red-700">{summary.failed}</p>
                  <p className="text-xs text-red-600 font-medium">Failed</p>
                </div>
                <div className="bg-amber-50 rounded-lg p-3 text-center">
                  <p className="text-2xl font-bold text-amber-700">{summary.warning}</p>
                  <p className="text-xs text-amber-600 font-medium">Warning</p>
                </div>
                <div className="bg-red-50 rounded-lg p-3 text-center">
                  <p className="text-2xl font-bold text-red-700">{summary.critical_findings}</p>
                  <p className="text-xs text-red-600 font-medium">Critical</p>
                </div>
              </div>
              {score?.calculated_at && (
                <p className="text-xs text-brand-gray-400">
                  Last assessed: {new Date(score.calculated_at).toLocaleString()}
                </p>
              )}
            </div>
          </div>
        </div>

        {/* Radar chart */}
        <div className="bg-white border border-brand-gray-200 rounded-xl p-6">
          <h2 className="text-sm font-semibold text-brand-gray-400 uppercase tracking-wide mb-2">
            Domain Profile
          </h2>
          {domains.length > 0 ? (
            <DomainRadarChart domains={domains} />
          ) : (
            <div className="flex items-center justify-center h-64 text-brand-gray-400 text-sm">
              Run an assessment to see the domain profile
            </div>
          )}
        </div>
      </div>

      {/* Domain cards */}
      <div>
        <h2 className="text-sm font-semibold text-brand-gray-400 uppercase tracking-wide mb-3">
          Domains ({domains.length})
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
          {domains.map(d => (
            <DomainCard
              key={d.id}
              id={d.id}
              name={d.name}
              score={d.score}
              weight={d.weight}
              checks_passed={d.checks_passed}
              checks_failed={d.checks_failed}
              checks_warning={d.checks_warning}
              critical_fails={d.critical_fails}
              nist_csf={d.nist_csf}
            />
          ))}
        </div>
      </div>

      {/* Bottom row: heatmap + donut + trend + findings */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Heatmap */}
        <div className="lg:col-span-2 bg-white border border-brand-gray-200 rounded-xl p-6">
          <h2 className="text-sm font-semibold text-brand-gray-400 uppercase tracking-wide mb-3">
            Account Heatmap
          </h2>
          <AccountHeatmap accounts={accounts} />
        </div>

        {/* Checks donut */}
        <div className="bg-white border border-brand-gray-200 rounded-xl p-6">
          <h2 className="text-sm font-semibold text-brand-gray-400 uppercase tracking-wide mb-3">
            Checks Summary
          </h2>
          {donutData.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie
                  data={donutData}
                  cx="50%" cy="50%"
                  innerRadius={55} outerRadius={80}
                  paddingAngle={3} dataKey="value"
                >
                  {donutData.map((entry, i) => (
                    <Cell key={i} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-48 text-brand-gray-400 text-sm">No data</div>
          )}
          <div className="flex justify-center gap-4 mt-2">
            {donutData.map(d => (
              <span key={d.name} className="flex items-center gap-1.5 text-xs text-brand-gray-500">
                <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: d.color }} />
                {d.name}: {d.value}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Score trend */}
      {history.length > 1 && (
        <div className="bg-white border border-brand-gray-200 rounded-xl p-6">
          <h2 className="text-sm font-semibold text-brand-gray-400 uppercase tracking-wide mb-3">
            Score Trend (90 days)
          </h2>
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={history}>
              <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
              <XAxis dataKey="date" tick={{ fontSize: 11, fill: '#9ca3af' }} />
              <YAxis domain={[0, 100]} tick={{ fontSize: 11, fill: '#9ca3af' }} />
              <Tooltip />
              <Line type="monotone" dataKey="score" stroke="#012169" strokeWidth={2} dot={{ r: 3 }} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Top critical findings */}
      <div className="bg-white border border-brand-gray-200 rounded-xl p-6">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-brand-gray-400 uppercase tracking-wide">
            Top Critical & High Findings
          </h2>
          <Link
            href="/darca/ransomware-readiness/findings/all"
            className="text-sm text-brand-blue hover:underline"
          >
            View all findings
          </Link>
        </div>
        {findings?.items?.length > 0 ? (
          <div className="space-y-2">
            {findings.items.slice(0, 10).map((f: any) => (
              <Link
                key={f.id}
                href={`/darca/ransomware-readiness/findings/${f.id}`}
                className="flex items-center gap-3 p-3 rounded-lg border border-brand-gray-100 hover:bg-brand-gray-50 transition-colors"
              >
                <Badge type="severity" value={f.severity} />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-brand-navy truncate">{f.rule_name}</p>
                  <p className="text-xs text-brand-gray-400">
                    {f.rule_id} &middot; {f.domain} &middot; {f.provider?.toUpperCase()} &middot; {f.failed_resources} resources affected
                  </p>
                </div>
                <span className="text-xs text-brand-gray-400 whitespace-nowrap">{f.account_id?.slice(0, 12)}</span>
              </Link>
            ))}
          </div>
        ) : (
          <p className="text-sm text-brand-gray-400 py-4">
            {summary.total_checks > 0 ? 'No failed findings — excellent posture!' : 'Run an assessment to see findings.'}
          </p>
        )}
      </div>

      {/* Knowledge Base side panel */}
      <KnowledgeBasePanel open={kbOpen} onClose={() => setKbOpen(false)} />
    </div>
  )
}
