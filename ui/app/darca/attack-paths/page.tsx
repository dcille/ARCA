'use client'

import { useEffect, useState, useCallback, useRef } from 'react'
import Header from '@/components/layout/Header'
import StatCard from '@/components/ui/StatCard'
import Badge from '@/components/ui/Badge'
import { api } from '@/lib/api'
import { cn } from '@/lib/utils'
import {
  ExclamationTriangleIcon,
  ArrowPathIcon,
  MapIcon,
  ShieldExclamationIcon,
  BoltIcon,
  ArrowsRightLeftIcon,
  EyeSlashIcon,
  ServerIcon,
  CircleStackIcon,
  GlobeAltIcon,
  UserIcon,
  CloudIcon,
  LockOpenIcon,
  ChevronRightIcon,
  XMarkIcon,
} from '@heroicons/react/24/outline'

// ── Graph visualization types ──────────────────────────────
interface GraphNode {
  id: string
  node_type: string
  label: string
  service: string
  severity: string
  metadata: Record<string, any>
  x?: number
  y?: number
}

interface GraphEdge {
  source_id: string
  target_id: string
  edge_type: string
  label: string
}

// ── Node styling by type ───────────────────────────────────
const nodeStyles: Record<string, { bg: string; border: string; icon: any }> = {
  internet:   { bg: 'bg-red-50',    border: 'border-red-300',    icon: GlobeAltIcon },
  identity:   { bg: 'bg-purple-50', border: 'border-purple-300', icon: UserIcon },
  resource:   { bg: 'bg-blue-50',   border: 'border-blue-300',   icon: ServerIcon },
  data_store: { bg: 'bg-amber-50',  border: 'border-amber-300',  icon: CircleStackIcon },
  network:    { bg: 'bg-teal-50',   border: 'border-teal-300',   icon: ArrowsRightLeftIcon },
  service:    { bg: 'bg-gray-50',   border: 'border-gray-300',   icon: CloudIcon },
  finding:    { bg: 'bg-orange-50', border: 'border-orange-300', icon: ExclamationTriangleIcon },
}

const categoryInfo: Record<string, { label: string; icon: any; color: string }> = {
  privilege_escalation: { label: 'Privilege Escalation', icon: BoltIcon, color: 'text-red-600' },
  data_exfiltration:    { label: 'Data Exfiltration',    icon: CircleStackIcon, color: 'text-amber-600' },
  lateral_movement:     { label: 'Lateral Movement',     icon: ArrowsRightLeftIcon, color: 'text-purple-600' },
  exposure:             { label: 'Exposure',             icon: GlobeAltIcon, color: 'text-blue-600' },
  detection_evasion:    { label: 'Detection Evasion',    icon: EyeSlashIcon, color: 'text-gray-600' },
  credential_access:    { label: 'Credential Access',    icon: LockOpenIcon, color: 'text-orange-600' },
  supply_chain:         { label: 'Supply Chain',         icon: ServerIcon, color: 'text-pink-600' },
  ransomware:           { label: 'Ransomware',           icon: ShieldExclamationIcon, color: 'text-red-700' },
}

// MITRE technique pattern: T followed by 4 digits, optionally .3 digits
const MITRE_TECH_REGEX = /^T\d{4}(\.\d{3})?$/

// ── Graph Canvas Component ─────────────────────────────────
function AttackPathGraph({ nodes, edges }: { nodes: GraphNode[]; edges: GraphEdge[] }) {
  const canvasRef = useRef<HTMLDivElement>(null)
  const [hoveredNode, setHoveredNode] = useState<string | null>(null)

  // Layout: left-to-right flow
  const layoutNodes = useCallback(() => {
    if (!nodes.length) return []

    const nodeWidth = 180
    const nodeHeight = 64
    const hGap = 80
    const vGap = 30

    // Build adjacency to determine layers
    const adj: Record<string, string[]> = {}
    const inDegree: Record<string, number> = {}
    for (const n of nodes) {
      adj[n.id] = []
      inDegree[n.id] = 0
    }
    for (const e of edges) {
      if (adj[e.source_id]) adj[e.source_id].push(e.target_id)
      inDegree[e.target_id] = (inDegree[e.target_id] || 0) + 1
    }

    // Topological layering
    const layers: string[][] = []
    const visited = new Set<string>()
    let current = nodes.filter(n => (inDegree[n.id] || 0) === 0).map(n => n.id)
    if (current.length === 0) current = [nodes[0].id]

    while (current.length > 0) {
      layers.push(current)
      current.forEach(id => visited.add(id))
      const next: string[] = []
      for (const id of current) {
        for (const neighbor of (adj[id] || [])) {
          if (!visited.has(neighbor) && !next.includes(neighbor)) {
            next.push(neighbor)
          }
        }
      }
      current = next
    }

    // Add any unvisited nodes to last layer
    const remaining = nodes.filter(n => !visited.has(n.id)).map(n => n.id)
    if (remaining.length) layers.push(remaining)

    const positioned: GraphNode[] = []
    for (let col = 0; col < layers.length; col++) {
      const layer = layers[col]
      const totalHeight = layer.length * nodeHeight + (layer.length - 1) * vGap
      const startY = Math.max(20, (400 - totalHeight) / 2)

      for (let row = 0; row < layer.length; row++) {
        const node = nodes.find(n => n.id === layer[row])
        if (node) {
          positioned.push({
            ...node,
            x: 40 + col * (nodeWidth + hGap),
            y: startY + row * (nodeHeight + vGap),
          })
        }
      }
    }

    return positioned
  }, [nodes, edges])

  const positionedNodes = layoutNodes()
  const nodeMap = Object.fromEntries(positionedNodes.map(n => [n.id, n]))

  const totalWidth = Math.max(
    600,
    ...positionedNodes.map(n => (n.x || 0) + 220)
  )
  const totalHeight = Math.max(
    300,
    ...positionedNodes.map(n => (n.y || 0) + 100)
  )

  return (
    <div ref={canvasRef} className="relative overflow-auto border border-brand-gray-200 rounded-xl bg-brand-gray-50" style={{ minHeight: '320px' }}>
      <svg width={totalWidth} height={totalHeight} className="absolute inset-0">
        <defs>
          <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="10" refY="3.5" orient="auto">
            <polygon points="0 0, 10 3.5, 0 7" fill="#94a3b8" />
          </marker>
        </defs>
        {edges.map((edge, i) => {
          const from = nodeMap[edge.source_id]
          const to = nodeMap[edge.target_id]
          if (!from || !to) return null
          const x1 = (from.x || 0) + 180
          const y1 = (from.y || 0) + 32
          const x2 = to.x || 0
          const y2 = (to.y || 0) + 32
          const midX = (x1 + x2) / 2

          const isHighlighted = hoveredNode === edge.source_id || hoveredNode === edge.target_id

          return (
            <g key={i}>
              <path
                d={`M ${x1} ${y1} C ${midX} ${y1}, ${midX} ${y2}, ${x2} ${y2}`}
                fill="none"
                stroke={isHighlighted ? '#3b82f6' : '#94a3b8'}
                strokeWidth={isHighlighted ? 2.5 : 1.5}
                markerEnd="url(#arrowhead)"
                className="transition-all duration-200"
              />
              {edge.label && (
                <text
                  x={midX}
                  y={((y1 + y2) / 2) - 6}
                  textAnchor="middle"
                  className="fill-brand-gray-400 text-[10px]"
                >
                  {edge.label}
                </text>
              )}
            </g>
          )
        })}
      </svg>

      {positionedNodes.map(node => {
        const style = nodeStyles[node.node_type] || nodeStyles.service
        const Icon = style.icon

        return (
          <div
            key={node.id}
            className={cn(
              'absolute rounded-lg border-2 px-3 py-2 cursor-pointer transition-all duration-200 shadow-sm',
              style.bg, style.border,
              hoveredNode === node.id && 'ring-2 ring-blue-400 shadow-md scale-105',
              node.node_type === 'finding' && 'opacity-80'
            )}
            style={{ left: node.x, top: node.y, width: 180, minHeight: 56 }}
            onMouseEnter={() => setHoveredNode(node.id)}
            onMouseLeave={() => setHoveredNode(null)}
          >
            <div className="flex items-center gap-2">
              <Icon className="w-4 h-4 flex-shrink-0 text-brand-gray-500" />
              <div className="min-w-0 flex-1">
                <p className="text-xs font-semibold text-brand-gray-700 truncate">{node.label}</p>
                <p className="text-[10px] text-brand-gray-400">{node.service}</p>
              </div>
            </div>
          </div>
        )
      })}
    </div>
  )
}

// ── Attack Path Card ──────────────────────────────────────
function AttackPathCard({
  path,
  isSelected,
  onSelect,
}: {
  path: any
  isSelected: boolean
  onSelect: () => void
}) {
  const cat = categoryInfo[path.category] || categoryInfo.exposure
  const CatIcon = cat.icon

  return (
    <div
      onClick={onSelect}
      className={cn(
        'card cursor-pointer transition-all duration-200 hover:shadow-md',
        isSelected && 'ring-2 ring-brand-green shadow-md'
      )}
    >
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-2">
          <CatIcon className={cn('w-5 h-5', cat.color)} />
          <span className={cn('text-xs font-medium', cat.color)}>{cat.label}</span>
        </div>
        <Badge type="severity" value={path.severity} />
      </div>

      <h3 className="text-sm font-bold text-brand-navy mb-1">{path.title}</h3>
      <p className="text-xs text-brand-gray-500 mb-3 line-clamp-2">{path.description}</p>

      <div className="flex items-center justify-between text-xs text-brand-gray-400">
        <div className="flex items-center gap-4">
          <span>{path.node_count} nodes</span>
          <span>{path.edge_count} edges</span>
        </div>
        <div className="flex items-center gap-1">
          <span className="font-semibold text-brand-navy">Risk: {path.risk_score}</span>
          <ChevronRightIcon className="w-4 h-4" />
        </div>
      </div>
    </div>
  )
}

// ── Detail Panel ──────────────────────────────────────────
function PathDetailPanel({
  path,
  graphData,
  onClose,
}: {
  path: any
  graphData: any
  onClose: () => void
}) {
  const cat = categoryInfo[path.category] || categoryInfo.exposure

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h2 className="text-xl font-bold text-brand-navy">{path.title}</h2>
          <p className="text-sm text-brand-gray-500 mt-1">{path.description}</p>
        </div>
        <button onClick={onClose} className="p-1 hover:bg-brand-gray-100 rounded-lg">
          <XMarkIcon className="w-5 h-5 text-brand-gray-400" />
        </button>
      </div>

      <div className="flex gap-4 flex-wrap">
        <Badge type="severity" value={path.severity} />
        <span className="severity-badge bg-brand-gray-100 text-brand-gray-600">
          Risk Score: {path.risk_score}
        </span>
        <span className="severity-badge bg-brand-gray-100 text-brand-gray-600">
          {cat.label}
        </span>
      </div>

      {/* Graph Visualization */}
      {graphData && graphData.nodes && (
        <div>
          <h3 className="text-sm font-semibold text-brand-navy mb-3">Attack Path Visualization</h3>
          <AttackPathGraph nodes={graphData.nodes} edges={graphData.edges} />
        </div>
      )}

      {/* Path Details */}
      <div className="grid grid-cols-2 gap-4">
        <div className="card">
          <p className="text-xs font-semibold text-brand-gray-400 uppercase mb-1">Entry Point</p>
          <p className="text-sm font-medium text-brand-navy">{path.entry_point}</p>
        </div>
        <div className="card">
          <p className="text-xs font-semibold text-brand-gray-400 uppercase mb-1">Target</p>
          <p className="text-sm font-medium text-brand-navy">{path.target}</p>
        </div>
      </div>

      {/* Techniques (MITRE ATT&CK linked) */}
      {path.techniques?.length > 0 && (
        <div>
          <h3 className="text-sm font-semibold text-brand-navy mb-2">Attack Techniques (MITRE ATT&CK)</h3>
          <div className="flex flex-wrap gap-2">
            {path.techniques.map((t: string, i: number) => {
              const isMitre = MITRE_TECH_REGEX.test(t)
              return isMitre ? (
                <a
                  key={i}
                  href={`https://attack.mitre.org/techniques/${t.replace('.', '/')}/`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1.5 px-2.5 py-1 bg-amber-50 border border-amber-200 rounded-md text-xs font-mono text-amber-800 hover:bg-amber-100 transition-colors"
                >
                  <BoltIcon className="w-3.5 h-3.5 text-amber-500" />
                  {t}
                </a>
              ) : (
                <span key={i} className="inline-flex items-center gap-1.5 px-2.5 py-1 bg-brand-gray-100 rounded-md text-xs text-brand-gray-600">
                  <BoltIcon className="w-3.5 h-3.5 text-amber-500" />
                  {t}
                </span>
              )
            })}
          </div>
        </div>
      )}

      {/* Affected Resources */}
      {path.affected_resources?.length > 0 && (
        <div>
          <h3 className="text-sm font-semibold text-brand-navy mb-2">Affected Resources</h3>
          <div className="flex flex-wrap gap-2">
            {path.affected_resources.map((r: string, i: number) => (
              <span key={i} className="px-2 py-1 bg-brand-gray-100 text-brand-gray-600 text-xs rounded-md">
                {r}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Remediation */}
      {path.remediation?.length > 0 && (
        <div>
          <h3 className="text-sm font-semibold text-brand-navy mb-2">Remediation Steps</h3>
          <div className="space-y-2">
            {path.remediation.map((r: string, i: number) => (
              <div key={i} className="flex items-start gap-2 text-sm text-brand-gray-600">
                <span className="w-5 h-5 rounded-full bg-brand-green/20 text-brand-green text-xs flex items-center justify-center flex-shrink-0 mt-0.5">
                  {i + 1}
                </span>
                {r}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────
export default function AttackPathsPage() {
  const [paths, setPaths] = useState<any[]>([])
  const [summary, setSummary] = useState<any>(null)
  const [selectedPath, setSelectedPath] = useState<any>(null)
  const [graphData, setGraphData] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [analyzing, setAnalyzing] = useState(false)
  const [analyzeResult, setAnalyzeResult] = useState<{ message: string; paths_discovered: number } | null>(null)
  const [filters, setFilters] = useState({ severity: '', category: '' })
  const [chokePoints, setChokePoints] = useState<any>(null)
  const [showChoke, setShowChoke] = useState(false)

  const loadData = async () => {
    setLoading(true)
    try {
      const params: Record<string, string> = {}
      if (filters.severity) params.severity = filters.severity
      if (filters.category) params.category = filters.category
      const [pathsData, summaryData] = await Promise.all([
        api.getAttackPaths(params),
        api.getAttackPathsSummary(),
      ])
      setPaths(pathsData)
      setSummary(summaryData)
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { loadData() }, [filters])

  const handleAnalyze = async () => {
    setAnalyzing(true)
    setAnalyzeResult(null)
    try {
      const result = await api.analyzeAttackPaths()
      setAnalyzeResult(result)
      await loadData()
      // Auto-dismiss after 8 seconds
      setTimeout(() => setAnalyzeResult(null), 8000)
    } catch (err: any) {
      setAnalyzeResult({ message: err.message || 'Analysis failed', paths_discovered: 0 })
      console.error(err)
    } finally {
      setAnalyzing(false)
    }
  }

  const handleShowChoke = async () => {
    if (showChoke) { setShowChoke(false); return }
    try {
      const data = await api.getAttackPathChokePoints()
      setChokePoints(data)
      setShowChoke(true)
    } catch (err) { console.error(err) }
  }

  const handleSelectPath = async (path: any) => {
    setSelectedPath(path)
    try {
      const detail = await api.getAttackPath(path.id)
      setGraphData(detail.graph_data)
    } catch (err) {
      console.error(err)
      setGraphData(null)
    }
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <Header title="Attack Paths" subtitle="Graph-based analysis of exploitable attack chains across your cloud environment" breadcrumbs={[{ label: 'Posture', href: '/darca/overview' }, { label: 'Attack Paths' }]} />
        <div className="flex items-center gap-2">
          {paths.length > 0 && (
            <button
              onClick={handleShowChoke}
              className={cn(
                'flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors border',
                showChoke
                  ? 'bg-amber-50 border-amber-300 text-amber-700'
                  : 'border-brand-gray-200 text-brand-gray-600 hover:bg-brand-gray-50'
              )}
            >
              <ExclamationTriangleIcon className="w-4 h-4" />
              Choke Points
            </button>
          )}
          <button
            onClick={handleAnalyze}
            disabled={analyzing}
            className={cn(
              'flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors',
              analyzing
                ? 'bg-brand-gray-200 text-brand-gray-400 cursor-not-allowed'
                : 'bg-brand-green text-white hover:bg-brand-green/90'
            )}
          >
            <ArrowPathIcon className={cn('w-4 h-4', analyzing && 'animate-spin')} />
            {analyzing ? 'Analyzing...' : 'Run Analysis'}
          </button>
        </div>
      </div>

      {/* Analysis Result Toast */}
      {analyzeResult && (
        <div className={cn(
          'mb-4 px-4 py-3 rounded-lg flex items-center justify-between text-sm',
          analyzeResult.paths_discovered > 0
            ? 'bg-brand-green/10 text-brand-green border border-brand-green/20'
            : 'bg-amber-50 text-amber-700 border border-amber-200'
        )}>
          <div className="flex items-center gap-2">
            {analyzeResult.paths_discovered > 0 ? (
              <MapIcon className="w-5 h-5" />
            ) : (
              <ExclamationTriangleIcon className="w-5 h-5" />
            )}
            <span>{analyzeResult.message}</span>
          </div>
          <button onClick={() => setAnalyzeResult(null)} className="p-1 hover:opacity-70">
            <XMarkIcon className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Summary Stats */}
      {summary && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4 mb-6">
          <StatCard
            title="Total Paths"
            value={summary.total_paths}
            icon={<MapIcon className="w-5 h-5" />}
          />
          <StatCard
            title="Critical"
            value={summary.critical_paths}
            icon={<ShieldExclamationIcon className="w-5 h-5" />}
            valueColor="text-severity-critical"
          />
          <StatCard
            title="High"
            value={summary.high_paths}
            icon={<ExclamationTriangleIcon className="w-5 h-5" />}
            valueColor="text-severity-high"
          />
          <StatCard
            title="Medium / Low"
            value={`${summary.medium_paths} / ${summary.low_paths}`}
            icon={<LockOpenIcon className="w-5 h-5" />}
          />
          <StatCard
            title="Avg Risk Score"
            value={summary.avg_risk_score}
            icon={<BoltIcon className="w-5 h-5" />}
            valueColor={
              summary.avg_risk_score >= 70
                ? 'text-severity-critical'
                : summary.avg_risk_score >= 40
                ? 'text-severity-high'
                : 'text-brand-navy'
            }
          />
        </div>
      )}

      {/* Filters */}
      <div className="flex gap-4 mb-6">
        <select
          value={filters.severity}
          onChange={(e) => setFilters({ ...filters, severity: e.target.value })}
          className="select-field"
        >
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>

        <select
          value={filters.category}
          onChange={(e) => setFilters({ ...filters, category: e.target.value })}
          className="select-field"
        >
          <option value="">All Categories</option>
          <option value="privilege_escalation">Privilege Escalation</option>
          <option value="data_exfiltration">Data Exfiltration</option>
          <option value="lateral_movement">Lateral Movement</option>
          <option value="exposure">Exposure</option>
          <option value="detection_evasion">Detection Evasion</option>
          <option value="credential_access">Credential Access</option>
          <option value="supply_chain">Supply Chain</option>
          <option value="ransomware">Ransomware</option>
        </select>
      </div>

      {/* Choke Points Panel */}
      {showChoke && chokePoints?.choke_points?.length > 0 && (
        <div className="card mb-6">
          <div className="flex items-start justify-between mb-3">
            <div>
              <h3 className="text-sm font-bold text-brand-navy">Choke Points — High-Value Remediation Targets</h3>
              <p className="text-xs text-brand-gray-400 mt-0.5">
                Nodes appearing most frequently across attack paths. Fixing these reduces the most risk.
              </p>
            </div>
            <button onClick={() => setShowChoke(false)} className="p-1 hover:bg-brand-gray-100 rounded">
              <XMarkIcon className="w-4 h-4 text-brand-gray-400" />
            </button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
            {chokePoints.choke_points.map((cp: any, i: number) => (
              <div key={i} className="flex items-center gap-3 px-3 py-2 bg-amber-50 border border-amber-200 rounded-lg">
                <span className="w-6 h-6 rounded-full bg-amber-500 text-white text-xs font-bold flex items-center justify-center flex-shrink-0">
                  {i + 1}
                </span>
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-semibold text-amber-900 truncate">{cp.label}</p>
                  <p className="text-[10px] text-amber-700">
                    {cp.service} &middot; {cp.node_type} &middot; {cp.path_appearances} paths &middot; {cp.connection_count} connections
                  </p>
                </div>
                <span className="text-xs font-mono font-bold text-amber-700">{cp.choke_score}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {loading ? (
        <div className="space-y-4">
          {[...Array(3)].map((_, i) => (
            <div key={i} className="card animate-pulse">
              <div className="h-24 bg-brand-gray-100 rounded" />
            </div>
          ))}
        </div>
      ) : selectedPath ? (
        <div className="card">
          <PathDetailPanel
            path={selectedPath}
            graphData={graphData}
            onClose={() => { setSelectedPath(null); setGraphData(null) }}
          />
        </div>
      ) : paths.length === 0 ? (
        <div className="card text-center py-16">
          <MapIcon className="w-16 h-16 mx-auto text-brand-gray-300 mb-4" />
          <h3 className="text-lg font-semibold text-brand-navy mb-2">No Attack Paths Discovered</h3>
          <p className="text-sm text-brand-gray-400 mb-6 max-w-md mx-auto">
            Run a cloud scan first to generate findings, then click &quot;Run Analysis&quot; to discover
            attack paths across your environment.
          </p>
          <button
            onClick={handleAnalyze}
            disabled={analyzing}
            className="inline-flex items-center gap-2 px-4 py-2 bg-brand-green text-white rounded-lg text-sm font-medium hover:bg-brand-green/90"
          >
            <ArrowPathIcon className={cn('w-4 h-4', analyzing && 'animate-spin')} />
            {analyzing ? 'Analyzing...' : 'Run Analysis'}
          </button>
        </div>
      ) : (
        <div className="space-y-4">
          {paths.map((path) => (
            <AttackPathCard
              key={path.id}
              path={path}
              isSelected={selectedPath?.id === path.id}
              onSelect={() => handleSelectPath(path)}
            />
          ))}
        </div>
      )}
    </div>
  )
}
