'use client'

import { useEffect, useState, useRef, useCallback, useMemo } from 'react'
import Header from '@/components/layout/Header'
import StatCard from '@/components/ui/StatCard'
import Badge from '@/components/ui/Badge'
import { api } from '@/lib/api'
import {
  GlobeAltIcon,
  ShieldExclamationIcon,
  ShieldCheckIcon,
  ServerStackIcon,
  CloudIcon,
  MapPinIcon,
  CubeIcon,
  FunnelIcon,
  ArrowPathIcon,
  MagnifyingGlassIcon,
  XMarkIcon,
  ChevronRightIcon,
  ArrowsPointingOutIcon,
  ArrowsPointingInIcon,
  ViewfinderCircleIcon,
} from '@heroicons/react/24/outline'

/* ─── types ─── */
interface GraphNode {
  id: string
  label: string
  type: 'root' | 'provider' | 'region' | 'service' | 'resource'
  category: string
  severity: string | null
  meta: Record<string, any>
  // layout
  x?: number
  y?: number
}

interface GraphEdge {
  source: string
  target: string
  label: string
}

interface GraphData {
  nodes: GraphNode[]
  edges: GraphEdge[]
  summary: Record<string, number>
}

interface GraphStats {
  total_resources: number
  at_risk: number
  compliant: number
  services: number
  providers: number
  by_severity: Record<string, number>
}

/* ─── colour palette ─── */
const NODE_COLORS: Record<string, string> = {
  root: '#1a2b4a',
  provider: '#3b82f6',
  region: '#8b5cf6',
  service: '#06b6d4',
  resource: '#10b981',
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#dc2626',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
  informational: '#6b7280',
}

const CATEGORY_ICONS: Record<string, string> = {
  root: '\u{1F30D}',
  identity: '\u{1F511}',
  storage: '\u{1F4E6}',
  compute: '\u{1F5A5}',
  database: '\u{1F4BE}',
  network: '\u{1F310}',
  logging: '\u{1F4D3}',
  encryption: '\u{1F512}',
  messaging: '\u{1F4E8}',
  security: '\u{1F6E1}',
  management: '\u{2699}',
  other: '\u{2B24}',
  aws: '\u{2601}',
  azure: '\u{2601}',
  gcp: '\u{2601}',
  region: '\u{1F4CD}',
}

/* ─── layout helpers ─── */
function buildRadialLayout(nodes: GraphNode[], edges: GraphEdge[]): GraphNode[] {
  if (nodes.length === 0) return []

  const childrenMap: Record<string, string[]> = {}
  const parentMap: Record<string, string> = {}
  for (const e of edges) {
    if (!childrenMap[e.source]) childrenMap[e.source] = []
    childrenMap[e.source].push(e.target)
    parentMap[e.target] = e.source
  }

  // BFS from root to assign levels
  const levels: Record<string, number> = {}
  const root = nodes.find((n) => n.type === 'root')
  if (!root) return nodes

  const queue: string[] = [root.id]
  levels[root.id] = 0
  while (queue.length > 0) {
    const current = queue.shift()!
    for (const child of childrenMap[current] || []) {
      if (levels[child] === undefined) {
        levels[child] = levels[current] + 1
        queue.push(child)
      }
    }
  }

  // Group by level
  const byLevel: Record<number, string[]> = {}
  let maxLevel = 0
  for (const [id, lvl] of Object.entries(levels)) {
    if (!byLevel[lvl]) byLevel[lvl] = []
    byLevel[lvl].push(id)
    if (lvl > maxLevel) maxLevel = lvl
  }

  const LEVEL_SPACING = 180
  const nodeMap: Record<string, GraphNode> = {}
  for (const n of nodes) nodeMap[n.id] = { ...n }

  // Root
  if (nodeMap[root.id]) {
    nodeMap[root.id].x = 0
    nodeMap[root.id].y = 0
  }

  // For each level, distribute children around their parent
  for (let lvl = 1; lvl <= maxLevel; lvl++) {
    const ids = byLevel[lvl] || []
    // Group by parent
    const parentGroups: Record<string, string[]> = {}
    for (const id of ids) {
      const p = parentMap[id] || root.id
      if (!parentGroups[p]) parentGroups[p] = []
      parentGroups[p].push(id)
    }

    // Get all parents at this level sorted by their x position
    const parentIds = Object.keys(parentGroups)
    parentIds.sort((a, b) => (nodeMap[a]?.x || 0) - (nodeMap[b]?.x || 0))

    let globalIdx = 0
    const totalAtLevel = ids.length
    const spacing = Math.max(60, 800 / Math.max(totalAtLevel, 1))

    for (const pid of parentIds) {
      const children = parentGroups[pid]
      for (const cid of children) {
        if (nodeMap[cid]) {
          const offsetX = (globalIdx - totalAtLevel / 2) * spacing
          nodeMap[cid].x = offsetX
          nodeMap[cid].y = lvl * LEVEL_SPACING
        }
        globalIdx++
      }
    }
  }

  return Object.values(nodeMap)
}

/* ─── component ─── */
export default function SecurityGraphPage() {
  const [graphData, setGraphData] = useState<GraphData | null>(null)
  const [stats, setStats] = useState<GraphStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null)
  const [hoveredNode, setHoveredNode] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [filterProvider, setFilterProvider] = useState('')
  const [filterSeverity, setFilterSeverity] = useState('')
  const [filterStatus, setFilterStatus] = useState('')
  const [depth, setDepth] = useState<'service' | 'resource'>('service')
  const [showFilters, setShowFilters] = useState(false)

  // Pan & zoom state
  const svgRef = useRef<SVGSVGElement>(null)
  const [viewBox, setViewBox] = useState({ x: -600, y: -80, w: 1200, h: 800 })
  const [isPanning, setIsPanning] = useState(false)
  const [panStart, setPanStart] = useState({ x: 0, y: 0 })
  const [zoomLevel, setZoomLevel] = useState(1)

  const loadData = useCallback(async () => {
    setLoading(true)
    try {
      const params: Record<string, string> = { depth }
      if (filterProvider) params.provider_type = filterProvider
      if (filterSeverity) params.severity = filterSeverity
      if (filterStatus) params.status = filterStatus

      const [graph, graphStats] = await Promise.all([
        api.getSecurityGraph(params),
        api.getSecurityGraphStats(),
      ])
      setGraphData(graph)
      setStats(graphStats)
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }, [depth, filterProvider, filterSeverity, filterStatus])

  useEffect(() => {
    loadData()
  }, [loadData])

  // Lay out the graph
  const layoutNodes = useMemo(() => {
    if (!graphData) return []
    return buildRadialLayout(graphData.nodes, graphData.edges)
  }, [graphData])

  const nodeById = useMemo(() => {
    const m: Record<string, GraphNode> = {}
    for (const n of layoutNodes) m[n.id] = n
    return m
  }, [layoutNodes])

  // Filter by search
  const highlightedIds = useMemo(() => {
    if (!search.trim()) return new Set<string>()
    const lower = search.toLowerCase()
    return new Set(
      layoutNodes.filter((n) => n.label.toLowerCase().includes(lower)).map((n) => n.id)
    )
  }, [layoutNodes, search])

  // Connected edges of hovered / selected node
  const connectedEdges = useMemo(() => {
    const target = hoveredNode || selectedNode?.id
    if (!target || !graphData) return new Set<string>()
    const set = new Set<string>()
    for (const e of graphData.edges) {
      if (e.source === target || e.target === target) {
        set.add(`${e.source}>${e.target}`)
      }
    }
    return set
  }, [hoveredNode, selectedNode, graphData])

  /* ── pan & zoom handlers ── */
  const handleMouseDown = (e: React.MouseEvent) => {
    if (e.button !== 0) return
    setIsPanning(true)
    setPanStart({ x: e.clientX, y: e.clientY })
  }

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!isPanning) return
    const dx = (e.clientX - panStart.x) * (viewBox.w / (svgRef.current?.clientWidth || 1))
    const dy = (e.clientY - panStart.y) * (viewBox.h / (svgRef.current?.clientHeight || 1))
    setViewBox((v) => ({ ...v, x: v.x - dx, y: v.y - dy }))
    setPanStart({ x: e.clientX, y: e.clientY })
  }

  const handleMouseUp = () => setIsPanning(false)

  const handleWheel = (e: React.WheelEvent) => {
    e.preventDefault()
    const factor = e.deltaY > 0 ? 1.12 : 0.89
    setViewBox((v) => {
      const cx = v.x + v.w / 2
      const cy = v.y + v.h / 2
      const nw = v.w * factor
      const nh = v.h * factor
      return { x: cx - nw / 2, y: cy - nh / 2, w: nw, h: nh }
    })
    setZoomLevel((z) => z * (e.deltaY > 0 ? 0.89 : 1.12))
  }

  const zoomIn = () => {
    setViewBox((v) => {
      const cx = v.x + v.w / 2
      const cy = v.y + v.h / 2
      const nw = v.w * 0.75
      const nh = v.h * 0.75
      return { x: cx - nw / 2, y: cy - nh / 2, w: nw, h: nh }
    })
    setZoomLevel((z) => z * 1.33)
  }

  const zoomOut = () => {
    setViewBox((v) => {
      const cx = v.x + v.w / 2
      const cy = v.y + v.h / 2
      const nw = v.w * 1.33
      const nh = v.h * 1.33
      return { x: cx - nw / 2, y: cy - nh / 2, w: nw, h: nh }
    })
    setZoomLevel((z) => z * 0.75)
  }

  const fitToView = () => {
    if (layoutNodes.length === 0) return
    const xs = layoutNodes.map((n) => n.x || 0)
    const ys = layoutNodes.map((n) => n.y || 0)
    const minX = Math.min(...xs) - 100
    const maxX = Math.max(...xs) + 100
    const minY = Math.min(...ys) - 100
    const maxY = Math.max(...ys) + 100
    setViewBox({ x: minX, y: minY, w: maxX - minX, h: maxY - minY })
    setZoomLevel(1)
  }

  const getNodeRadius = (type: string) => {
    switch (type) {
      case 'root': return 28
      case 'provider': return 22
      case 'region': return 18
      case 'service': return 16
      case 'resource': return 12
      default: return 12
    }
  }

  const getNodeFill = (node: GraphNode) => {
    if (node.severity) return SEVERITY_COLORS[node.severity] || NODE_COLORS[node.type]
    return NODE_COLORS[node.type] || '#6b7280'
  }

  return (
    <div className="h-full flex flex-col">
      <Header
        title="Security Graph"
        subtitle="Interactive visualization of your cloud resource relationships and security posture"
        actions={
          <div className="flex gap-2">
            <button onClick={() => setShowFilters(!showFilters)} className="btn-outline flex items-center gap-1.5 text-sm">
              <FunnelIcon className="w-4 h-4" />
              Filters
            </button>
            <button onClick={loadData} className="btn-primary flex items-center gap-1.5 text-sm">
              <ArrowPathIcon className="w-4 h-4" />
              Refresh
            </button>
          </div>
        }
      />

      {/* Stats row */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-6">
        <StatCard title="Resources" value={stats?.total_resources || 0} icon={<CubeIcon className="w-5 h-5" />} />
        <StatCard title="At Risk" value={stats?.at_risk || 0} icon={<ShieldExclamationIcon className="w-5 h-5" />} valueColor="text-status-fail" />
        <StatCard title="Compliant" value={stats?.compliant || 0} icon={<ShieldCheckIcon className="w-5 h-5" />} valueColor="text-status-pass" />
        <StatCard title="Services" value={stats?.services || 0} icon={<ServerStackIcon className="w-5 h-5" />} />
        <StatCard title="Providers" value={stats?.providers || 0} icon={<CloudIcon className="w-5 h-5" />} />
        <StatCard
          title="Critical"
          value={stats?.by_severity?.critical || 0}
          icon={<ShieldExclamationIcon className="w-5 h-5" />}
          valueColor="text-severity-critical"
        />
      </div>

      {/* Filters panel */}
      {showFilters && (
        <div className="card mb-4 animate-fade-in">
          <div className="flex flex-wrap gap-4 items-end">
            <div>
              <label className="block text-xs font-medium text-brand-gray-500 mb-1">Cloud Provider</label>
              <select value={filterProvider} onChange={(e) => setFilterProvider(e.target.value)} className="px-3 py-1.5 border border-brand-gray-300 rounded-lg text-sm">
                <option value="">All</option>
                <option value="aws">AWS</option>
                <option value="azure">Azure</option>
                <option value="gcp">GCP</option>
                <option value="oci">OCI</option>
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-brand-gray-500 mb-1">Severity</label>
              <select value={filterSeverity} onChange={(e) => setFilterSeverity(e.target.value)} className="px-3 py-1.5 border border-brand-gray-300 rounded-lg text-sm">
                <option value="">All</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-brand-gray-500 mb-1">Status</label>
              <select value={filterStatus} onChange={(e) => setFilterStatus(e.target.value)} className="px-3 py-1.5 border border-brand-gray-300 rounded-lg text-sm">
                <option value="">All</option>
                <option value="at_risk">At Risk</option>
                <option value="compliant">Compliant</option>
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-brand-gray-500 mb-1">Depth</label>
              <select value={depth} onChange={(e) => setDepth(e.target.value as any)} className="px-3 py-1.5 border border-brand-gray-300 rounded-lg text-sm">
                <option value="service">Service level</option>
                <option value="resource">Resource level</option>
                <option value="region">Region level</option>
                <option value="provider">Provider level</option>
              </select>
            </div>
            <div className="relative">
              <label className="block text-xs font-medium text-brand-gray-500 mb-1">Search</label>
              <div className="relative">
                <MagnifyingGlassIcon className="absolute left-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-brand-gray-400" />
                <input
                  type="text"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="Search nodes..."
                  className="pl-8 pr-8 py-1.5 border border-brand-gray-300 rounded-lg text-sm w-48"
                />
                {search && (
                  <button onClick={() => setSearch('')} className="absolute right-2 top-1/2 -translate-y-1/2 text-brand-gray-400 hover:text-brand-gray-600">
                    <XMarkIcon className="w-4 h-4" />
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Main graph area */}
      <div className="flex-1 flex gap-4 min-h-0">
        {/* Graph canvas */}
        <div className="flex-1 card p-0 relative overflow-hidden">
          {loading ? (
            <div className="absolute inset-0 flex items-center justify-center">
              <div className="flex flex-col items-center gap-3">
                <div className="w-12 h-12 border-4 border-brand-green border-t-transparent rounded-full animate-spin" />
                <p className="text-sm text-brand-gray-400">Building security graph...</p>
              </div>
            </div>
          ) : layoutNodes.length <= 1 ? (
            <div className="absolute inset-0 flex items-center justify-center">
              <div className="text-center">
                <GlobeAltIcon className="w-16 h-16 text-brand-gray-300 mx-auto mb-4" />
                <h3 className="text-lg font-semibold text-brand-navy mb-2">No graph data</h3>
                <p className="text-sm text-brand-gray-400">Run a scan to populate the security graph.</p>
              </div>
            </div>
          ) : (
            <svg
              ref={svgRef}
              viewBox={`${viewBox.x} ${viewBox.y} ${viewBox.w} ${viewBox.h}`}
              className="w-full h-full cursor-grab active:cursor-grabbing"
              onMouseDown={handleMouseDown}
              onMouseMove={handleMouseMove}
              onMouseUp={handleMouseUp}
              onMouseLeave={handleMouseUp}
              onWheel={handleWheel}
            >
              <defs>
                <filter id="glow-critical">
                  <feGaussianBlur stdDeviation="4" result="blur" />
                  <feFlood floodColor="#dc2626" floodOpacity="0.4" result="color" />
                  <feComposite in="color" in2="blur" operator="in" result="glow" />
                  <feMerge><feMergeNode in="glow" /><feMergeNode in="SourceGraphic" /></feMerge>
                </filter>
                <filter id="glow-high">
                  <feGaussianBlur stdDeviation="3" result="blur" />
                  <feFlood floodColor="#f97316" floodOpacity="0.35" result="color" />
                  <feComposite in="color" in2="blur" operator="in" result="glow" />
                  <feMerge><feMergeNode in="glow" /><feMergeNode in="SourceGraphic" /></feMerge>
                </filter>
                <filter id="shadow">
                  <feDropShadow dx="0" dy="1" stdDeviation="2" floodOpacity="0.15" />
                </filter>
              </defs>

              {/* Edges */}
              {graphData?.edges.map((e, i) => {
                const src = nodeById[e.source]
                const tgt = nodeById[e.target]
                if (!src || !tgt || src.x === undefined || tgt.x === undefined) return null

                const active = connectedEdges.has(`${e.source}>${e.target}`)
                const midY = ((src.y || 0) + (tgt.y || 0)) / 2

                return (
                  <path
                    key={i}
                    d={`M${src.x},${src.y} C${src.x},${midY} ${tgt.x},${midY} ${tgt.x},${tgt.y}`}
                    fill="none"
                    stroke={active ? '#3b82f6' : '#d1d5db'}
                    strokeWidth={active ? 2 : 1}
                    strokeOpacity={active ? 1 : 0.5}
                    className="transition-all duration-200"
                  />
                )
              })}

              {/* Nodes */}
              {layoutNodes.map((node) => {
                if (node.x === undefined || node.y === undefined) return null

                const radius = getNodeRadius(node.type)
                const fill = getNodeFill(node)
                const isHovered = hoveredNode === node.id
                const isSelected = selectedNode?.id === node.id
                const isSearchMatch = highlightedIds.size > 0 && highlightedIds.has(node.id)
                const isDimmed = highlightedIds.size > 0 && !highlightedIds.has(node.id)

                let filterAttr: string | undefined
                if (node.severity === 'critical') filterAttr = 'url(#glow-critical)'
                else if (node.severity === 'high') filterAttr = 'url(#glow-high)'
                else if (isSelected || isHovered) filterAttr = 'url(#shadow)'

                return (
                  <g
                    key={node.id}
                    transform={`translate(${node.x}, ${node.y})`}
                    className="cursor-pointer"
                    onMouseEnter={() => setHoveredNode(node.id)}
                    onMouseLeave={() => setHoveredNode(null)}
                    onClick={(e) => {
                      e.stopPropagation()
                      setSelectedNode(node.id === selectedNode?.id ? null : node)
                    }}
                    opacity={isDimmed ? 0.25 : 1}
                  >
                    {/* Selection ring */}
                    {(isSelected || isSearchMatch) && (
                      <circle r={radius + 5} fill="none" stroke="#3b82f6" strokeWidth="2" strokeDasharray="4 2">
                        {isSearchMatch && (
                          <animate attributeName="stroke-dashoffset" from="0" to="12" dur="1s" repeatCount="indefinite" />
                        )}
                      </circle>
                    )}

                    {/* Main circle */}
                    <circle
                      r={isHovered ? radius + 3 : radius}
                      fill={fill}
                      filter={filterAttr}
                      className="transition-all duration-200"
                    />

                    {/* Inner icon/text */}
                    <text
                      textAnchor="middle"
                      dominantBaseline="central"
                      fill="white"
                      fontSize={radius * 0.7}
                      fontWeight="bold"
                      pointerEvents="none"
                    >
                      {node.type === 'root'
                        ? 'ENV'
                        : node.type === 'provider'
                        ? (node.meta?.provider_type || '?').toUpperCase().slice(0, 3)
                        : node.type === 'region'
                        ? 'R'
                        : node.type === 'service'
                        ? node.label.slice(0, 2).toUpperCase()
                        : node.meta?.failed_findings > 0
                        ? '!'
                        : '\u2713'}
                    </text>

                    {/* Label */}
                    {(zoomLevel > 0.5 || isHovered || isSelected) && (
                      <text
                        y={radius + 14}
                        textAnchor="middle"
                        fill="#374151"
                        fontSize="10"
                        fontWeight={isHovered ? '600' : '400'}
                        pointerEvents="none"
                        className="select-none"
                      >
                        {node.label.length > 20 ? node.label.slice(0, 18) + '...' : node.label}
                      </text>
                    )}

                    {/* Finding count badge */}
                    {node.type === 'resource' && node.meta?.failed_findings > 0 && (
                      <g transform={`translate(${radius * 0.7}, ${-radius * 0.7})`}>
                        <circle r="8" fill="#dc2626" />
                        <text
                          textAnchor="middle"
                          dominantBaseline="central"
                          fill="white"
                          fontSize="8"
                          fontWeight="bold"
                          pointerEvents="none"
                        >
                          {node.meta.failed_findings}
                        </text>
                      </g>
                    )}

                    {/* Hover tooltip */}
                    {isHovered && (
                      <g transform={`translate(0, ${-radius - 20})`}>
                        <rect x="-80" y="-18" width="160" height="20" rx="4" fill="#1f2937" fillOpacity="0.9" />
                        <text textAnchor="middle" dominantBaseline="central" fill="white" fontSize="9" y="-8">
                          {node.label.length > 28 ? node.label.slice(0, 26) + '...' : node.label}
                        </text>
                      </g>
                    )}
                  </g>
                )
              })}
            </svg>
          )}

          {/* Zoom controls */}
          <div className="absolute bottom-4 left-4 flex flex-col gap-1">
            <button onClick={zoomIn} className="w-8 h-8 bg-white border border-brand-gray-200 rounded-lg shadow-sm flex items-center justify-center hover:bg-brand-gray-50 text-brand-gray-600" title="Zoom in">
              <ArrowsPointingInIcon className="w-4 h-4" />
            </button>
            <button onClick={zoomOut} className="w-8 h-8 bg-white border border-brand-gray-200 rounded-lg shadow-sm flex items-center justify-center hover:bg-brand-gray-50 text-brand-gray-600" title="Zoom out">
              <ArrowsPointingOutIcon className="w-4 h-4" />
            </button>
            <button onClick={fitToView} className="w-8 h-8 bg-white border border-brand-gray-200 rounded-lg shadow-sm flex items-center justify-center hover:bg-brand-gray-50 text-brand-gray-600" title="Fit to view">
              <ViewfinderCircleIcon className="w-4 h-4" />
            </button>
          </div>

          {/* Legend */}
          <div className="absolute top-4 right-4 bg-white/90 backdrop-blur-sm rounded-lg border border-brand-gray-200 p-3 shadow-sm">
            <p className="text-xs font-semibold text-brand-gray-600 mb-2">Legend</p>
            <div className="space-y-1.5">
              {[
                { color: NODE_COLORS.provider, label: 'Provider' },
                { color: NODE_COLORS.region, label: 'Region' },
                { color: NODE_COLORS.service, label: 'Service' },
                { color: NODE_COLORS.resource, label: 'Resource (OK)' },
                { color: SEVERITY_COLORS.critical, label: 'Critical' },
                { color: SEVERITY_COLORS.high, label: 'High' },
                { color: SEVERITY_COLORS.medium, label: 'Medium' },
              ].map((item) => (
                <div key={item.label} className="flex items-center gap-2">
                  <div className="w-3 h-3 rounded-full" style={{ backgroundColor: item.color }} />
                  <span className="text-[10px] text-brand-gray-500">{item.label}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Node count */}
          <div className="absolute bottom-4 right-4 bg-white/90 backdrop-blur-sm rounded-lg border border-brand-gray-200 px-3 py-1.5 shadow-sm">
            <span className="text-xs text-brand-gray-500">
              {graphData?.summary?.total_nodes || 0} nodes &middot; {graphData?.summary?.total_edges || 0} edges
            </span>
          </div>
        </div>

        {/* Detail panel */}
        {selectedNode && (
          <div className="w-80 card overflow-y-auto animate-slide-in-right flex-shrink-0">
            <div className="flex items-start justify-between mb-4">
              <div className="flex items-center gap-2">
                <div
                  className="w-8 h-8 rounded-lg flex items-center justify-center"
                  style={{ backgroundColor: getNodeFill(selectedNode) }}
                >
                  <span className="text-white text-xs font-bold">
                    {selectedNode.type === 'root' ? 'ENV' : selectedNode.label.slice(0, 2).toUpperCase()}
                  </span>
                </div>
                <div>
                  <h3 className="text-sm font-bold text-brand-navy">{selectedNode.label}</h3>
                  <p className="text-xs text-brand-gray-400 capitalize">{selectedNode.type}</p>
                </div>
              </div>
              <button onClick={() => setSelectedNode(null)} className="p-1 rounded hover:bg-brand-gray-100">
                <XMarkIcon className="w-4 h-4 text-brand-gray-400" />
              </button>
            </div>

            {/* Properties */}
            <div className="space-y-3">
              <div>
                <p className="text-xs font-semibold text-brand-gray-500 mb-1.5">Properties</p>
                <div className="bg-brand-gray-50 rounded-lg p-3 space-y-2">
                  <div className="flex justify-between text-xs">
                    <span className="text-brand-gray-400">Type</span>
                    <span className="font-medium text-brand-navy capitalize">{selectedNode.type}</span>
                  </div>
                  <div className="flex justify-between text-xs">
                    <span className="text-brand-gray-400">Category</span>
                    <span className="font-medium text-brand-navy capitalize">{selectedNode.category}</span>
                  </div>
                  {selectedNode.severity && (
                    <div className="flex justify-between text-xs items-center">
                      <span className="text-brand-gray-400">Severity</span>
                      <Badge type="severity" value={selectedNode.severity} />
                    </div>
                  )}
                </div>
              </div>

              {/* Resource-specific details */}
              {selectedNode.type === 'resource' && selectedNode.meta && (
                <div>
                  <p className="text-xs font-semibold text-brand-gray-500 mb-1.5">Resource Details</p>
                  <div className="bg-brand-gray-50 rounded-lg p-3 space-y-2">
                    {selectedNode.meta.resource_id && (
                      <div className="flex justify-between text-xs">
                        <span className="text-brand-gray-400">Resource ID</span>
                        <span className="font-mono text-brand-navy text-[10px] truncate max-w-[140px]" title={selectedNode.meta.resource_id}>
                          {selectedNode.meta.resource_id}
                        </span>
                      </div>
                    )}
                    <div className="flex justify-between text-xs">
                      <span className="text-brand-gray-400">Findings</span>
                      <span className="font-medium text-brand-navy">{selectedNode.meta.total_findings}</span>
                    </div>
                    <div className="flex justify-between text-xs">
                      <span className="text-brand-gray-400">Failed</span>
                      <span className="font-medium text-status-fail">{selectedNode.meta.failed_findings}</span>
                    </div>
                    <div className="flex justify-between text-xs">
                      <span className="text-brand-gray-400">Passed</span>
                      <span className="font-medium text-status-pass">{selectedNode.meta.passed_findings}</span>
                    </div>
                    <div className="flex justify-between text-xs items-center">
                      <span className="text-brand-gray-400">Status</span>
                      <Badge type="status" value={selectedNode.meta.status === 'at_risk' ? 'FAIL' : 'PASS'} />
                    </div>
                  </div>
                </div>
              )}

              {/* Provider meta */}
              {selectedNode.type === 'provider' && selectedNode.meta && (
                <div>
                  <p className="text-xs font-semibold text-brand-gray-500 mb-1.5">Provider Details</p>
                  <div className="bg-brand-gray-50 rounded-lg p-3 space-y-2">
                    <div className="flex justify-between text-xs">
                      <span className="text-brand-gray-400">Provider</span>
                      <span className="font-medium text-brand-navy uppercase">{selectedNode.meta.provider_type}</span>
                    </div>
                    {selectedNode.meta.account_id && (
                      <div className="flex justify-between text-xs">
                        <span className="text-brand-gray-400">Account</span>
                        <span className="font-mono text-brand-navy text-[10px]">{selectedNode.meta.account_id}</span>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Connected nodes */}
              <div>
                <p className="text-xs font-semibold text-brand-gray-500 mb-1.5">Connections</p>
                <div className="space-y-1">
                  {graphData?.edges
                    .filter((e) => e.source === selectedNode.id || e.target === selectedNode.id)
                    .slice(0, 20)
                    .map((e, i) => {
                      const otherId = e.source === selectedNode.id ? e.target : e.source
                      const other = nodeById[otherId]
                      if (!other) return null
                      return (
                        <button
                          key={i}
                          onClick={() => setSelectedNode(other)}
                          className="w-full flex items-center gap-2 px-2 py-1.5 rounded-lg hover:bg-brand-gray-100 text-left transition-colors"
                        >
                          <div className="w-4 h-4 rounded-full flex-shrink-0" style={{ backgroundColor: getNodeFill(other) }} />
                          <span className="text-xs text-brand-gray-600 truncate">{other.label}</span>
                          <ChevronRightIcon className="w-3 h-3 text-brand-gray-400 ml-auto" />
                        </button>
                      )
                    })}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
