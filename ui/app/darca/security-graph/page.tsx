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
  BoltIcon,
  LinkIcon,
  SignalIcon,
} from '@heroicons/react/24/outline'

/* ─── types ─── */
interface GraphNode {
  id: string
  label: string
  type: 'root' | 'provider' | 'region' | 'service' | 'resource' | 'internet'
  category: string
  severity: string | null
  meta: Record<string, any>
  x?: number
  y?: number
}

interface GraphEdge {
  source: string
  target: string
  label: string
  edge_type?: string
  risk_level?: string
  meta?: Record<string, any>
}

interface EdgeTypeDef {
  color: string
  style: string
  label: string
}

interface GraphData {
  nodes: GraphNode[]
  edges: GraphEdge[]
  edge_type_definitions?: Record<string, EdgeTypeDef>
  summary: Record<string, number>
}

interface GraphStats {
  total_resources: number
  at_risk: number
  compliant: number
  services: number
  providers: number
  by_severity: Record<string, number>
  internet_exposed?: number
  has_scan_data?: boolean
}

interface NodeDetail {
  node_id: string
  resource_id: string
  resource_name: string
  service: string
  region: string
  findings: Array<{
    id: string
    check_id: string
    check_title: string
    severity: string
    status: string
    status_extended: string
    remediation: string
  }>
  summary: {
    total_findings: number
    passed: number
    failed: number
    severity_breakdown: Record<string, number>
    pass_rate: number
  }
  compliance_frameworks: string[]
  is_internet_exposed: boolean
  is_data_store: boolean
}

interface BlastRadiusData {
  center_node: string
  center_label: string
  max_depth: number
  total_reachable: number
  reachable: Array<GraphNode & { blast_depth: number }>
  depth_counts: Record<number, number>
}

/* ─── colour palette ─── */
const NODE_COLORS: Record<string, string> = {
  root: '#1a2b4a',
  provider: '#3b82f6',
  region: '#8b5cf6',
  service: '#06b6d4',
  resource: '#10b981',
  internet: '#dc2626',
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#dc2626',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
  informational: '#6b7280',
}

const EDGE_COLORS: Record<string, string> = {
  hierarchy: '#d1d5db',
  has_access: '#3b82f6',
  exposes: '#ef4444',
  internet_exposed: '#dc2626',
  stores_data: '#8b5cf6',
  encrypts: '#10b981',
  logs: '#06b6d4',
  attack_path: '#dc2626',
  network_path: '#f59e0b',
  monitors: '#06b6d4',
}

const EDGE_DASH: Record<string, string> = {
  dashed: '8 4',
  dotted: '3 3',
  solid: '',
}

const EDGE_STYLE_MAP: Record<string, string> = {
  hierarchy: 'solid',
  has_access: 'solid',
  exposes: 'dashed',
  internet_exposed: 'dashed',
  stores_data: 'solid',
  encrypts: 'solid',
  logs: 'solid',
  attack_path: 'dotted',
  network_path: 'solid',
  monitors: 'solid',
}

/* ─── layout helpers ─── */
function buildRadialLayout(nodes: GraphNode[], edges: GraphEdge[]): GraphNode[] {
  if (nodes.length === 0) return []

  // Only use hierarchy edges for tree layout
  const hierarchyEdges = edges.filter((e) => !e.edge_type || e.edge_type === 'hierarchy')

  const childrenMap: Record<string, string[]> = {}
  const parentMap: Record<string, string> = {}
  for (const e of hierarchyEdges) {
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
    const parentGroups: Record<string, string[]> = {}
    for (const id of ids) {
      const p = parentMap[id] || root.id
      if (!parentGroups[p]) parentGroups[p] = []
      parentGroups[p].push(id)
    }

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

  // Position special nodes (internet) that aren't in the hierarchy
  for (const n of nodes) {
    if (!levels[n.id] && nodeMap[n.id]) {
      if (n.id === 'internet' || n.type === 'internet') {
        nodeMap[n.id].x = -400
        nodeMap[n.id].y = (maxLevel * LEVEL_SPACING) / 2
      } else if (!nodeMap[n.id].x && !nodeMap[n.id].y) {
        nodeMap[n.id].x = 400
        nodeMap[n.id].y = (maxLevel * LEVEL_SPACING) / 2
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
  const [nodeDetail, setNodeDetail] = useState<NodeDetail | null>(null)
  const [nodeDetailLoading, setNodeDetailLoading] = useState(false)
  const [blastRadius, setBlastRadius] = useState<BlastRadiusData | null>(null)
  const [blastRadiusLoading, setBlastRadiusLoading] = useState(false)
  const [showBlastRadius, setShowBlastRadius] = useState(false)
  const [hoveredNode, setHoveredNode] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [filterProvider, setFilterProvider] = useState('')
  const [filterSeverity, setFilterSeverity] = useState('')
  const [filterStatus, setFilterStatus] = useState('')
  const [depth, setDepth] = useState<'service' | 'resource'>('resource')
  const [showFilters, setShowFilters] = useState(false)
  const [showRelationships, setShowRelationships] = useState(true)
  const [activeEdgeFilter, setActiveEdgeFilter] = useState<string | null>(null)
  const [detailTab, setDetailTab] = useState<'info' | 'findings' | 'blast'>('info')

  // Pan & zoom state
  const svgRef = useRef<SVGSVGElement>(null)
  const [viewBox, setViewBox] = useState({ x: -600, y: -80, w: 1200, h: 800 })
  const [isPanning, setIsPanning] = useState(false)
  const [panStart, setPanStart] = useState({ x: 0, y: 0 })
  const [zoomLevel, setZoomLevel] = useState(1)

  const loadData = useCallback(async () => {
    setLoading(true)
    try {
      const params: Record<string, string> = { depth, include_relationships: 'true' }
      if (filterProvider) params.provider_type = filterProvider
      if (filterSeverity) params.severity = filterSeverity
      if (filterStatus) params.status = filterStatus
      if (activeEdgeFilter) params.edge_types = `hierarchy,${activeEdgeFilter}`

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
  }, [depth, filterProvider, filterSeverity, filterStatus, activeEdgeFilter])

  useEffect(() => {
    loadData()
  }, [loadData])

  // Load node detail when a resource node is selected
  useEffect(() => {
    if (!selectedNode || selectedNode.type !== 'resource') {
      setNodeDetail(null)
      setBlastRadius(null)
      setShowBlastRadius(false)
      setDetailTab('info')
      return
    }
    setNodeDetailLoading(true)
    api.getSecurityGraphNodeDetail(selectedNode.id)
      .then((data) => setNodeDetail(data))
      .catch(() => setNodeDetail(null))
      .finally(() => setNodeDetailLoading(false))
  }, [selectedNode])

  // Load blast radius on demand
  const loadBlastRadius = useCallback(async () => {
    if (!selectedNode) return
    setBlastRadiusLoading(true)
    try {
      const data = await api.getSecurityGraphBlastRadius(selectedNode.id, 3)
      setBlastRadius(data)
      setShowBlastRadius(true)
      setDetailTab('blast')
    } catch {
      setBlastRadius(null)
    } finally {
      setBlastRadiusLoading(false)
    }
  }, [selectedNode])

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

  // Separate hierarchy vs relationship edges
  const { hierarchyEdges, relationshipEdges } = useMemo(() => {
    if (!graphData) return { hierarchyEdges: [] as GraphEdge[], relationshipEdges: [] as GraphEdge[] }
    const h: GraphEdge[] = []
    const r: GraphEdge[] = []
    for (const e of graphData.edges) {
      if (!e.edge_type || e.edge_type === 'hierarchy') h.push(e)
      else r.push(e)
    }
    return { hierarchyEdges: h, relationshipEdges: r }
  }, [graphData])

  // Blast radius node IDs for highlighting
  const blastNodeIds = useMemo(() => {
    if (!showBlastRadius || !blastRadius) return new Set<string>()
    const set = new Set<string>()
    set.add(blastRadius.center_node)
    for (const n of blastRadius.reachable) set.add(n.id)
    return set
  }, [showBlastRadius, blastRadius])

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
      case 'internet': return 20
      case 'resource': return 12
      default: return 12
    }
  }

  const getNodeFill = (node: GraphNode) => {
    // Blast radius highlighting
    if (showBlastRadius && blastNodeIds.size > 0) {
      if (node.id === blastRadius?.center_node) return '#dc2626'
      if (blastNodeIds.has(node.id)) return '#f97316'
    }
    if (node.type === 'internet') return '#dc2626'
    if (node.severity) return SEVERITY_COLORS[node.severity] || NODE_COLORS[node.type]
    return NODE_COLORS[node.type] || '#6b7280'
  }

  const getEdgeColor = (edge: GraphEdge, isActive: boolean) => {
    if (isActive) return EDGE_COLORS[edge.edge_type || 'hierarchy'] || '#3b82f6'
    return EDGE_COLORS[edge.edge_type || 'hierarchy'] || '#d1d5db'
  }

  const getEdgeDash = (edge: GraphEdge) => {
    const style = EDGE_STYLE_MAP[edge.edge_type || 'hierarchy'] || 'solid'
    return EDGE_DASH[style] || ''
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
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-3 mb-6">
        <StatCard title="Resources" value={stats?.total_resources || 0} icon={<CubeIcon className="w-5 h-5" />} />
        <StatCard title="At Risk" value={stats?.at_risk || 0} icon={<ShieldExclamationIcon className="w-5 h-5" />} valueColor="text-status-fail" />
        <StatCard title="Compliant" value={stats?.compliant || 0} icon={<ShieldCheckIcon className="w-5 h-5" />} valueColor="text-status-pass" />
        <StatCard title="Services" value={stats?.services || 0} icon={<ServerStackIcon className="w-5 h-5" />} />
        <StatCard title="Providers" value={stats?.providers || 0} icon={<CloudIcon className="w-5 h-5" />} />
        <StatCard title="Critical" value={stats?.by_severity?.critical || 0} icon={<ShieldExclamationIcon className="w-5 h-5" />} valueColor="text-severity-critical" />
        <StatCard title="Internet Exposed" value={stats?.internet_exposed || 0} icon={<SignalIcon className="w-5 h-5" />} valueColor="text-severity-critical" />
        <StatCard title="Relationships" value={graphData?.summary?.relationship_edges || 0} icon={<LinkIcon className="w-5 h-5" />} />
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
            <div>
              <label className="block text-xs font-medium text-brand-gray-500 mb-1">Edge Type</label>
              <select value={activeEdgeFilter || ''} onChange={(e) => setActiveEdgeFilter(e.target.value || null)} className="px-3 py-1.5 border border-brand-gray-300 rounded-lg text-sm">
                <option value="">All edges</option>
                <option value="has_access">IAM Access</option>
                <option value="internet_exposed">Internet Exposed</option>
                <option value="network_path">Network Path</option>
                <option value="attack_path">Attack Path</option>
                <option value="encrypts">Encryption</option>
                <option value="monitors">Monitoring</option>
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
            <div className="flex items-end">
              <label className="flex items-center gap-2 cursor-pointer py-1.5">
                <input
                  type="checkbox"
                  checked={showRelationships}
                  onChange={(e) => setShowRelationships(e.target.checked)}
                  className="rounded border-brand-gray-300"
                />
                <span className="text-xs text-brand-gray-600">Show relationships</span>
              </label>
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
                {/* Arrow markers for relationship edges */}
                {Object.entries(EDGE_COLORS).map(([type, color]) => (
                  <marker key={type} id={`arrow-${type}`} viewBox="0 0 10 10" refX="10" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                    <path d="M 0 0 L 10 5 L 0 10 z" fill={color} />
                  </marker>
                ))}
                <marker id="arrow-default" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="#94a3b8" />
                </marker>
              </defs>

              {/* Hierarchy Edges */}
              {hierarchyEdges.map((e, i) => {
                const src = nodeById[e.source]
                const tgt = nodeById[e.target]
                if (!src || !tgt || src.x === undefined || tgt.x === undefined) return null
                const active = connectedEdges.has(`${e.source}>${e.target}`)
                const midY = ((src.y || 0) + (tgt.y || 0)) / 2
                return (
                  <path
                    key={`h-${i}`}
                    d={`M${src.x},${src.y} C${src.x},${midY} ${tgt.x},${midY} ${tgt.x},${tgt.y}`}
                    fill="none"
                    stroke={active ? '#94a3b8' : '#e2e8f0'}
                    strokeWidth={active ? 1.5 : 0.8}
                    strokeOpacity={active ? 0.8 : 0.4}
                  />
                )
              })}

              {/* Relationship Edges */}
              {showRelationships && relationshipEdges.map((e, i) => {
                const src = nodeById[e.source]
                const tgt = nodeById[e.target]
                if (!src || !tgt || src.x === undefined || tgt.x === undefined) return null
                const active = connectedEdges.has(`${e.source}>${e.target}`)
                const color = getEdgeColor(e, active)
                const dash = getEdgeDash(e)
                // Curved path with offset to distinguish from hierarchy edges
                const dx = (tgt.x || 0) - (src.x || 0)
                const dy = (tgt.y || 0) - (src.y || 0)
                const cx1 = (src.x || 0) + dx * 0.25 - dy * 0.15
                const cy1 = (src.y || 0) + dy * 0.25 + dx * 0.15
                const cx2 = (src.x || 0) + dx * 0.75 - dy * 0.15
                const cy2 = (src.y || 0) + dy * 0.75 + dx * 0.15
                return (
                  <g key={`r-${i}`}>
                    <path
                      d={`M${src.x},${src.y} C${cx1},${cy1} ${cx2},${cy2} ${tgt.x},${tgt.y}`}
                      fill="none"
                      stroke={color}
                      strokeWidth={active ? 2.5 : 1.5}
                      strokeOpacity={active ? 1 : 0.6}
                      strokeDasharray={dash}
                      markerEnd={`url(#arrow-${e.edge_type || 'default'})`}
                    />
                    {/* Edge label on hover */}
                    {active && e.label && (
                      <g transform={`translate(${(cx1 + cx2) / 2}, ${(cy1 + cy2) / 2})`}>
                        <rect x="-40" y="-10" width="80" height="16" rx="3" fill="#1f2937" fillOpacity="0.85" />
                        <text textAnchor="middle" dominantBaseline="central" fill="white" fontSize="8" y="-2">{e.label.length > 16 ? e.label.slice(0, 14) + '..' : e.label}</text>
                      </g>
                    )}
                  </g>
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
                const isBlastNode = showBlastRadius && blastNodeIds.has(node.id)
                const isDimmed =
                  (highlightedIds.size > 0 && !highlightedIds.has(node.id)) ||
                  (showBlastRadius && blastNodeIds.size > 0 && !blastNodeIds.has(node.id))

                let filterAttr: string | undefined
                if (node.severity === 'critical' || (isBlastNode && node.id === blastRadius?.center_node)) filterAttr = 'url(#glow-critical)'
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
                    opacity={isDimmed ? 0.15 : 1}
                  >
                    {/* Blast radius ring */}
                    {isBlastNode && node.id === blastRadius?.center_node && (
                      <circle r={radius + 8} fill="none" stroke="#dc2626" strokeWidth="2" strokeDasharray="6 3">
                        <animate attributeName="stroke-dashoffset" from="0" to="18" dur="1.5s" repeatCount="indefinite" />
                      </circle>
                    )}

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
                        : node.type === 'internet'
                        ? 'NET'
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
                        <text textAnchor="middle" dominantBaseline="central" fill="white" fontSize="8" fontWeight="bold" pointerEvents="none">
                          {node.meta.failed_findings}
                        </text>
                      </g>
                    )}

                    {/* Data store / internet badge */}
                    {node.type === 'resource' && node.meta?.is_data_store && (
                      <g transform={`translate(${-radius * 0.7}, ${-radius * 0.7})`}>
                        <circle r="6" fill="#8b5cf6" />
                        <text textAnchor="middle" dominantBaseline="central" fill="white" fontSize="7" pointerEvents="none">D</text>
                      </g>
                    )}

                    {/* Hover tooltip */}
                    {isHovered && (
                      <g transform={`translate(0, ${-radius - 20})`}>
                        <rect x="-90" y="-26" width="180" height="28" rx="4" fill="#1f2937" fillOpacity="0.92" />
                        <text textAnchor="middle" dominantBaseline="central" fill="white" fontSize="9" y="-16">
                          {node.label.length > 30 ? node.label.slice(0, 28) + '...' : node.label}
                        </text>
                        {node.type === 'resource' && (
                          <text textAnchor="middle" dominantBaseline="central" fill="#94a3b8" fontSize="7" y="-5">
                            {node.meta?.service || ''} {node.meta?.status === 'at_risk' ? '| At Risk' : '| OK'}
                          </text>
                        )}
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
          <div className="absolute top-4 right-4 bg-white/90 backdrop-blur-sm rounded-lg border border-brand-gray-200 p-3 shadow-sm max-h-[calc(100%-2rem)] overflow-y-auto">
            <p className="text-xs font-semibold text-brand-gray-600 mb-2">Nodes</p>
            <div className="space-y-1">
              {[
                { color: NODE_COLORS.provider, label: 'Provider' },
                { color: NODE_COLORS.region, label: 'Region' },
                { color: NODE_COLORS.service, label: 'Service' },
                { color: NODE_COLORS.resource, label: 'Resource (OK)' },
                { color: NODE_COLORS.internet, label: 'Internet' },
                { color: SEVERITY_COLORS.critical, label: 'Critical' },
                { color: SEVERITY_COLORS.high, label: 'High' },
                { color: SEVERITY_COLORS.medium, label: 'Medium' },
              ].map((item) => (
                <div key={item.label} className="flex items-center gap-2">
                  <div className="w-2.5 h-2.5 rounded-full flex-shrink-0" style={{ backgroundColor: item.color }} />
                  <span className="text-[10px] text-brand-gray-500">{item.label}</span>
                </div>
              ))}
            </div>
            {showRelationships && (
              <>
                <p className="text-xs font-semibold text-brand-gray-600 mt-3 mb-1.5">Edges</p>
                <div className="space-y-1">
                  {[
                    { color: EDGE_COLORS.has_access, label: 'IAM Access', dash: '' },
                    { color: EDGE_COLORS.internet_exposed, label: 'Internet Exp.', dash: '4 2' },
                    { color: EDGE_COLORS.attack_path, label: 'Attack Path', dash: '2 2' },
                    { color: EDGE_COLORS.network_path, label: 'Network Path', dash: '' },
                    { color: EDGE_COLORS.encrypts, label: 'Encrypts', dash: '' },
                    { color: EDGE_COLORS.monitors, label: 'Monitors', dash: '' },
                  ].map((item) => (
                    <div key={item.label} className="flex items-center gap-2">
                      <svg width="16" height="8" className="flex-shrink-0">
                        <line x1="0" y1="4" x2="16" y2="4" stroke={item.color} strokeWidth="2" strokeDasharray={item.dash} />
                      </svg>
                      <span className="text-[10px] text-brand-gray-500">{item.label}</span>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>

          {/* Node count */}
          <div className="absolute bottom-4 right-4 bg-white/90 backdrop-blur-sm rounded-lg border border-brand-gray-200 px-3 py-1.5 shadow-sm">
            <span className="text-xs text-brand-gray-500">
              {graphData?.summary?.total_nodes || 0} nodes &middot; {graphData?.summary?.total_edges || 0} edges
              {(graphData?.summary?.relationship_edges || 0) > 0 && (
                <> &middot; {graphData?.summary?.relationship_edges} relationships</>
              )}
            </span>
          </div>
        </div>

        {/* Detail panel */}
        {selectedNode && (
          <div className="w-96 card overflow-y-auto animate-slide-in-right flex-shrink-0">
            {/* Header */}
            <div className="flex items-start justify-between mb-3">
              <div className="flex items-center gap-2 min-w-0">
                <div className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0" style={{ backgroundColor: getNodeFill(selectedNode) }}>
                  <span className="text-white text-xs font-bold">
                    {selectedNode.type === 'root' ? 'ENV' : selectedNode.type === 'internet' ? 'NET' : selectedNode.label.slice(0, 2).toUpperCase()}
                  </span>
                </div>
                <div className="min-w-0">
                  <h3 className="text-sm font-bold text-brand-navy truncate">{selectedNode.label}</h3>
                  <p className="text-xs text-brand-gray-400 capitalize">{selectedNode.type}</p>
                </div>
              </div>
              <button onClick={() => { setSelectedNode(null); setShowBlastRadius(false) }} className="p-1 rounded hover:bg-brand-gray-100 flex-shrink-0">
                <XMarkIcon className="w-4 h-4 text-brand-gray-400" />
              </button>
            </div>

            {/* Tabs for resource nodes */}
            {selectedNode.type === 'resource' && (
              <div className="flex gap-1 mb-3 border-b border-brand-gray-200 pb-1">
                {(['info', 'findings', 'blast'] as const).map((tab) => (
                  <button
                    key={tab}
                    onClick={() => {
                      setDetailTab(tab)
                      if (tab === 'blast' && !blastRadius) loadBlastRadius()
                    }}
                    className={`px-3 py-1 text-xs rounded-t-lg transition-colors ${
                      detailTab === tab
                        ? 'bg-brand-gray-100 text-brand-navy font-semibold'
                        : 'text-brand-gray-400 hover:text-brand-gray-600'
                    }`}
                  >
                    {tab === 'info' ? 'Info' : tab === 'findings' ? 'Findings' : 'Blast Radius'}
                  </button>
                ))}
              </div>
            )}

            <div className="space-y-3">
              {/* ── INFO TAB ── */}
              {detailTab === 'info' && (
                <>
                  {/* Properties */}
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

                  {/* Resource-specific details */}
                  {selectedNode.type === 'resource' && selectedNode.meta && (
                    <div>
                      <p className="text-xs font-semibold text-brand-gray-500 mb-1.5">Resource Details</p>
                      <div className="bg-brand-gray-50 rounded-lg p-3 space-y-2">
                        {selectedNode.meta.resource_id && (
                          <div className="flex justify-between text-xs">
                            <span className="text-brand-gray-400">Resource ID</span>
                            <span className="font-mono text-brand-navy text-[10px] truncate max-w-[160px]" title={selectedNode.meta.resource_id}>
                              {selectedNode.meta.resource_id}
                            </span>
                          </div>
                        )}
                        <div className="flex justify-between text-xs">
                          <span className="text-brand-gray-400">Service</span>
                          <span className="font-medium text-brand-navy">{selectedNode.meta.service}</span>
                        </div>
                        <div className="flex justify-between text-xs">
                          <span className="text-brand-gray-400">Region</span>
                          <span className="font-medium text-brand-navy">{selectedNode.meta.region}</span>
                        </div>
                        <div className="flex justify-between text-xs">
                          <span className="text-brand-gray-400">Findings</span>
                          <span className="font-medium text-brand-navy">{selectedNode.meta.total_findings}</span>
                        </div>
                        <div className="flex justify-between text-xs">
                          <span className="text-brand-gray-400">Failed / Passed</span>
                          <span>
                            <span className="font-medium text-status-fail">{selectedNode.meta.failed_findings}</span>
                            <span className="text-brand-gray-300 mx-1">/</span>
                            <span className="font-medium text-status-pass">{selectedNode.meta.passed_findings}</span>
                          </span>
                        </div>
                        <div className="flex justify-between text-xs items-center">
                          <span className="text-brand-gray-400">Status</span>
                          <Badge type="status" value={selectedNode.meta.status === 'at_risk' ? 'FAIL' : 'PASS'} />
                        </div>
                        {selectedNode.meta.is_data_store && (
                          <div className="flex justify-between text-xs items-center">
                            <span className="text-brand-gray-400">Data Store</span>
                            <span className="text-xs text-purple-600 font-medium">Yes</span>
                          </div>
                        )}
                        {selectedNode.meta.is_identity && (
                          <div className="flex justify-between text-xs items-center">
                            <span className="text-brand-gray-400">IAM Resource</span>
                            <span className="text-xs text-blue-600 font-medium">Yes</span>
                          </div>
                        )}
                      </div>

                      {/* Internet exposure & compliance from nodeDetail */}
                      {nodeDetail && (
                        <>
                          {nodeDetail.is_internet_exposed && (
                            <div className="mt-2 px-3 py-2 bg-red-50 border border-red-200 rounded-lg">
                              <div className="flex items-center gap-1.5">
                                <SignalIcon className="w-3.5 h-3.5 text-red-500" />
                                <span className="text-xs font-semibold text-red-700">Internet Exposed</span>
                              </div>
                            </div>
                          )}
                          {nodeDetail.compliance_frameworks.length > 0 && (
                            <div className="mt-2">
                              <p className="text-xs font-semibold text-brand-gray-500 mb-1">Compliance</p>
                              <div className="flex flex-wrap gap-1">
                                {nodeDetail.compliance_frameworks.slice(0, 8).map((fw) => (
                                  <span key={fw} className="px-1.5 py-0.5 text-[10px] bg-brand-gray-100 text-brand-gray-600 rounded">{fw}</span>
                                ))}
                                {nodeDetail.compliance_frameworks.length > 8 && (
                                  <span className="px-1.5 py-0.5 text-[10px] bg-brand-gray-100 text-brand-gray-400 rounded">+{nodeDetail.compliance_frameworks.length - 8}</span>
                                )}
                              </div>
                            </div>
                          )}
                        </>
                      )}

                      {/* Quick blast radius button */}
                      <button
                        onClick={loadBlastRadius}
                        disabled={blastRadiusLoading}
                        className="mt-2 w-full flex items-center justify-center gap-1.5 px-3 py-1.5 text-xs bg-orange-50 border border-orange-200 text-orange-700 rounded-lg hover:bg-orange-100 transition-colors disabled:opacity-50"
                      >
                        <BoltIcon className="w-3.5 h-3.5" />
                        {blastRadiusLoading ? 'Computing...' : 'Compute Blast Radius'}
                      </button>
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

                  {/* Connected nodes - split by hierarchy vs relationships */}
                  <div>
                    <p className="text-xs font-semibold text-brand-gray-500 mb-1.5">Connections</p>
                    <div className="space-y-1 max-h-48 overflow-y-auto">
                      {graphData?.edges
                        .filter((e) => e.source === selectedNode.id || e.target === selectedNode.id)
                        .filter((e) => e.edge_type !== 'hierarchy')
                        .slice(0, 30)
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
                              <svg width="12" height="8" className="flex-shrink-0">
                                <line x1="0" y1="4" x2="12" y2="4" stroke={EDGE_COLORS[e.edge_type || 'hierarchy'] || '#d1d5db'} strokeWidth="2" strokeDasharray={getEdgeDash(e)} />
                              </svg>
                              <span className="text-xs text-brand-gray-600 truncate">{other.label}</span>
                              <span className="text-[9px] text-brand-gray-400 ml-auto flex-shrink-0">{e.label || e.edge_type}</span>
                            </button>
                          )
                        })}
                      {/* Hierarchy connections */}
                      {graphData?.edges
                        .filter((e) => e.source === selectedNode.id || e.target === selectedNode.id)
                        .filter((e) => !e.edge_type || e.edge_type === 'hierarchy')
                        .slice(0, 10)
                        .map((e, i) => {
                          const otherId = e.source === selectedNode.id ? e.target : e.source
                          const other = nodeById[otherId]
                          if (!other) return null
                          return (
                            <button
                              key={`h-${i}`}
                              onClick={() => setSelectedNode(other)}
                              className="w-full flex items-center gap-2 px-2 py-1.5 rounded-lg hover:bg-brand-gray-100 text-left transition-colors"
                            >
                              <div className="w-3 h-3 rounded-full flex-shrink-0" style={{ backgroundColor: getNodeFill(other) }} />
                              <span className="text-xs text-brand-gray-600 truncate">{other.label}</span>
                              <ChevronRightIcon className="w-3 h-3 text-brand-gray-400 ml-auto" />
                            </button>
                          )
                        })}
                    </div>
                  </div>
                </>
              )}

              {/* ── FINDINGS TAB ── */}
              {detailTab === 'findings' && selectedNode.type === 'resource' && (
                <div>
                  {nodeDetailLoading ? (
                    <div className="flex items-center justify-center py-6">
                      <div className="w-6 h-6 border-2 border-brand-green border-t-transparent rounded-full animate-spin" />
                    </div>
                  ) : nodeDetail ? (
                    <>
                      {/* Summary bar */}
                      <div className="bg-brand-gray-50 rounded-lg p-3 mb-3">
                        <div className="flex items-center justify-between text-xs mb-2">
                          <span className="text-brand-gray-500">Pass Rate</span>
                          <span className="font-semibold text-brand-navy">{nodeDetail.summary.pass_rate}%</span>
                        </div>
                        <div className="w-full bg-brand-gray-200 rounded-full h-1.5">
                          <div className="bg-green-500 h-1.5 rounded-full" style={{ width: `${nodeDetail.summary.pass_rate}%` }} />
                        </div>
                        <div className="flex justify-between mt-2">
                          {Object.entries(nodeDetail.summary.severity_breakdown).map(([sev, count]) => (
                            count > 0 && (
                              <div key={sev} className="text-center">
                                <div className="text-[10px] text-brand-gray-400 capitalize">{sev}</div>
                                <div className="text-xs font-semibold" style={{ color: SEVERITY_COLORS[sev] || '#6b7280' }}>{count}</div>
                              </div>
                            )
                          ))}
                        </div>
                      </div>

                      {/* Finding list */}
                      <div className="space-y-2 max-h-[400px] overflow-y-auto">
                        {nodeDetail.findings.map((f) => (
                          <div key={f.id} className={`p-2.5 rounded-lg border ${f.status === 'FAIL' ? 'border-red-200 bg-red-50/50' : 'border-green-200 bg-green-50/50'}`}>
                            <div className="flex items-start justify-between gap-2 mb-1">
                              <span className="text-xs font-medium text-brand-navy leading-tight">{f.check_title || f.check_id}</span>
                              <Badge type="severity" value={f.severity} />
                            </div>
                            {f.status_extended && (
                              <p className="text-[10px] text-brand-gray-500 leading-relaxed mb-1">{f.status_extended.length > 120 ? f.status_extended.slice(0, 118) + '...' : f.status_extended}</p>
                            )}
                            {f.remediation && f.status === 'FAIL' && (
                              <p className="text-[10px] text-blue-600 leading-relaxed">{f.remediation.length > 100 ? f.remediation.slice(0, 98) + '...' : f.remediation}</p>
                            )}
                          </div>
                        ))}
                      </div>
                    </>
                  ) : (
                    <p className="text-xs text-brand-gray-400 text-center py-4">No findings data available.</p>
                  )}
                </div>
              )}

              {/* ── BLAST RADIUS TAB ── */}
              {detailTab === 'blast' && selectedNode.type === 'resource' && (
                <div>
                  {blastRadiusLoading ? (
                    <div className="flex flex-col items-center justify-center py-6 gap-2">
                      <div className="w-6 h-6 border-2 border-orange-500 border-t-transparent rounded-full animate-spin" />
                      <span className="text-xs text-brand-gray-400">Computing blast radius...</span>
                    </div>
                  ) : blastRadius ? (
                    <>
                      <div className="bg-orange-50 border border-orange-200 rounded-lg p-3 mb-3">
                        <div className="flex items-center gap-2 mb-2">
                          <BoltIcon className="w-4 h-4 text-orange-600" />
                          <span className="text-xs font-semibold text-orange-800">
                            {blastRadius.total_reachable} reachable resource{blastRadius.total_reachable !== 1 ? 's' : ''}
                          </span>
                        </div>
                        <p className="text-[10px] text-orange-700">
                          If &quot;{blastRadius.center_label}&quot; is compromised, {blastRadius.total_reachable} other resource{blastRadius.total_reachable !== 1 ? 's' : ''} could be impacted within {blastRadius.max_depth} hops.
                        </p>
                        <div className="flex gap-3 mt-2">
                          {Object.entries(blastRadius.depth_counts).map(([d, count]) => (
                            <div key={d} className="text-center">
                              <div className="text-xs font-bold text-orange-700">{count}</div>
                              <div className="text-[9px] text-orange-500">Hop {d}</div>
                            </div>
                          ))}
                        </div>
                      </div>

                      <div className="flex gap-2 mb-2">
                        <button
                          onClick={() => setShowBlastRadius(!showBlastRadius)}
                          className={`flex-1 text-xs px-3 py-1.5 rounded-lg transition-colors ${
                            showBlastRadius ? 'bg-orange-500 text-white' : 'bg-orange-100 text-orange-700'
                          }`}
                        >
                          {showBlastRadius ? 'Hide on graph' : 'Show on graph'}
                        </button>
                      </div>

                      <div className="space-y-1 max-h-60 overflow-y-auto">
                        {blastRadius.reachable.map((n) => (
                          <div key={n.id} className="flex items-center gap-2 px-2 py-1.5 rounded-lg bg-brand-gray-50">
                            <div className="w-3 h-3 rounded-full flex-shrink-0" style={{ backgroundColor: SEVERITY_COLORS[n.severity || ''] || '#10b981' }} />
                            <span className="text-xs text-brand-gray-600 truncate">{n.label}</span>
                            <span className="text-[9px] text-orange-500 ml-auto flex-shrink-0">Hop {n.blast_depth}</span>
                          </div>
                        ))}
                      </div>
                    </>
                  ) : (
                    <div className="text-center py-4">
                      <p className="text-xs text-brand-gray-400 mb-2">Blast radius not yet computed.</p>
                      <button onClick={loadBlastRadius} className="text-xs text-orange-600 hover:underline">Compute now</button>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
