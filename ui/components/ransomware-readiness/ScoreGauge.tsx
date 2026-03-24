'use client'

const LEVEL_CONFIG: Record<string, { color: string; bg: string }> = {
  Excelente: { color: '#2D8B4E', bg: 'bg-emerald-50' },
  Bueno: { color: '#27AE60', bg: 'bg-green-50' },
  Moderado: { color: '#F39C12', bg: 'bg-amber-50' },
  Bajo: { color: '#E67E22', bg: 'bg-orange-50' },
  Critico: { color: '#C0392B', bg: 'bg-red-50' },
}

export default function ScoreGauge({
  score,
  level,
  trend,
  size = 'lg',
}: {
  score: number
  level: string
  trend?: number | null
  size?: 'sm' | 'md' | 'lg'
}) {
  const config = LEVEL_CONFIG[level] || LEVEL_CONFIG['Critico']
  const dims = size === 'lg' ? { w: 180, r: 68, sw: 10 } : size === 'md' ? { w: 120, r: 46, sw: 8 } : { w: 80, r: 30, sw: 6 }
  const circumference = 2 * Math.PI * dims.r
  const offset = circumference - (score / 100) * circumference
  const cx = dims.w / 2
  const cy = dims.w / 2

  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative" style={{ width: dims.w, height: dims.w }}>
        <svg viewBox={`0 0 ${dims.w} ${dims.w}`} className="w-full h-full -rotate-90">
          <circle cx={cx} cy={cy} r={dims.r} fill="none" stroke="#f0f0f0" strokeWidth={dims.sw} />
          <circle
            cx={cx} cy={cy} r={dims.r} fill="none"
            stroke={config.color} strokeWidth={dims.sw} strokeLinecap="round"
            strokeDasharray={circumference} strokeDashoffset={offset}
            className="transition-all duration-1000 ease-out"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={`font-bold text-brand-navy tabular-nums ${size === 'lg' ? 'text-5xl' : size === 'md' ? 'text-3xl' : 'text-xl'}`}>
            {score}
          </span>
          <span className="text-xs font-medium uppercase mt-0.5" style={{ color: config.color }}>
            {level}
          </span>
        </div>
      </div>
      {trend !== null && trend !== undefined && (
        <div className={`flex items-center gap-1 text-sm font-medium ${trend >= 0 ? 'text-emerald-600' : 'text-red-500'}`}>
          <span>{trend >= 0 ? '+' : ''}{trend}</span>
          <span className="text-brand-gray-400 font-normal">vs 30d ago</span>
        </div>
      )}
    </div>
  )
}
