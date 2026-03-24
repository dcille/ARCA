'use client'

import { Radar, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, ResponsiveContainer, Tooltip } from 'recharts'

interface DomainScore {
  id: string
  name: string
  score: number
  weight: number
}

export default function DomainRadarChart({ domains }: { domains: DomainScore[] }) {
  const data = domains.map(d => ({
    domain: d.id,
    name: d.name,
    score: d.score,
    fullMark: 100,
  }))

  return (
    <ResponsiveContainer width="100%" height={320}>
      <RadarChart data={data} cx="50%" cy="50%" outerRadius="75%">
        <PolarGrid stroke="#e5e7eb" />
        <PolarAngleAxis
          dataKey="name"
          tick={{ fontSize: 11, fill: '#6b7280' }}
          className="text-xs"
        />
        <PolarRadiusAxis
          angle={90}
          domain={[0, 100]}
          tick={{ fontSize: 10, fill: '#9ca3af' }}
          tickCount={5}
        />
        <Radar
          name="Score"
          dataKey="score"
          stroke="#012169"
          fill="#012169"
          fillOpacity={0.15}
          strokeWidth={2}
        />
        <Tooltip
          content={({ payload }) => {
            if (!payload?.length) return null
            const d = payload[0].payload
            return (
              <div className="bg-white border border-brand-gray-200 rounded-lg shadow-lg px-3 py-2 text-sm">
                <p className="font-semibold text-brand-navy">{d.name}</p>
                <p className="text-brand-gray-500">Score: <span className="font-bold">{d.score}</span>/100</p>
              </div>
            )
          }}
        />
      </RadarChart>
    </ResponsiveContainer>
  )
}
