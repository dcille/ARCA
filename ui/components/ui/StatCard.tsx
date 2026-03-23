import { cn } from '@/lib/utils'

interface StatCardProps {
  title: string
  value: string | number
  subtitle?: string
  icon?: React.ReactNode
  trend?: 'up' | 'down' | 'neutral'
  trendValue?: string
  className?: string
  valueColor?: string
  iconBg?: string
}

export default function StatCard({
  title,
  value,
  subtitle,
  icon,
  trend,
  trendValue,
  className,
  valueColor,
  iconBg,
}: StatCardProps) {
  return (
    <div className={cn('card group', className)}>
      <div className="flex items-start justify-between">
        <div className="min-w-0">
          <p className="text-xs font-semibold text-brand-gray-400 uppercase tracking-wider">{title}</p>
          <p className={cn('text-3xl font-bold mt-2 tabular-nums', valueColor || 'text-brand-navy')}>
            {value}
          </p>
          {subtitle && (
            <p className="text-sm text-brand-gray-400 mt-1 truncate">{subtitle}</p>
          )}
          {trend && trendValue && (
            <p className={cn(
              'text-sm font-medium mt-2 flex items-center gap-1',
              trend === 'up' ? 'text-status-pass' : trend === 'down' ? 'text-status-fail' : 'text-brand-gray-400'
            )}>
              {trend === 'up' && (
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 19.5l15-15m0 0H8.25m11.25 0v11.25" />
                </svg>
              )}
              {trend === 'down' && (
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 4.5l15 15m0 0V8.25m0 11.25H8.25" />
                </svg>
              )}
              {trendValue}
            </p>
          )}
        </div>
        {icon && (
          <div className={cn(
            'p-3 rounded-xl transition-transform duration-200 group-hover:scale-110',
            iconBg || 'bg-brand-green/10 text-brand-green'
          )}>
            {icon}
          </div>
        )}
      </div>
    </div>
  )
}
