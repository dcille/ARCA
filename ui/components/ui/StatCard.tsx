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
}: StatCardProps) {
  return (
    <div className={cn('card', className)}>
      <div className="flex items-start justify-between">
        <div>
          <p className="text-sm font-medium text-brand-gray-500">{title}</p>
          <p className={cn('text-3xl font-bold mt-2', valueColor || 'text-brand-navy')}>
            {value}
          </p>
          {subtitle && (
            <p className="text-sm text-brand-gray-400 mt-1">{subtitle}</p>
          )}
          {trend && trendValue && (
            <p className={cn(
              'text-sm font-medium mt-2',
              trend === 'up' ? 'text-status-pass' : trend === 'down' ? 'text-status-fail' : 'text-brand-gray-400'
            )}>
              {trend === 'up' ? '+' : trend === 'down' ? '-' : ''}{trendValue}
            </p>
          )}
        </div>
        {icon && (
          <div className="p-3 rounded-xl bg-brand-green/10 text-brand-green">
            {icon}
          </div>
        )}
      </div>
    </div>
  )
}
