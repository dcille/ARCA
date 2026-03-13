import { cn, getSeverityColor, getStatusColor } from '@/lib/utils'

interface BadgeProps {
  type: 'severity' | 'status'
  value: string
  className?: string
}

export default function Badge({ type, value, className }: BadgeProps) {
  const colorClass = type === 'severity' ? getSeverityColor(value) : getStatusColor(value)

  return (
    <span className={cn('severity-badge', colorClass, className)}>
      {value}
    </span>
  )
}
