import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function getSeverityColor(severity: string): string {
  const map: Record<string, string> = {
    critical: 'bg-severity-critical text-white',
    high: 'bg-severity-high text-white',
    medium: 'bg-severity-medium text-white',
    low: 'bg-severity-low text-white',
    informational: 'bg-severity-informational text-white',
  }
  return map[severity?.toLowerCase()] || map.informational
}

export function getStatusColor(status: string): string {
  const map: Record<string, string> = {
    PASS: 'bg-status-pass text-white',
    FAIL: 'bg-status-fail text-white',
    pass: 'bg-status-pass text-white',
    fail: 'bg-status-fail text-white',
    running: 'bg-status-running text-white',
    pending: 'bg-status-pending text-white',
    completed: 'bg-status-pass text-white',
    failed: 'bg-status-fail text-white',
    connected: 'bg-status-pass text-white',
    error: 'bg-status-fail text-white',
  }
  return map[status?.toLowerCase()] || 'bg-brand-gray-400 text-white'
}

export function getSaaSIcon(provider: string): string {
  const map: Record<string, string> = {
    servicenow: 'SN',
    m365: 'M365',
    salesforce: 'SF',
    snowflake: 'SF*',
  }
  return map[provider] || provider.slice(0, 2).toUpperCase()
}

export function getSaaSLabel(provider: string): string {
  const map: Record<string, string> = {
    servicenow: 'ServiceNow',
    m365: 'Microsoft 365',
    salesforce: 'Salesforce',
    snowflake: 'Snowflake',
  }
  return map[provider] || provider
}

export function formatDate(date: string | null): string {
  if (!date) return 'N/A'
  return new Date(date).toLocaleString()
}

export function formatPercent(value: number): string {
  return `${value.toFixed(1)}%`
}
