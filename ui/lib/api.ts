/**
 * D-ARCA API Client.
 *
 * All requests go to the same origin (e.g. http://localhost:3000/api/...).
 * Next.js rewrites proxy them to the backend API server, so the browser
 * never needs to reach port 8080 directly — no CORS, no cross-origin issues.
 */

class ApiClient {
  private getToken(): string | null {
    if (typeof window === 'undefined') return null
    try {
      const stored = localStorage.getItem('darca-auth')
      if (stored) {
        const parsed = JSON.parse(stored)
        return parsed.state?.token || null
      }
    } catch {
      return null
    }
    return null
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
    options?: { params?: Record<string, string> }
  ): Promise<T> {
    // path already starts with /api/v1/...
    const url = new URL(path, window.location.origin)
    if (options?.params) {
      Object.entries(options.params).forEach(([key, val]) => {
        if (val) url.searchParams.set(key, val)
      })
    }

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    }

    const token = this.getToken()
    if (token) {
      headers['Authorization'] = `Bearer ${token}`
    }

    const response = await fetch(url.toString(), {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    })

    if (response.status === 401) {
      if (typeof window !== 'undefined') {
        localStorage.removeItem('darca-auth')
        window.location.href = '/auth/sign-in'
      }
      throw new Error('Unauthorized')
    }

    if (!response.ok) {
      const error = await response.json().catch(() => ({}))
      throw new Error(error.detail || `Request failed: ${response.status}`)
    }

    if (response.status === 204) return {} as T
    return response.json()
  }

  // Auth
  async login(email: string, password: string) {
    return this.request<{ access_token: string; user: any }>('POST', '/api/v1/auth/login', { email, password })
  }

  async register(email: string, password: string, name: string) {
    return this.request<{ access_token: string; user: any }>('POST', '/api/v1/auth/register', { email, password, name })
  }

  async getMe() {
    return this.request<any>('GET', '/api/v1/auth/me')
  }

  // Dashboard
  async getDashboardOverview() {
    return this.request<any>('GET', '/api/v1/dashboard/overview')
  }

  async getDashboardTrends(days?: number) {
    const params = days ? { days: String(days) } : undefined
    return this.request<any>('GET', '/api/v1/dashboard/trends', undefined, { params })
  }

  // Providers
  async getProviders() {
    return this.request<any[]>('GET', '/api/v1/providers')
  }

  async createProvider(data: any) {
    return this.request<any>('POST', '/api/v1/providers', data)
  }

  async deleteProvider(id: string) {
    return this.request<void>('DELETE', `/api/v1/providers/${id}`)
  }

  // Scans
  async getScans(scanType?: string) {
    const params = scanType ? { scan_type: scanType } : undefined
    return this.request<any[]>('GET', '/api/v1/scans', undefined, { params })
  }

  async createScan(data: any) {
    return this.request<any>('POST', '/api/v1/scans', data)
  }

  async getScan(id: string) {
    return this.request<any>('GET', `/api/v1/scans/${id}`)
  }

  // Findings
  async getFindings(params?: Record<string, string>) {
    return this.request<any[]>('GET', '/api/v1/findings', undefined, { params })
  }

  async getFindingsStats(params?: Record<string, string>) {
    return this.request<any>('GET', '/api/v1/findings/stats', undefined, { params })
  }

  // Compliance
  async getComplianceFrameworks() {
    return this.request<any[]>('GET', '/api/v1/compliance/frameworks')
  }

  async getComplianceSummary(framework?: string) {
    const params = framework ? { framework } : undefined
    return this.request<any>('GET', '/api/v1/compliance/summary', undefined, { params })
  }

  // SaaS
  async getSaaSConnections(providerType?: string) {
    const params = providerType ? { provider_type: providerType } : undefined
    return this.request<any[]>('GET', '/api/v1/saas/connections', undefined, { params })
  }

  async createSaaSConnection(data: any) {
    return this.request<any>('POST', '/api/v1/saas/connections', data)
  }

  async deleteSaaSConnection(id: string) {
    return this.request<void>('DELETE', `/api/v1/saas/connections/${id}`)
  }

  async testSaaSConnection(id: string) {
    return this.request<{ success: boolean; message: string }>('POST', `/api/v1/saas/connections/${id}/test`)
  }

  async getSaaSFindings(params?: Record<string, string>) {
    return this.request<any[]>('GET', '/api/v1/saas/findings', undefined, { params })
  }

  async getSaaSOverview() {
    return this.request<any>('GET', '/api/v1/saas/overview')
  }

  async getSaaSFindingsStats(providerType?: string) {
    const params = providerType ? { provider_type: providerType } : undefined
    return this.request<any>('GET', '/api/v1/saas/findings/stats', undefined, { params })
  }
  // Attack Paths
  async analyzeAttackPaths(scanId?: string) {
    const params = scanId ? { scan_id: scanId } : undefined
    return this.request<any>('POST', '/api/v1/attack-paths/analyze', undefined, { params })
  }

  async getAttackPaths(params?: Record<string, string>) {
    return this.request<any[]>('GET', '/api/v1/attack-paths', undefined, { params })
  }

  async getAttackPathsSummary() {
    return this.request<any>('GET', '/api/v1/attack-paths/summary')
  }

  async getAttackPath(id: string) {
    return this.request<any>('GET', `/api/v1/attack-paths/${id}`)
  }
  // Reports
  async downloadReport(type: 'executive' | 'technical', params?: Record<string, string>) {
    const url = new URL(`/api/v1/reports/${type}`, window.location.origin)
    if (params) {
      Object.entries(params).forEach(([key, val]) => {
        if (val) url.searchParams.set(key, val)
      })
    }
    const token = this.getToken()
    const headers: Record<string, string> = {}
    if (token) headers['Authorization'] = `Bearer ${token}`

    const response = await fetch(url.toString(), { headers })
    if (!response.ok) throw new Error(`Report generation failed: ${response.status}`)

    const blob = await response.blob()
    const downloadUrl = window.URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = downloadUrl
    a.download = response.headers.get('Content-Disposition')?.split('filename=')[1]?.replace(/"/g, '') || `ARCA_${type}_report.pdf`
    document.body.appendChild(a)
    a.click()
    a.remove()
    window.URL.revokeObjectURL(downloadUrl)
  }

  async exportFindings(format: 'csv' | 'json', params?: Record<string, string>) {
    const url = new URL('/api/v1/reports/export/findings', window.location.origin)
    url.searchParams.set('format', format)
    if (params) {
      Object.entries(params).forEach(([key, val]) => {
        if (val) url.searchParams.set(key, val)
      })
    }
    const token = this.getToken()
    const headers: Record<string, string> = {}
    if (token) headers['Authorization'] = `Bearer ${token}`

    const response = await fetch(url.toString(), { headers })
    if (!response.ok) throw new Error(`Export failed: ${response.status}`)

    const blob = await response.blob()
    const downloadUrl = window.URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = downloadUrl
    const ext = format === 'json' ? 'json' : 'csv'
    a.download = `ARCA_Findings.${ext}`
    document.body.appendChild(a)
    a.click()
    a.remove()
    window.URL.revokeObjectURL(downloadUrl)
  }

  // Schedules
  async getSchedules() {
    return this.request<any[]>('GET', '/api/v1/schedules')
  }

  async createSchedule(data: any) {
    return this.request<any>('POST', '/api/v1/schedules', data)
  }

  async updateSchedule(id: string, data: any) {
    return this.request<any>('PUT', `/api/v1/schedules/${id}`, data)
  }

  async deleteSchedule(id: string) {
    return this.request<void>('DELETE', `/api/v1/schedules/${id}`)
  }

  // Notifications
  async getNotifications(unreadOnly?: boolean) {
    const params = unreadOnly ? { unread_only: 'true' } : undefined
    return this.request<any[]>('GET', '/api/v1/notifications', undefined, { params })
  }

  async getNotificationCount() {
    return this.request<{ unread_count: number }>('GET', '/api/v1/notifications/count')
  }

  async markNotificationRead(id: string) {
    return this.request<any>('PUT', `/api/v1/notifications/${id}/read`)
  }

  async markAllNotificationsRead() {
    return this.request<any>('PUT', '/api/v1/notifications/read-all')
  }

  // Integrations
  async getIntegrations() {
    return this.request<any[]>('GET', '/api/v1/integrations')
  }

  async createIntegration(data: any) {
    return this.request<any>('POST', '/api/v1/integrations', data)
  }

  async updateIntegration(id: string, data: any) {
    return this.request<any>('PUT', `/api/v1/integrations/${id}`, data)
  }

  async deleteIntegration(id: string) {
    return this.request<void>('DELETE', `/api/v1/integrations/${id}`)
  }

  async testIntegration(id: string) {
    return this.request<{ success: boolean; message: string }>('POST', `/api/v1/integrations/${id}/test`)
  }

  // Inventory
  async getInventoryResources(params?: Record<string, string>) {
    return this.request<any[]>('GET', '/api/v1/inventory/resources', undefined, { params })
  }

  async getInventorySummary(params?: Record<string, string>) {
    return this.request<any>('GET', '/api/v1/inventory/summary', undefined, { params })
  }
}

export const api = new ApiClient()
