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

  async getAccountDashboard(providerId: string) {
    return this.request<any>('GET', `/api/v1/dashboard/account/${providerId}`)
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

  async createFindingException(findingId: string, reason: string, evidence?: File) {
    const formData = new FormData()
    formData.append('reason', reason)
    if (evidence) formData.append('evidence', evidence)

    const token = this.getToken()
    const headers: Record<string, string> = {}
    if (token) headers['Authorization'] = `Bearer ${token}`

    const response = await fetch(`/api/v1/findings/${findingId}/exception`, {
      method: 'POST',
      headers,
      body: formData,
    })
    if (!response.ok) {
      const error = await response.json().catch(() => ({}))
      throw new Error(error.detail || `Request failed: ${response.status}`)
    }
    return response.json()
  }

  async markFindingRemediated(findingId: string, reason: string, evidence?: File) {
    const formData = new FormData()
    formData.append('reason', reason)
    if (evidence) formData.append('evidence', evidence)

    const token = this.getToken()
    const headers: Record<string, string> = {}
    if (token) headers['Authorization'] = `Bearer ${token}`

    const response = await fetch(`/api/v1/findings/${findingId}/remediate`, {
      method: 'POST',
      headers,
      body: formData,
    })
    if (!response.ok) {
      const error = await response.json().catch(() => ({}))
      throw new Error(error.detail || `Request failed: ${response.status}`)
    }
    return response.json()
  }

  async getFindingActions(findingId: string) {
    return this.request<any[]>('GET', `/api/v1/findings/${findingId}/actions`)
  }

  // Compliance
  async getComplianceAccounts() {
    return this.request<any[]>('GET', '/api/v1/compliance/accounts')
  }

  async getComplianceFrameworks(providerType?: string) {
    const params = providerType ? { provider_type: providerType } : undefined
    return this.request<any[]>('GET', '/api/v1/compliance/frameworks', undefined, { params })
  }

  async getComplianceSummary(framework?: string, providerId?: string, providerType?: string) {
    const params: Record<string, string> = {}
    if (framework) params.framework = framework
    if (providerId) params.provider_id = providerId
    if (providerType) params.provider_type = providerType
    return this.request<any>('GET', '/api/v1/compliance/summary', undefined, { params: Object.keys(params).length ? params : undefined })
  }

  async getFrameworkPreferences() {
    return this.request<Record<string, boolean>>('GET', '/api/v1/compliance/framework-preferences')
  }

  async updateFrameworkPreferences(preferences: Record<string, boolean>) {
    return this.request<any>('PUT', '/api/v1/compliance/framework-preferences', { preferences })
  }

  async getComplianceFrameworkChecks(frameworkId: string, params?: Record<string, string>) {
    return this.request<any>('GET', `/api/v1/compliance/frameworks/${frameworkId}/checks`, undefined, { params })
  }

  async getComplianceFrameworkStats(frameworkId: string) {
    return this.request<any>('GET', `/api/v1/compliance/frameworks/${frameworkId}/stats`)
  }

  async getComplianceFrameworkLibrary(frameworkId: string, providerType?: string) {
    const params = providerType ? { provider_type: providerType } : undefined
    return this.request<any>('GET', `/api/v1/compliance/frameworks/${frameworkId}/library`, undefined, { params })
  }

  async getComplianceFrameworkControls(frameworkId: string, providerId?: string, providerType?: string) {
    const params: Record<string, string> = {}
    if (providerId) params.provider_id = providerId
    if (providerType) params.provider_type = providerType
    return this.request<any>('GET', `/api/v1/compliance/frameworks/${frameworkId}/controls`, undefined, { params: Object.keys(params).length ? params : undefined })
  }

  async updateProvider(id: string, data: any) {
    return this.request<any>('PUT', `/api/v1/providers/${id}`, data)
  }

  async discoverAccounts(providerId: string) {
    return this.request<any[]>('POST', `/api/v1/providers/${providerId}/discover-accounts`)
  }

  async getChildAccounts(providerId: string) {
    return this.request<any[]>('GET', `/api/v1/providers/${providerId}/accounts`)
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

  async getAttackPathRuns(limit?: number) {
    const params = limit ? { limit: String(limit) } : undefined
    return this.request<any[]>('GET', '/api/v1/attack-paths/runs', undefined, { params })
  }

  async getAttackPathChokePoints(runId?: string) {
    const params = runId ? { analysis_run_id: runId } : undefined
    return this.request<any>('GET', '/api/v1/attack-paths/choke-points', undefined, { params })
  }

  async compareAttackPathRuns(run1: string, run2: string) {
    return this.request<any>('GET', '/api/v1/attack-paths/compare', undefined, { params: { run1, run2 } })
  }

  // MITRE ATT&CK (extended)
  async getMitreCoverageGaps(params?: Record<string, string>) {
    return this.request<any>('GET', '/api/v1/mitre/coverage-gaps', undefined, { params })
  }

  async getMitreNavigatorLayer(params?: Record<string, string>) {
    return this.request<any>('GET', '/api/v1/mitre/navigator-layer', undefined, { params })
  }

  async getMitreTechniqueChecks(techniqueId: string) {
    return this.request<any>('GET', `/api/v1/mitre/technique/${techniqueId}/checks`)
  }

  async getMitreAttackPathsCoverage() {
    return this.request<any>('GET', '/api/v1/mitre/attack-paths')
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

  async downloadRRReport() {
    const url = new URL('/api/v1/reports/ransomware-readiness', window.location.origin)
    const token = this.getToken()
    const headers: Record<string, string> = {}
    if (token) headers['Authorization'] = `Bearer ${token}`

    const response = await fetch(url.toString(), { headers })
    if (!response.ok) throw new Error(`Report generation failed: ${response.status}`)

    const blob = await response.blob()
    const downloadUrl = window.URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = downloadUrl
    a.download = response.headers.get('Content-Disposition')?.split('filename=')[1]?.replace(/"/g, '') || 'ARCA_Ransomware_Readiness_Report.pdf'
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

  async getInventorySummaryByAccount() {
    return this.request<any[]>('GET', '/api/v1/inventory/summary/by-account')
  }

  async getResourceFindings(resourceId: string) {
    return this.request<any[]>('GET', '/api/v1/inventory/resources/findings', undefined, {
      params: { resource_id: resourceId },
    })
  }

  // DSPM
  async getDSPMOverview() {
    return this.request<any>('GET', '/api/v1/dspm/overview')
  }

  async getDSPMChecks(providerType?: string) {
    const params = providerType ? { provider_type: providerType } : undefined
    return this.request<any[]>('GET', '/api/v1/dspm/checks', undefined, { params })
  }

  async getDSPMDataStores(providerType?: string) {
    const params = providerType ? { provider_type: providerType } : undefined
    return this.request<any[]>('GET', '/api/v1/dspm/data-stores', undefined, { params })
  }

  async getDSPMPIIPatterns() {
    return this.request<any>('GET', '/api/v1/dspm/pii-patterns')
  }

  async getDSPMClassificationLevels() {
    return this.request<any>('GET', '/api/v1/dspm/classification-levels')
  }

  async getDSPMScanCapabilities() {
    return this.request<any>('GET', '/api/v1/dspm/scan-capabilities')
  }

  async getDSPMFindings(params?: Record<string, string>) {
    return this.request<any>('GET', '/api/v1/dspm/findings', undefined, { params })
  }

  async getDSPMAttackPaths() {
    return this.request<any>('GET', '/api/v1/dspm/attack-paths')
  }

  // Security Graph
  async getSecurityGraph(params?: Record<string, string>) {
    return this.request<any>('GET', '/api/v1/security-graph/graph', undefined, { params })
  }

  async getSecurityGraphStats() {
    return this.request<any>('GET', '/api/v1/security-graph/stats')
  }

  async getSecurityGraphNodeDetail(nodeId: string) {
    return this.request<any>('GET', `/api/v1/security-graph/nodes/${encodeURIComponent(nodeId)}`)
  }

  async getSecurityGraphBlastRadius(nodeId: string, maxDepth?: number) {
    const params: Record<string, string> = {}
    if (maxDepth) params.max_depth = String(maxDepth)
    return this.request<any>('GET', `/api/v1/security-graph/blast-radius/${encodeURIComponent(nodeId)}`, undefined, { params })
  }

  async getSecurityGraphPaths(source: string, target: string) {
    return this.request<any>('GET', '/api/v1/security-graph/paths', undefined, {
      params: { source, target },
    })
  }

  async searchSecurityGraphNodes(query: string) {
    return this.request<any>('GET', '/api/v1/security-graph/search', undefined, {
      params: { q: query },
    })
  }

  // MITRE ATT&CK
  async getMitreMatrix(params?: Record<string, string>) {
    return this.request<any>('GET', '/api/v1/mitre/matrix', undefined, { params })
  }

  async getMitreTechnique(techniqueId: string, params?: Record<string, string>) {
    return this.request<any>('GET', `/api/v1/mitre/technique/${techniqueId}`, undefined, { params })
  }

  // Organizations
  async createOrganization(data: { name: string; slug: string }) {
    return this.request<any>('POST', '/api/v1/organizations', data)
  }

  async getCurrentOrganization() {
    return this.request<any>('GET', '/api/v1/organizations/current')
  }

  async updateOrganization(data: any) {
    return this.request<any>('PUT', '/api/v1/organizations/current', data)
  }

  async getOrganizationMembers() {
    return this.request<any[]>('GET', '/api/v1/organizations/current/members')
  }

  async inviteMember(email: string, role?: string) {
    return this.request<any>('POST', '/api/v1/organizations/current/members/invite', { email, role })
  }

  async removeMember(userId: string) {
    return this.request<void>('DELETE', `/api/v1/organizations/current/members/${userId}`)
  }

  async updateMemberRole(userId: string, role: string) {
    return this.request<any>('PUT', `/api/v1/organizations/current/members/${userId}/role`, { role })
  }

  // Ransomware Readiness
  async getRRScore(accountId?: string) {
    const params = accountId ? { account_id: accountId } : undefined
    return this.request<any>('GET', '/api/v1/ransomware-readiness/score', undefined, { params })
  }

  async getRRScoreHistory(days?: number, scope?: string, scopeId?: string) {
    const params: Record<string, string> = {}
    if (days) params.days = String(days)
    if (scope) params.scope = scope
    if (scopeId) params.scope_id = scopeId
    return this.request<any[]>('GET', '/api/v1/ransomware-readiness/score/history', undefined, { params: Object.keys(params).length ? params : undefined })
  }

  async getRRDomains() {
    return this.request<any[]>('GET', '/api/v1/ransomware-readiness/domains')
  }

  async getRRDomainRules(domainId: string) {
    return this.request<any[]>('GET', `/api/v1/ransomware-readiness/domains/${domainId}/rules`)
  }

  async getRRFindings(params?: Record<string, string>) {
    return this.request<any>('GET', '/api/v1/ransomware-readiness/findings', undefined, { params })
  }

  async getRRFindingDetail(findingId: string) {
    return this.request<any>('GET', `/api/v1/ransomware-readiness/findings/${findingId}`)
  }

  async updateRRFinding(findingId: string, data: any) {
    return this.request<any>('PATCH', `/api/v1/ransomware-readiness/findings/${findingId}`, data)
  }

  async getRRAccounts() {
    return this.request<any[]>('GET', '/api/v1/ransomware-readiness/accounts')
  }

  async getRRAccountDetail(accountId: string) {
    return this.request<any>('GET', `/api/v1/ransomware-readiness/accounts/${accountId}`)
  }

  async getRRRules(params?: Record<string, string>) {
    return this.request<any[]>('GET', '/api/v1/ransomware-readiness/rules', undefined, { params })
  }

  async getRRGovernance() {
    return this.request<any>('GET', '/api/v1/ransomware-readiness/governance')
  }

  async updateRRGovernance(data: any) {
    return this.request<any>('PUT', '/api/v1/ransomware-readiness/governance', data)
  }

  async triggerRREvaluation() {
    return this.request<any>('POST', '/api/v1/ransomware-readiness/evaluate')
  }

  // Audit Log
  async getAuditLogs(params?: Record<string, string>) {
    return this.request<any[]>('GET', '/api/v1/audit-log', undefined, { params })
  }

  async getAuditLogStats(days?: number) {
    const params = days ? { days: String(days) } : undefined
    return this.request<any>('GET', '/api/v1/audit-log/stats', undefined, { params })
  }

  // Custom Frameworks
  async getCustomFrameworks() {
    return this.request<any[]>('GET', '/api/v1/custom-frameworks')
  }

  async createCustomFramework(data: { name: string; description?: string; version?: string; providers: string[]; selected_check_ids?: string[] }) {
    return this.request<any>('POST', '/api/v1/custom-frameworks', data)
  }

  async getCustomFramework(id: string) {
    return this.request<any>('GET', `/api/v1/custom-frameworks/${id}`)
  }

  async getCustomFrameworkEvaluation(fwId: string) {
    return this.request<any>('GET', `/api/v1/custom-frameworks/${fwId}/evaluation`)
  }

  async updateCustomFramework(id: string, data: any) {
    return this.request<any>('PUT', `/api/v1/custom-frameworks/${id}`, data)
  }

  async deleteCustomFramework(id: string) {
    return this.request<void>('DELETE', `/api/v1/custom-frameworks/${id}`)
  }

  async cloneCustomFramework(id: string) {
    return this.request<any>('POST', `/api/v1/custom-frameworks/${id}/clone`)
  }

  async getAvailableChecks(params?: Record<string, string>) {
    return this.request<any>('GET', '/api/v1/custom-frameworks/available-checks', undefined, { params })
  }

  async getRegistryStats() {
    return this.request<any>('GET', '/api/v1/custom-frameworks/registry-stats')
  }

  async addChecksToFramework(fwId: string, checkIds: string[]) {
    return this.request<any>('POST', `/api/v1/custom-frameworks/${fwId}/checks`, { registry_check_ids: checkIds })
  }

  async removeCheckFromFramework(fwId: string, checkRecordId: string) {
    return this.request<void>('DELETE', `/api/v1/custom-frameworks/${fwId}/checks/${checkRecordId}`)
  }

  async createCustomControl(fwId: string, data: any) {
    return this.request<any>('POST', `/api/v1/custom-frameworks/${fwId}/controls`, data)
  }

  async updateCustomControl(fwId: string, ctrlId: string, data: any) {
    return this.request<any>('PUT', `/api/v1/custom-frameworks/${fwId}/controls/${ctrlId}`, data)
  }

  async deleteCustomControl(fwId: string, ctrlId: string) {
    return this.request<void>('DELETE', `/api/v1/custom-frameworks/${fwId}/controls/${ctrlId}`)
  }

  async downloadFrameworkTemplate(fwId: string) {
    const url = new URL(`/api/v1/custom-frameworks/${fwId}/template.xlsx`, window.location.origin)
    const token = this.getToken()
    const headers: Record<string, string> = {}
    if (token) headers['Authorization'] = `Bearer ${token}`
    const response = await fetch(url.toString(), { headers })
    if (!response.ok) throw new Error(`Template download failed: ${response.status}`)
    const blob = await response.blob()
    const downloadUrl = window.URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = downloadUrl
    a.download = 'custom_controls_template.xlsx'
    document.body.appendChild(a)
    a.click()
    a.remove()
    window.URL.revokeObjectURL(downloadUrl)
  }

  async importExcelPreview(fwId: string, file: File) {
    const formData = new FormData()
    formData.append('file', file)
    const token = this.getToken()
    const headers: Record<string, string> = {}
    if (token) headers['Authorization'] = `Bearer ${token}`
    const response = await fetch(`/api/v1/custom-frameworks/${fwId}/import-excel`, {
      method: 'POST',
      headers,
      body: formData,
    })
    if (!response.ok) {
      const error = await response.json().catch(() => ({}))
      throw new Error(error.detail || `Import failed: ${response.status}`)
    }
    return response.json()
  }

  async importExcelConfirm(fwId: string, controls: any[]) {
    return this.request<any>('POST', `/api/v1/custom-frameworks/${fwId}/import-confirm`, { controls })
  }

  // API Keys
  async getApiKeys() {
    return this.request<any[]>('GET', '/api/v1/auth/api-keys')
  }

  async createApiKey(name: string) {
    return this.request<any>('POST', '/api/v1/auth/api-keys', { name })
  }

  async deleteApiKey(id: string) {
    return this.request<void>('DELETE', `/api/v1/auth/api-keys/${id}`)
  }
}

export const api = new ApiClient()
