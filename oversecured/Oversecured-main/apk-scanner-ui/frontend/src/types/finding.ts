export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'

export interface Finding {
  id: string
  scan_id: string
  app_id: string
  rule_id: string
  rule_group?: string
  title: string
  description?: string
  severity: Severity
  original_sev?: string
  category?: string
  source?: string
  confidence?: number
  validated: boolean
  poc_command?: string
  poc_vector?: string
  impact?: string
  recommendation?: string
  location?: string
  escalation_rule?: string
  sectors?: string[]
  raw_data?: Record<string, unknown>
  created_at?: string
}

export interface FindingSummary {
  total: number
  by_severity: Record<string, number>
  by_source: Record<string, number>
  by_rule_group: Record<string, number>
}

export interface FindingListResponse {
  findings: Finding[]
  total: number
}
