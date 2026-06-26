import { api } from './client'
import type { Finding, FindingSummary, FindingListResponse, Severity } from '../types/finding'

export async function listFindings(params?: {
  scan_id?: string
  app_id?: string
  severity?: string
  source?: string
  rule_id?: string
  validated?: boolean
  search?: string
  min_confidence?: number
  sort_by?: string
  order?: string
  limit?: number
  offset?: number
}): Promise<FindingListResponse> {
  const { data } = await api.get<FindingListResponse>('/findings', { params })
  return data
}

export async function getFinding(id: string): Promise<Finding> {
  const { data } = await api.get<Finding>(`/findings/${id}`)
  return data
}

export async function getFindingSummary(params?: {
  scan_id?: string
  app_id?: string
}): Promise<FindingSummary> {
  const { data } = await api.get<FindingSummary>('/findings/summary', { params })
  return data
}

export async function getChains(scan_id: string): Promise<{
  id: string
  scan_id: string
  title: string
  severity: Severity
  validated: boolean
  steps: Array<{ role: string; finding_id: string; label: string }>
  poc_sequence: string[]
  created_at?: string
}[]> {
  const { data } = await api.get('/findings/chains', { params: { scan_id } })
  return data
}
