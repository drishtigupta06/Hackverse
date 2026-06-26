import { api } from './client'
import type { Scan, ScanListResponse } from '../types/scan'
import type { ScanConfig } from '../types/config'

export async function createScan(config: ScanConfig): Promise<Scan> {
  const { data } = await api.post<Scan>('/scans', config)
  return data
}

export async function listScans(params?: {
  app_id?: string
  status?: string
  limit?: number
  offset?: number
}): Promise<ScanListResponse> {
  const { data } = await api.get<ScanListResponse>('/scans', { params })
  return data
}

export async function getScan(id: string): Promise<Scan> {
  const { data } = await api.get<Scan>(`/scans/${id}`)
  return data
}

export async function deleteScan(id: string): Promise<void> {
  await api.delete(`/scans/${id}`)
}

export async function cancelScan(id: string): Promise<void> {
  await api.patch(`/scans/${id}/cancel`)
}
