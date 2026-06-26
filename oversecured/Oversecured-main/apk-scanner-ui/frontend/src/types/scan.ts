export interface Scan {
  id: string
  app_id: string
  status: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled'
  scan_mode: string
  config: Record<string, unknown>
  sector_detected?: string[]
  started_at?: string
  completed_at?: string
  duration_secs?: number
  html_report_path?: string
  sarif_path?: string
  error_message?: string
  created_at?: string
}

export interface ScanListResponse {
  scans: Scan[]
  total: number
}
