export interface AppInfo {
  id: string
  filename: string
  package_name?: string
  app_name?: string
  version_code?: string
  version_name?: string
  sha256?: string
  size_bytes?: number
  uploaded_at?: string
}

export interface AppListResponse {
  apps: AppInfo[]
  total: number
}

export interface ScanConfig {
  app_id: string
  scan_mode: 'fast' | 'standard' | 'thorough' | 'bb'
  fp_filter: 'off' | 'basic' | 'aggressive'
  min_confidence: 'low' | 'medium' | 'high'
  skip_jadx: boolean
  skip_phase2: boolean
  ai_triage: boolean
  ai_model: string
  ai_confidence: 'Low' | 'Medium' | 'High'
  cve_update: boolean
  cve_days: number
  cve_list?: string
  cve_search?: string
  frida_enabled: boolean
  frida_mode: 'attach' | 'spawn'
  frida_package?: string
  frida_device?: string
  frida_ssl: boolean
  frida_root: boolean
  frida_hooks: boolean
  frida_api: boolean
  frida_prefs: boolean
  frida_all: boolean
  frida_timeout: number
  exploit: boolean
  exploit_validate: boolean
  exploit_vector: 'adb' | 'drozer' | 'frida'
  exploit_pkg: string
  emulator_enabled: boolean
  emulator_avd: string
  emulator_ram: number
  no_emulator_cleanup: boolean
  screenrecord: boolean
  screenrecord_duration: number
  screenrecord_bitrate: number
  emulator_test: boolean
  taint: boolean
  component_graph: boolean
  chains: boolean
  root_cause: boolean
  dedup: boolean
  confidence: boolean
  coverage_audit: boolean
  fp_measure: boolean
  fp_report: boolean
  fp_threshold: number
  sarif: boolean
  history_save: boolean
}
