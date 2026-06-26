import { useState, useEffect, useRef, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { Upload, Zap, Target, Microscope, Bug, Cpu, Shield, Database, Eye, Filter, FlaskConical, Smartphone, FileDown, CloudUpload, X, Check, ChevronRight, ChevronDown, Link as LinkIcon } from 'lucide-react'
import { uploadApk, listApps } from '../api/apps'
import { createScan } from '../api/scans'
import type { AppInfo, ScanConfig } from '../types/config'

const initialConfig: ScanConfig = {
  app_id: '',
  scan_mode: 'standard',
  fp_filter: 'basic',
  min_confidence: 'low',
  skip_jadx: false,
  skip_phase2: false,
  ai_triage: false,
  ai_model: 'llama2',
  ai_confidence: 'Medium',
  cve_update: false,
  cve_days: 30,
  taint: false,
  component_graph: false,
  chains: false,
  root_cause: false,
  dedup: true,
  confidence: true,
  coverage_audit: false,
  frida_enabled: false,
  frida_mode: 'spawn',
  frida_all: false,
  frida_ssl: false,
  frida_root: false,
  frida_hooks: false,
  frida_api: false,
  frida_prefs: false,
  frida_timeout: 30,
  exploit: false,
  exploit_validate: false,
  exploit_vector: 'adb',
  exploit_pkg: 'com.attacker',
  emulator_enabled: false,
  emulator_avd: 'Pixel_6_API_33',
  emulator_ram: 2048,
  no_emulator_cleanup: false,
  screenrecord: false,
  screenrecord_duration: 60,
  screenrecord_bitrate: 4000000,
  emulator_test: false,
  fp_measure: false,
  fp_report: false,
  fp_threshold: 0.30,
  sarif: true,
  history_save: true,
}

function calcEstimate(config: ScanConfig): string {
  let minutes = 0
  switch (config.scan_mode) {
    case 'fast': minutes = 1; break
    case 'standard': minutes = 4; break
    case 'thorough': minutes = 12; break
    case 'bb': minutes = 25; break
  }
  if (config.frida_enabled) minutes += 2
  if (config.emulator_enabled) minutes += 5
  if (config.ai_triage) minutes += 3
  if (config.taint) minutes += 2
  if (config.exploit) minutes += 2
  return `~${minutes} min`
}

export function NewScanPage() {
  const navigate = useNavigate()
  const [step, setStep] = useState(1)
  const [config, setConfig] = useState<ScanConfig>({ ...initialConfig })
  const [apps, setApps] = useState<AppInfo[]>([])
  const [uploading, setUploading] = useState(false)
  const [uploadProgress, setUploadProgress] = useState(0)
  const [uploadedApp, setUploadedApp] = useState<AppInfo | null>(null)
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({
    exploit: false,
    frida: false,
    emulator: false,
  })
  const [submitting, setSubmitting] = useState(false)

  useEffect(() => {
    listApps().then((res) => setApps(res.apps)).catch(() => {})
  }, [])

  const intervalRef = useRef<number>()

  const handleFileUpload = useCallback(async (file: File) => {
    if (!file.name.endsWith('.apk')) return
    setUploading(true)
    setUploadProgress(0)
    intervalRef.current = window.setInterval(() => setUploadProgress((p) => Math.min(p + 10, 90)), 500)
    try {
      const app = await uploadApk(file)
      clearInterval(intervalRef.current)
      setUploadProgress(100)
      setUploadedApp(app)
      setConfig((c) => ({ ...c, app_id: app.id }))
    } catch (e) {
      clearInterval(intervalRef.current)
      setUploadProgress(0)
      console.error('Upload failed', e)
    } finally {
      setUploading(false)
    }
  }, [])

  useEffect(() => {
    return () => clearInterval(intervalRef.current)
  }, [])

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    const file = e.dataTransfer.files[0]
    if (file) handleFileUpload(file)
  }, [handleFileUpload])

  const update = <K extends keyof ScanConfig>(key: K, value: ScanConfig[K]) =>
    setConfig((c) => ({ ...c, [key]: value }))

  const handleSubmit = async () => {
    if (!config.app_id) return
    setSubmitting(true)
    try {
      const scan = await createScan(config)
      navigate(`/scans/${scan.id}`)
    } catch (e) {
      console.error('Failed to create scan', e)
      setSubmitting(false)
    }
  }

  const handleBrowseClick = () => {
    const input = document.createElement('input')
    input.type = 'file'
    input.accept = '.apk'
    input.onchange = (e) => {
      const file = (e.target as HTMLInputElement).files?.[0]
      if (file) handleFileUpload(file)
    }
    input.click()
  }

  return (
    <div className="max-w-[720px] mx-auto space-y-6 pb-24">
      <h1 className="text-lg font-medium">New Scan</h1>

      {/* Step 1: APK */}
      <div className="card p-6 space-y-4">
        <h2 className="text-sm font-medium flex items-center gap-2">
          <span className="w-6 h-6 rounded-full bg-accent text-white text-xs flex items-center justify-center">1</span>
          APK Selection
        </h2>

        <div
          onDrop={handleDrop}
          onDragOver={(e) => e.preventDefault()}
          className="border-2 border-dashed border-border hover:border-accent/50 rounded-lg p-8 text-center cursor-pointer transition-colors"
          onClick={handleBrowseClick}
        >
          {uploading ? (
            <div className="space-y-3">
              <CloudUpload className="w-10 h-10 text-accent mx-auto animate-pulse" />
              <p className="text-sm text-text-secondary">Uploading...</p>
              <div className="w-full bg-surface-secondary rounded-full h-2 max-w-xs mx-auto">
                <div className="bg-accent h-2 rounded-full transition-all" style={{ width: `${uploadProgress}%` }} />
              </div>
            </div>
          ) : uploadedApp ? (
            <div className="space-y-2" onClick={(e) => e.stopPropagation()}>
              <Check className="w-10 h-10 text-green-400 mx-auto" />
              <p className="text-sm font-medium text-text-primary">{uploadedApp.filename}</p>
              <p className="text-xs text-text-secondary">{uploadedApp.package_name || 'Unknown package'}</p>
              {uploadedApp.size_bytes && (
                <p className="text-xs text-text-tertiary">{(uploadedApp.size_bytes / 1024 / 1024).toFixed(1)} MB</p>
              )}
              <button
                onClick={() => { setUploadedApp(null); update('app_id', '') }}
                className="text-xs text-accent hover:text-accent-hover mt-2"
              >
                Remove and select different
              </button>
            </div>
          ) : (
            <div className="space-y-2">
              <CloudUpload className="w-10 h-10 text-text-tertiary mx-auto" />
              <p className="text-sm text-text-secondary">Drop APK here or click to browse</p>
              <p className="text-xs text-text-tertiary">Max 500MB, .apk files only</p>
            </div>
          )}
        </div>

        {apps.length > 0 && !uploadedApp && (
          <div>
            <p className="text-xs text-text-secondary mb-2">Or select from previously uploaded:</p>
            <select
              className="w-full"
              value={config.app_id}
              onChange={(e) => {
                const app = apps.find((a) => a.id === e.target.value)
                if (app) { setUploadedApp(app); update('app_id', app.id) }
              }}
            >
              <option value="">Select an app...</option>
              {apps.map((app) => (
                <option key={app.id} value={app.id}>
                  {app.filename} ({app.package_name || 'unknown'})
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      {/* Step 2: Scan Mode */}
      <div className="card p-6 space-y-4">
        <h2 className="text-sm font-medium flex items-center gap-2">
          <span className="w-6 h-6 rounded-full bg-accent text-white text-xs flex items-center justify-center">2</span>
          Scan Mode
        </h2>

        <div className="grid grid-cols-4 gap-2">
          {([
            { id: 'fast', label: 'Fast', icon: Zap, desc: 'Manifest only, no JADX, ~30s' },
            { id: 'standard', icon: Target, label: 'Standard', desc: 'Manifest + source + escalation, ~3-5min' },
            { id: 'thorough', icon: Microscope, label: 'Thorough', desc: 'All modules + taint + chains, ~10-15min' },
            { id: 'bb', icon: Bug, label: 'Bug Bounty', desc: 'Full + PoC + validation + AI, ~20-30min' },
          ] as const).map((m) => (
            <button
              key={m.id}
              onClick={() => update('scan_mode', m.id)}
              className={`p-3 rounded-lg border text-left transition-colors ${
                config.scan_mode === m.id
                  ? 'border-accent bg-accent/10'
                  : 'border-border hover:border-border-hover bg-surface-secondary'
              }`}
            >
              <m.icon className={`w-5 h-5 mb-1 ${config.scan_mode === m.id ? 'text-accent' : 'text-text-secondary'}`} />
              <div className={`text-sm font-medium ${config.scan_mode === m.id ? 'text-accent' : 'text-text-primary'}`}>
                {m.label}
              </div>
              <div className="text-xs text-text-tertiary mt-1">{m.desc}</div>
            </button>
          ))}
        </div>
      </div>

      {/* Step 3: Analysis Modules */}
      <div className="card p-6 space-y-4">
        <h2 className="text-sm font-medium flex items-center gap-2">
          <span className="w-6 h-6 rounded-full bg-accent text-white text-xs flex items-center justify-center">3</span>
          Analysis Modules
        </h2>

        <div className="grid grid-cols-2 gap-3">
          <ModuleToggle icon={Cpu} label="AI Triage" desc="Ollama LLM exploitability scoring" checked={config.ai_triage} onChange={(v) => update('ai_triage', v)}>
            {config.ai_triage && (
              <div className="mt-2 space-y-2 pt-2 border-t border-border">
                <div>
                  <label className="text-xs text-text-secondary">Model name</label>
                  <input className="w-full mt-1 text-sm" value={config.ai_model} onChange={(e) => update('ai_model', e.target.value)} />
                </div>
                <div>
                  <label className="text-xs text-text-secondary">Min confidence</label>
                  <select className="w-full mt-1 text-sm" value={config.ai_confidence} onChange={(e) => update('ai_confidence', e.target.value as ScanConfig['ai_confidence'])}>
                    <option>Low</option><option>Medium</option><option>High</option>
                  </select>
                </div>
              </div>
            )}
          </ModuleToggle>

          <ModuleToggle icon={Database} label="Taint Analysis" desc="Inter-procedural data flow tracking" checked={config.taint} onChange={(v) => update('taint', v)} />
          <ModuleToggle icon={Eye} label="Component Graph" desc="Attack surface visualization" checked={config.component_graph} onChange={(v) => update('component_graph', v)} />
          <ModuleToggle icon={LinkIcon} label="Exploit Chains" desc="Multi-step attack path detection" checked={config.chains} onChange={(v) => update('chains', v)} />
          <ModuleToggle icon={Filter} label="Root Cause Dedup" desc="Deduplicate by root cause" checked={config.root_cause} onChange={(v) => update('root_cause', v)} />
          <ModuleToggle icon={Shield} label="Confidence Scoring" desc="Calibrated confidence per finding" checked={config.confidence} onChange={(v) => update('confidence', v)} />

          <ModuleToggle icon={Bug} label="CVE Analysis" desc="Match against NVD CVE database" checked={config.cve_update} onChange={(v) => update('cve_update', v)}>
            {config.cve_update && (
              <div className="mt-2 space-y-2 pt-2 border-t border-border">
                <div>
                  <label className="text-xs text-text-secondary">Days back</label>
                  <input type="number" className="w-full mt-1 text-sm" value={config.cve_days} onChange={(e) => update('cve_days', parseInt(e.target.value) || 30)} />
                </div>
                <div>
                  <label className="text-xs text-text-secondary">CVE search keywords</label>
                  <input className="w-full mt-1 text-sm" value={config.cve_search || ''} onChange={(e) => update('cve_search', e.target.value)} placeholder="e.g. WebView RCE" />
                </div>
                <div>
                  <label className="text-xs text-text-secondary">Specific CVE IDs (space separated)</label>
                  <input className="w-full mt-1 text-sm" value={config.cve_list || ''} onChange={(e) => update('cve_list', e.target.value)} placeholder="e.g. CVE-2025-XXXX CVE-2024-YYYY" />
                </div>
              </div>
            )}
          </ModuleToggle>

          <ModuleToggle icon={Filter} label="FP Filter" desc="Suppress common false positives" checked={config.fp_filter !== 'off'} onChange={(v) => update('fp_filter', v ? 'basic' : 'off')}>
            {config.fp_filter !== 'off' && (
              <div className="mt-2 space-y-2 pt-2 border-t border-border">
                <div>
                  <label className="text-xs text-text-secondary">Level</label>
                  <select className="w-full mt-1 text-sm" value={config.fp_filter} onChange={(e) => update('fp_filter', e.target.value as ScanConfig['fp_filter'])}>
                    <option value="basic">Basic</option>
                    <option value="aggressive">Aggressive</option>
                  </select>
                </div>
              </div>
            )}
          </ModuleToggle>
        </div>
      </div>

      {/* Step 4: Exploit */}
      <CollapsibleSection
        icon={Bug}
        label="Exploit Generation"
        open={expandedSections.exploit}
        onToggle={() => setExpandedSections((s) => ({ ...s, exploit: !s.exploit }))}
      >
        <ModuleToggle icon={Bug} label="Generate Exploits" desc="Create PoC exploits for findings" checked={config.exploit} onChange={(v) => update('exploit', v)}>
          {config.exploit && (
            <div className="mt-3 space-y-3 pt-3 border-t border-border">
              <Toggle label="Validate via device" checked={config.exploit_validate} onChange={(v) => update('exploit_validate', v)} />
              <div>
                <label className="text-xs text-text-secondary">Exploit vector</label>
                <div className="flex gap-3 mt-1">
                  {(['adb', 'drozer', 'frida'] as const).map((v) => (
                    <label key={v} className="flex items-center gap-1.5 text-sm text-text-secondary cursor-pointer">
                      <input type="radio" name="exploit_vector" checked={config.exploit_vector === v} onChange={() => update('exploit_vector', v)} className="accent-accent" />
                      {v.toUpperCase()}
                    </label>
                  ))}
                </div>
              </div>
              <div>
                <label className="text-xs text-text-secondary">Attacker package</label>
                <input className="w-full mt-1 text-sm" value={config.exploit_pkg} onChange={(e) => update('exploit_pkg', e.target.value)} />
              </div>
            </div>
          )}
        </ModuleToggle>
      </CollapsibleSection>

      {/* Step 5: Frida */}
      <CollapsibleSection
        icon={FlaskConical}
        label="Frida Dynamic Analysis"
        open={expandedSections.frida}
        onToggle={() => setExpandedSections((s) => ({ ...s, frida: !s.frida }))}
      >
        <ModuleToggle icon={FlaskConical} label="Enable Frida" desc="Dynamic instrumentation hooks" checked={config.frida_enabled} onChange={(v) => update('frida_enabled', v)}>
          {config.frida_enabled && (
            <div className="mt-3 space-y-3 pt-3 border-t border-border">
              <div className="flex gap-3">
                {(['spawn', 'attach'] as const).map((m) => (
                  <label key={m} className="flex items-center gap-1.5 text-sm text-text-secondary cursor-pointer">
                    <input type="radio" name="frida_mode" checked={config.frida_mode === m} onChange={() => update('frida_mode', m)} className="accent-accent" />
                    {m === 'spawn' ? 'Spawn app' : 'Attach to running'}
                  </label>
                ))}
              </div>
              <div>
                <label className="text-xs text-text-secondary">Package (auto-filled from APK)</label>
                <input className="w-full mt-1 text-sm" value={config.frida_package || ''} onChange={(e) => update('frida_package', e.target.value)} placeholder={uploadedApp?.package_name || ''} />
              </div>
              <div>
                <label className="text-xs text-text-secondary">Timeout per module (seconds)</label>
                <input type="number" className="w-full mt-1 text-sm" value={config.frida_timeout} onChange={(e) => update('frida_timeout', parseInt(e.target.value) || 30)} />
              </div>
              <div>
                <p className="text-xs text-text-secondary mb-2">Sub-modules:</p>
                <div className="grid grid-cols-2 gap-2">
                  <Toggle label="SSL Pinning Detection" checked={config.frida_ssl} onChange={(v) => update('frida_ssl', v)} />
                  <Toggle label="Root Detection Bypass" checked={config.frida_root} onChange={(v) => update('frida_root', v)} />
                  <Toggle label="Runtime Hooks" checked={config.frida_hooks} onChange={(v) => update('frida_hooks', v)} />
                  <Toggle label="API Monitor" checked={config.frida_api} onChange={(v) => update('frida_api', v)} />
                  <Toggle label="SharedPrefs Monitor" checked={config.frida_prefs} onChange={(v) => update('frida_prefs', v)} />
                  <Toggle label="Enable All" checked={config.frida_all} onChange={(v) => {
                    update('frida_all', v)
                    if (v) { update('frida_ssl', true); update('frida_root', true); update('frida_hooks', true); update('frida_api', true); update('frida_prefs', true) }
                  }} />
                </div>
              </div>
            </div>
          )}
        </ModuleToggle>
      </CollapsibleSection>

      {/* Step 6: Emulator */}
      <CollapsibleSection
        icon={Smartphone}
        label="Emulator"
        open={expandedSections.emulator}
        onToggle={() => setExpandedSections((s) => ({ ...s, emulator: !s.emulator }))}
      >
        <ModuleToggle icon={Smartphone} label="Enable Emulator" desc="Auto-launch Android emulator" checked={config.emulator_enabled} onChange={(v) => update('emulator_enabled', v)}>
          {config.emulator_enabled && (
            <div className="mt-3 space-y-3 pt-3 border-t border-border">
              <div>
                <label className="text-xs text-text-secondary">AVD Name</label>
                <input className="w-full mt-1 text-sm" value={config.emulator_avd} onChange={(e) => update('emulator_avd', e.target.value)} />
              </div>
              <div>
                <label className="text-xs text-text-secondary">RAM: {config.emulator_ram} MB</label>
                <input type="range" min={512} max={8192} step={256} className="w-full mt-1 accent-accent" value={config.emulator_ram} onChange={(e) => update('emulator_ram', parseInt(e.target.value))} />
              </div>
              <Toggle label="Keep emulator running after scan" checked={config.no_emulator_cleanup} onChange={(v) => update('no_emulator_cleanup', v)} />
              <Toggle label="Record screen" checked={config.screenrecord} onChange={(v) => update('screenrecord', v)}>
                {config.screenrecord && (
                  <div className="mt-2 space-y-2 pl-4">
                    <div>
                      <label className="text-xs text-text-secondary">Duration (seconds)</label>
                      <input type="number" className="w-full mt-1 text-sm" value={config.screenrecord_duration} onChange={(e) => update('screenrecord_duration', parseInt(e.target.value) || 60)} />
                    </div>
                  </div>
                )}
              </Toggle>
              <Toggle label="Run UI tests after scan" checked={config.emulator_test} onChange={(v) => update('emulator_test', v)} />
            </div>
          )}
        </ModuleToggle>
      </CollapsibleSection>

      {/* Step 7: Output */}
      <div className="card p-6 space-y-4">
        <h2 className="text-sm font-medium flex items-center gap-2">
          <span className="w-6 h-6 rounded-full bg-accent text-white text-xs flex items-center justify-center">7</span>
          Output Options
        </h2>
        <div className="space-y-3">
          <Toggle label="Save to scan history" checked={config.history_save} onChange={(v) => update('history_save', v)} />
          <Toggle label="Export SARIF" checked={config.sarif} onChange={(v) => update('sarif', v)} />
          <div>
            <label className="text-xs text-text-secondary">Min confidence to show</label>
              <select className="w-full mt-1 text-sm" value={config.min_confidence} onChange={(e) => update('min_confidence', e.target.value as ScanConfig['min_confidence'])}>
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
            </select>
          </div>
        </div>
      </div>

      {/* Footer */}
      <div className="fixed bottom-0 left-[200px] right-0 bg-surface-card border-t border-border px-6 py-3 flex items-center justify-between z-10">
        <span className="text-sm text-text-secondary">Estimated time: {calcEstimate(config)}</span>
        <div className="flex items-center gap-3">
          <button onClick={() => navigate('/')} className="btn-secondary text-sm">Cancel</button>
          <button
            onClick={handleSubmit}
            disabled={!config.app_id || submitting}
            className="btn-primary flex items-center gap-2 text-sm"
          >
            {submitting ? 'Starting...' : 'Start Scan'}
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  )
}

function ModuleToggle({
  icon: Icon,
  label,
  desc,
  checked,
  onChange,
  children,
}: {
  icon: React.ComponentType<{ className?: string }>
  label: string
  desc: string
  checked: boolean
  onChange: (v: boolean) => void
  children?: React.ReactNode
}) {
  return (
    <div className={`p-3 rounded-lg border transition-colors ${checked ? 'border-accent/50 bg-accent/5' : 'border-border bg-surface-secondary'}`}>
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-start gap-2.5">
          <Icon className={`w-4 h-4 mt-0.5 ${checked ? 'text-accent' : 'text-text-tertiary'}`} />
          <div>
            <div className={`text-sm font-medium ${checked ? 'text-accent' : 'text-text-primary'}`}>{label}</div>
            <div className="text-xs text-text-tertiary mt-0.5">{desc}</div>
          </div>
        </div>
        <button
          onClick={() => onChange(!checked)}
          className={`w-9 h-5 rounded-full transition-colors relative flex-shrink-0 ${
            checked ? 'bg-accent' : 'bg-border'
          }`}
        >
          <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-white transition-transform ${
            checked ? 'translate-x-[18px]' : 'translate-x-0.5'
          }`} />
        </button>
      </div>
      {checked && children}
    </div>
  )
}

function Toggle({
  label,
  checked,
  onChange,
  disabled,
  children,
}: {
  label: string
  checked: boolean
  onChange: (v: boolean) => void
  disabled?: boolean
  children?: React.ReactNode
}) {
  return (
    <div>
      <div className="flex items-center justify-between gap-2">
        <span className="text-sm text-text-secondary">{label}</span>
        <button
          disabled={disabled}
          onClick={() => onChange(!checked)}
          className={`w-8 h-4 rounded-full transition-colors relative flex-shrink-0 ${
            disabled ? 'opacity-50 cursor-not-allowed' : ''
          } ${checked ? 'bg-accent' : 'bg-border'}`}
        >
          <span className={`absolute top-0.5 w-3 h-3 rounded-full bg-white transition-transform ${
            checked ? 'translate-x-[16px]' : 'translate-x-0.5'
          }`} />
        </button>
      </div>
      {children}
    </div>
  )
}

function CollapsibleSection({
  icon: Icon,
  label,
  open,
  onToggle,
  children,
}: {
  icon: React.ComponentType<{ className?: string }>
  label: string
  open: boolean
  onToggle: () => void
  children: React.ReactNode
}) {
  return (
    <div className="card">
      <button
        onClick={onToggle}
        className="w-full px-6 py-4 flex items-center justify-between text-sm font-medium text-text-primary hover:bg-surface-secondary/50 transition-colors"
      >
        <span className="flex items-center gap-2">
          <Icon className="w-4 h-4 text-accent" />
          {label}
        </span>
        {open ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
      </button>
      {open && <div className="px-6 pb-4">{children}</div>}
    </div>
  )
}
