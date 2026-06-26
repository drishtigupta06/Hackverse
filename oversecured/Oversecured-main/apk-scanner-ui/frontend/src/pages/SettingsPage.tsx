import { useState, useEffect } from 'react'
import { getSettings, updateSettings, type Settings } from '../api/settings'
import { api } from '../api/client'
import { useToastStore } from '../store/useToastStore'
import { Save, Wifi, FlaskConical, Cpu, Loader, Smartphone } from 'lucide-react'

const DEFAULT_SETTINGS: Settings = {
  scannerPath: '/scanner/scanner.py',
  jadxPath: 'jadx',
  adbPath: 'adb',
  fridaPath: 'frida',
  fridaServerPath: '/opt/frida-server-x86_64',
  emulatorPath: 'emulator',
  ollamaUrl: 'http://ollama:11434',
  defaultScanMode: 'standard',
  defaultFridaTimeout: 30,
}

export function SettingsPage() {
  const [settings, setSettings] = useState<Settings>(DEFAULT_SETTINGS)
  const [originalSettings, setOriginalSettings] = useState<Settings>(DEFAULT_SETTINGS)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [testResults, setTestResults] = useState<Record<string, string>>({})
  const addToast = useToastStore((s) => s.addToast)

  useEffect(() => {
    getSettings()
      .then((data) => {
        setSettings({ ...DEFAULT_SETTINGS, ...data })
        setOriginalSettings({ ...DEFAULT_SETTINGS, ...data })
      })
      .catch(() => addToast('error', 'Failed to load settings'))
      .finally(() => setLoading(false))
  }, [])

  const testConnection = async (key: string, endpoint: string) => {
    setTestResults((r) => ({ ...r, [key]: 'testing...' }))
    try {
      const { data } = await api.get(endpoint)
      const ok = data.status === 'connected' || data.status === 'available'
      setTestResults((r) => ({ ...r, [key]: ok ? 'Connected' : data.status || 'Unknown' }))
      if (!ok) addToast('warning', `${key}: ${data.status}`)
    } catch {
      setTestResults((r) => ({ ...r, [key]: 'Failed' }))
      addToast('error', `${key} connection failed`)
    }
  }

  const handleSave = async () => {
    setSaving(true)
    try {
      await updateSettings(settings)
      setOriginalSettings({ ...settings })
      addToast('success', 'Settings saved')
    } catch {
      addToast('error', 'Failed to save settings')
    } finally {
      setSaving(false)
    }
  }

  const hasChanges = JSON.stringify(settings) !== JSON.stringify(originalSettings)

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader className="w-6 h-6 animate-spin text-text-secondary" />
      </div>
    )
  }

  return (
    <div className="max-w-[600px] mx-auto space-y-6">
      <h1 className="text-lg font-medium">Settings</h1>

      <div className="card p-6 space-y-4">
        <h2 className="text-sm font-medium">Paths</h2>
        <div className="space-y-3">
          <div>
            <label className="text-xs text-text-secondary">Scanner engine path</label>
            <input className="w-full mt-1 text-sm" value={settings.scannerPath} onChange={(e) => setSettings((s) => ({ ...s, scannerPath: e.target.value }))} />
          </div>
          <div>
            <label className="text-xs text-text-secondary">JADX path</label>
            <input className="w-full mt-1 text-sm" value={settings.jadxPath} onChange={(e) => setSettings((s) => ({ ...s, jadxPath: e.target.value }))} />
          </div>
          <div>
            <label className="text-xs text-text-secondary">ADB path</label>
            <input className="w-full mt-1 text-sm" value={settings.adbPath} onChange={(e) => setSettings((s) => ({ ...s, adbPath: e.target.value }))} />
          </div>
          <div>
            <label className="text-xs text-text-secondary">Frida path</label>
            <input className="w-full mt-1 text-sm" value={settings.fridaPath} onChange={(e) => setSettings((s) => ({ ...s, fridaPath: e.target.value }))} />
          </div>
          <div>
            <label className="text-xs text-text-secondary">Frida server path (Android binary)</label>
            <input className="w-full mt-1 text-sm" value={settings.fridaServerPath} onChange={(e) => setSettings((s) => ({ ...s, fridaServerPath: e.target.value }))} />
          </div>
          <div>
            <label className="text-xs text-text-secondary">Emulator path</label>
            <input className="w-full mt-1 text-sm" value={settings.emulatorPath} onChange={(e) => setSettings((s) => ({ ...s, emulatorPath: e.target.value }))} />
          </div>
          <div>
            <label className="text-xs text-text-secondary">Ollama URL</label>
            <input className="w-full mt-1 text-sm" value={settings.ollamaUrl} onChange={(e) => setSettings((s) => ({ ...s, ollamaUrl: e.target.value }))} />
          </div>
        </div>
      </div>

      <div className="card p-6 space-y-4">
        <h2 className="text-sm font-medium">Defaults</h2>
        <div className="space-y-3">
          <div>
            <label className="text-xs text-text-secondary">Default scan mode</label>
            <select className="w-full mt-1 text-sm" value={settings.defaultScanMode} onChange={(e) => setSettings((s) => ({ ...s, defaultScanMode: e.target.value }))}>
              <option value="fast">Fast</option>
              <option value="standard">Standard</option>
              <option value="thorough">Thorough</option>
              <option value="bb">Bug Bounty</option>
            </select>
          </div>
          <div>
            <label className="text-xs text-text-secondary">Default Frida timeout (seconds)</label>
            <input type="number" className="w-full mt-1 text-sm" value={settings.defaultFridaTimeout} onChange={(e) => setSettings((s) => ({ ...s, defaultFridaTimeout: parseInt(e.target.value) || 30 }))} />
          </div>
        </div>
      </div>

      <div className="card p-6 space-y-4">
        <h2 className="text-sm font-medium">Connection Tests</h2>
        <div className="space-y-2">
          <TestRow icon={Wifi} label="ADB" result={testResults.adb} onTest={() => testConnection('adb', '/api/v1/health/adb')} />
          <TestRow icon={FlaskConical} label="Frida" result={testResults.frida} onTest={() => testConnection('frida', '/api/v1/health/frida')} />
          <TestRow icon={Smartphone} label="Frida Server" result={testResults.fridaServer} onTest={() => testConnection('frida-server', '/api/v1/health/frida-server')} />
          <TestRow icon={Cpu} label="Ollama" result={testResults.ollama} onTest={() => testConnection('ollama', '/api/v1/health/ollama')} />
        </div>
      </div>

      <button
        onClick={handleSave}
        disabled={saving || !hasChanges}
        className="btn-primary flex items-center gap-2 text-sm disabled:opacity-50"
      >
        <Save className="w-4 h-4" />
        {saving ? 'Saving...' : hasChanges ? 'Save Settings' : 'Saved'}
      </button>
    </div>
  )
}

function TestRow({
  icon: Icon,
  label,
  result,
  onTest,
}: {
  icon: React.ComponentType<{ className?: string }>
  label: string
  result?: string
  onTest: () => void
}) {
  return (
    <div className="flex items-center justify-between py-2">
      <div className="flex items-center gap-2">
        <Icon className="w-4 h-4 text-text-secondary" />
        <span className="text-sm text-text-primary">{label}</span>
        {result && (
          <span className={`text-xs ${
            result === 'Connected' || result === 'Available' ? 'text-green-400' :
            result === 'testing...' ? 'text-yellow-400' : 'text-red-400'
          }`}>{result}</span>
        )}
      </div>
      <button onClick={onTest} className="btn-secondary text-xs">Test</button>
    </div>
  )
}
