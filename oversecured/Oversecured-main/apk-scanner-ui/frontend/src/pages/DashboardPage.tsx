import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, Upload, AlertTriangle, Link, TrendingUp, TrendingDown } from 'lucide-react'
import { listScans } from '../api/scans'
import { getFindingSummary } from '../api/findings'
import { listApps } from '../api/apps'
import type { Scan } from '../types/scan'
import type { FindingSummary } from '../types/finding'
import type { AppInfo } from '../types/config'
import { KpiCard } from '../components/dashboard/KpiCard'
import { SeverityChart } from '../components/dashboard/SeverityChart'
import { TopFindingsCard } from '../components/dashboard/TopFindingsCard'

export function DashboardPage() {
  const navigate = useNavigate()
  const [scans, setScans] = useState<Scan[]>([])
  const [apps, setApps] = useState<AppInfo[]>([])
  const [summary, setSummary] = useState<FindingSummary | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const load = async () => {
      try {
        const [scanRes, appRes] = await Promise.all([listScans({ limit: 100 }), listApps()])
        setScans(scanRes.scans)
        setApps(appRes.apps)
        if (scanRes.scans.length > 0) {
          const s = await getFindingSummary()
          setSummary(s)
        }
      } catch (e) {
        console.error('Failed to load dashboard', e)
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [])

  const completedScans = scans.filter((s) => s.status === 'completed')
  const criticalCount = summary?.by_severity?.CRITICAL ?? 0
  const chainCount = completedScans.filter((s) => s.config?.chains).length

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin w-8 h-8 border-2 border-accent border-t-transparent rounded-full" />
      </div>
    )
  }

  if (scans.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-[60vh] gap-6">
        <Shield className="w-16 h-16 text-accent/40" />
        <h2 className="text-xl font-medium text-text-primary">No scans yet</h2>
        <p className="text-text-secondary text-sm">Upload an APK and start your first security scan</p>
        <button onClick={() => navigate('/scans/new')} className="btn-primary flex items-center gap-2">
          <Upload className="w-4 h-4" />
          Start your first scan
        </button>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <h1 className="text-lg font-medium">Dashboard</h1>

      <div className="grid grid-cols-5 gap-4">
        <KpiCard icon={Shield} label="Total Scans" value={scans.length} />
        <KpiCard icon={Upload} label="Total Apps" value={apps.length} />
        <KpiCard icon={AlertTriangle} label="Total Findings" value={summary?.total ?? 0} />
        <KpiCard
          icon={AlertTriangle}
          label="Critical"
          value={criticalCount}
          color="text-severity-critical-text"
        />
        <KpiCard icon={Link} label="Exploit Chains" value={chainCount} />
      </div>

      <div className="grid grid-cols-5 gap-4">
        <div className="col-span-3 card p-4">
          <h3 className="text-sm font-medium text-text-primary mb-3">Recent Scans</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-text-tertiary border-b border-border">
                  <th className="text-left py-2 font-medium">App</th>
                  <th className="text-left py-2 font-medium">Mode</th>
                  <th className="text-left py-2 font-medium">Status</th>
                  <th className="text-right py-2 font-medium">Findings</th>
                  <th className="text-right py-2 font-medium">Duration</th>
                  <th className="text-right py-2 font-medium"></th>
                </tr>
              </thead>
              <tbody>
                {scans.slice(0, 10).map((scan) => (
                  <tr
                    key={scan.id}
                    className="border-b border-border hover:bg-surface-secondary/50 cursor-pointer"
                    onClick={() => navigate(`/scans/${scan.id}`)}
                  >
                    <td className="py-2.5 text-text-primary">{scan.id.slice(0, 8)}...</td>
                    <td className="py-2.5">
                      <span className="badge bg-surface-secondary text-text-secondary border border-border">
                        {scan.scan_mode}
                      </span>
                    </td>
                    <td className="py-2.5">
                      <ScanStatusBadge status={scan.status} />
                    </td>
                    <td className="py-2.5 text-right text-text-secondary">{'-'}</td>
                    <td className="py-2.5 text-right text-text-secondary">
                      {scan.duration_secs ? `${scan.duration_secs}s` : '-'}
                    </td>
                    <td className="py-2.5 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation()
                          navigate(`/scans/${scan.id}`)
                        }}
                        className="text-accent hover:text-accent-hover text-xs"
                      >
                        View
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="col-span-2 space-y-4">
          <SeverityChart summary={summary} />
          <TopFindingsCard summary={summary} />
        </div>
      </div>
    </div>
  )
}

function ScanStatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    queued: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
    running: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
    completed: 'bg-green-500/20 text-green-400 border-green-500/30',
    failed: 'bg-red-500/20 text-red-400 border-red-500/30',
    cancelled: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  }
  return (
    <span className={`badge border ${colors[status] || colors.queued}`}>
      {status === 'running' && (
        <span className="inline-block w-1.5 h-1.5 rounded-full bg-blue-400 animate-pulse mr-1.5" />
      )}
      {status}
    </span>
  )
}
