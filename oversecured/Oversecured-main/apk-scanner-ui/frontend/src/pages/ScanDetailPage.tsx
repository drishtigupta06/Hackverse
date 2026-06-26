import { useEffect, useState, useRef, useCallback } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { getScan, cancelScan, deleteScan } from '../api/scans'
import { listFindings, getFindingSummary, getChains } from '../api/findings'
import { getApp } from '../api/apps'
import { getWsUrl } from '../api/client'
import { useToastStore } from '../store/useToastStore'
import type { Scan } from '../types/scan'
import type { Finding, FindingSummary, Severity } from '../types/finding'
import type { AppInfo } from '../types/config'
import { FindingsTable } from '../components/findings/FindingsTable'
import { ChainList } from '../components/chains/ChainList'
import { Share2, ExternalLink, AlertTriangle } from 'lucide-react'

type Tab = 'findings' | 'chains' | 'logs' | 'graph'

interface LogEntry {
  ts: string
  level: string
  message: string
}

interface ExploitChainData {
  id: string
  scan_id: string
  title: string
  severity: Severity
  validated: boolean
  steps: Array<{ role: string; finding_id: string; label: string }>
  poc_sequence: string[]
  created_at?: string
}

export function ScanDetailPage() {
  const { scanId } = useParams<{ scanId: string }>()
  const navigate = useNavigate()
  const [scan, setScan] = useState<Scan | null>(null)
  const [app, setApp] = useState<AppInfo | null>(null)
  const [findings, setFindings] = useState<Finding[]>([])
  const [chains, setChains] = useState<ExploitChainData[]>([])
  const [summary, setSummary] = useState<FindingSummary | null>(null)
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [tab, setTab] = useState<Tab>('findings')
  const [loading, setLoading] = useState(true)
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false)
  const [fetchingLogs, setFetchingLogs] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)
  const logEndRef = useRef<HTMLDivElement>(null)
  const reconnectRef = useRef<number>()
  const addToast = useToastStore((s) => s.addToast)
  const pollingRef = useRef<ReturnType<typeof setInterval>>()

  const loadData = useCallback(async () => {
    if (!scanId) return
    try {
      const s = await getScan(scanId)
      setScan(s)

      if (s.app_id) {
        getApp(s.app_id).then(setApp).catch(() => {})
      }

      if (s.status === 'completed') {
        const [f, sm, ch] = await Promise.all([
          listFindings({ scan_id: scanId, limit: 500 }),
          getFindingSummary({ scan_id: scanId }),
          getChains(scanId),
        ])
        setFindings(f.findings)
        setSummary(sm)
        setChains(ch)
      }
    } catch (e) {
      console.error('Failed to load scan', e)
    } finally {
      setLoading(false)
    }
  }, [scanId])

  useEffect(() => {
    loadData()
    pollingRef.current = setInterval(loadData, 5000)
    return () => {
      if (pollingRef.current) clearInterval(pollingRef.current)
    }
  }, [loadData])

  useEffect(() => {
    if (!scanId || !scan) return

    if (scan.status === 'running') {
      const abortController = new AbortController()

      const connect = () => {
        if (abortController.signal.aborted) return
        const ws = new WebSocket(getWsUrl(`/scans/${scanId}/logs`))
        wsRef.current = ws

        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data)
            if (data.event === 'scan_complete') {
              loadData()
              ws.close()
              return
            }
            if (data.message) {
              setLogs((prev) => [...prev.slice(-499), { ts: data.ts, level: data.level || 'info', message: data.message }])
            }
          } catch { /* ignore */ }
        }

        ws.onclose = () => {
          if (!abortController.signal.aborted) {
            reconnectRef.current = window.setTimeout(connect, 2000)
          }
        }
      }

      connect()
      return () => {
        abortController.abort()
        clearTimeout(reconnectRef.current)
        wsRef.current?.close()
      }
    }

    if (scan.status === 'completed' && !fetchingLogs) {
      setFetchingLogs(true)
      import('../api/scans').then(({ listScans }) => {
        listScans({ limit: 1, status: 'completed' }).catch(() => {})
      })
    }
  }, [scanId, scan?.status, loadData, fetchingLogs])

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [logs])

  const handleCancel = async () => {
    try {
      await cancelScan(scan!.id)
      addToast('info', 'Scan cancelled')
      navigate('/')
    } catch {
      addToast('error', 'Failed to cancel scan')
    }
  }

  const handleDelete = async () => {
    try {
      await deleteScan(scan!.id)
      addToast('success', 'Scan deleted')
      navigate('/')
    } catch {
      addToast('error', 'Failed to delete scan')
    } finally {
      setShowDeleteConfirm(false)
    }
  }

  useEffect(() => {
    if (scan?.status !== 'running') {
      if (pollingRef.current) {
        clearInterval(pollingRef.current)
        pollingRef.current = undefined
      }
    }
  }, [scan?.status])

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin w-8 h-8 border-2 border-accent border-t-transparent rounded-full" />
      </div>
    )
  }

  if (!scan) {
    return <div className="text-text-secondary">Scan not found</div>
  }

  const p1Count = findings.filter((f) => f.source === 'manifest' || f.source === 'source').length
  const criticalCount = findings.filter((f) => f.severity === 'CRITICAL').length
  const highCount = findings.filter((f) => f.severity === 'HIGH').length
  const escalatedCount = findings.filter((f) => f.original_sev && f.original_sev !== f.severity).length
  const validatedCount = findings.filter((f) => f.validated).length

  const componentGraphData = scan.config?.component_graph ? findings.filter(f => f.source === 'component') : []

  return (
    <div className="space-y-6">
      <div className="card p-6">
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-lg font-medium">{scan.id.slice(0, 8)}...</h1>
            <div className="flex items-center gap-3 mt-2 text-sm text-text-secondary">
              <span className="badge bg-surface-secondary text-text-secondary border border-border">{scan.scan_mode}</span>
              {app && (
                <span className="badge bg-accent/10 text-accent border border-accent/20">{app.filename} ({app.package_name})</span>
              )}
              {scan.sector_detected?.map((s) => (
                <span key={s} className="badge bg-accent/10 text-accent border border-accent/20">{s}</span>
              ))}
              <span>Started: {scan.started_at ? new Date(scan.started_at).toLocaleString() : '-'}</span>
              {scan.duration_secs && <span>Duration: {scan.duration_secs}s</span>}
            </div>
          </div>
          <div className="flex items-center gap-2">
            {scan.status === 'running' && (
              <button onClick={handleCancel} className="btn-danger text-sm">Cancel</button>
            )}
            {scan.html_report_path && (
              <button onClick={() => window.open(`/api/v1/reports/${scan.id}/html`)} className="btn-secondary text-sm flex items-center gap-1">
                <ExternalLink className="w-3 h-3" /> HTML
              </button>
            )}
            {scan.sarif_path && (
              <button onClick={() => window.open(`/api/v1/reports/${scan.id}/sarif`)} className="btn-secondary text-sm flex items-center gap-1">
                <Share2 className="w-3 h-3" /> SARIF
              </button>
            )}
            {scan.status !== 'running' && (
              <button onClick={() => setShowDeleteConfirm(true)} className="btn-danger text-sm">Delete</button>
            )}
          </div>
        </div>

        {scan.status === 'running' && (
          <div className="mt-4 flex items-center gap-2 text-sm">
            <span className="inline-block w-2 h-2 rounded-full bg-blue-400 animate-pulse" />
            <span className="text-blue-400">Scan in progress...</span>
          </div>
        )}

        {scan.status === 'completed' && (
          <div className="grid grid-cols-5 gap-4 mt-4 pt-4 border-t border-border">
            <StatBox label="P1 Findings" value={p1Count} />
            <StatBox label="Escalated" value={escalatedCount} color="text-yellow-400" />
            <StatBox label="Critical" value={criticalCount} color="text-severity-critical-text" />
            <StatBox label="High" value={highCount} color="text-severity-high-text" />
            <StatBox label="Validated" value={validatedCount} color="text-green-400" />
          </div>
        )}

        {scan.status === 'failed' && (
          <div className="mt-4 p-3 bg-severity-critical-bg border border-severity-critical-border rounded text-severity-critical-text text-sm">
            {scan.error_message || 'Scan failed with unknown error'}
          </div>
        )}
      </div>

      {showDeleteConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={() => setShowDeleteConfirm(false)}>
          <div className="card p-6 max-w-sm mx-4" onClick={(e) => e.stopPropagation()}>
            <h3 className="text-sm font-medium text-text-primary mb-2">Delete Scan</h3>
            <p className="text-sm text-text-secondary mb-4">Are you sure you want to delete this scan? This action cannot be undone.</p>
            <div className="flex justify-end gap-2">
              <button onClick={() => setShowDeleteConfirm(false)} className="btn-secondary text-sm">Cancel</button>
              <button onClick={handleDelete} className="btn-danger text-sm">Delete</button>
            </div>
          </div>
        </div>
      )}

      {scan.status === 'completed' && (
        <>
          <div className="flex gap-1 card p-1">
            {(['findings', 'chains', 'graph', 'logs'] as Tab[]).map((t) => (
              <button
                key={t}
                onClick={() => setTab(t)}
                className={`px-4 py-2 text-sm rounded transition-colors ${
                  tab === t ? 'bg-accent text-white' : 'text-text-secondary hover:text-text-primary'
                }`}
              >
                {t === 'findings' && `Findings (${findings.length})`}
                {t === 'chains' && `Chains (${chains.length})`}
                {t === 'graph' && `Component Graph (${componentGraphData.length})`}
                {t === 'logs' && 'Logs'}
              </button>
            ))}
          </div>

          {tab === 'findings' && <FindingsTable findings={findings} />}

          {tab === 'chains' && <ChainList chains={chains} />}

          {tab === 'graph' && (
            <div className="card p-6 space-y-4">
              <h3 className="text-sm font-medium">Component Attack Surface</h3>
              {componentGraphData.length === 0 ? (
                <div className="flex flex-col items-center gap-2 py-8">
                  <AlertTriangle className="w-8 h-8 text-text-tertiary" />
                  <p className="text-sm text-text-secondary">No component graph data available</p>
                  <p className="text-xs text-text-tertiary">Enable Component Graph in scan config to generate attack surface visualization</p>
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                  {componentGraphData.map((f, i) => (
                    <div key={i} className="p-3 rounded-lg border border-border bg-surface-secondary">
                      <div className="text-xs font-mono text-accent mb-1">{f.rule_id}</div>
                      <div className="text-sm text-text-primary">{f.title}</div>
                      <div className="text-xs text-text-tertiary mt-1">{f.location}</div>
                      {f.severity && (
                        <span className={`text-xs mt-2 inline-block badge ${
                          f.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400' :
                          f.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400' :
                          'bg-yellow-500/20 text-yellow-400'
                        }`}>{f.severity}</span>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {tab === 'logs' && (
            <div className="card p-4">
              <div className="bg-[#0d0f14] rounded-lg p-4 font-mono text-xs max-h-[500px] overflow-y-auto space-y-1">
                {logs.length === 0 ? (
                  <div className="text-text-tertiary text-center py-4">No logs available. Logs are only captured during active scans.</div>
                ) : (
                  logs.map((log, i) => (
                    <div key={i} className={`${log.level === 'error' ? 'text-red-400' : log.level === 'warn' ? 'text-yellow-400' : log.level === 'debug' ? 'text-text-tertiary' : 'text-text-secondary'}`}>
                      <span className="text-text-tertiary mr-2">{log.ts ? new Date(log.ts).toLocaleTimeString() : ''}</span>
                      {log.message}
                    </div>
                  ))
                )}
                <div ref={logEndRef} />
              </div>
            </div>
          )}
        </>
      )}

      {scan.status === 'running' && (
        <div className="card p-4">
          <div className="bg-[#0d0f14] rounded-lg p-4 font-mono text-xs max-h-[600px] overflow-y-auto space-y-1">
            {logs.map((log, i) => (
              <div key={i} className={`${log.level === 'error' ? 'text-red-400' : log.level === 'warn' ? 'text-yellow-400' : log.level === 'debug' ? 'text-text-tertiary' : 'text-text-secondary'}`}>
                <span className="text-text-tertiary mr-2">{log.ts ? new Date(log.ts).toLocaleTimeString() : ''}</span>
                {log.message}
              </div>
            ))}
            <div ref={logEndRef} />
          </div>
        </div>
      )}
    </div>
  )
}

function StatBox({ label, value, color }: { label: string; value: number; color?: string }) {
  return (
    <div className="text-center">
      <div className={`text-xl font-medium ${color || 'text-text-primary'}`}>{value}</div>
      <div className="text-xs text-text-secondary mt-0.5">{label}</div>
    </div>
  )
}
