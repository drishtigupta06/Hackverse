import { useEffect, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { listScans } from '../api/scans'
import { getFindingSummary } from '../api/findings'
import { listApps } from '../api/apps'
import type { Scan } from '../types/scan'
import type { AppInfo } from '../types/config'
import { Search, ChevronLeft, ChevronRight } from 'lucide-react'

const PAGE_SIZE = 20

export function AllScansPage() {
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  const [scans, setScans] = useState<Scan[]>([])
  const [apps, setApps] = useState<AppInfo[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)

  const statusFilter = searchParams.get('status') || ''
  const modeFilter = searchParams.get('mode') || ''
  const searchQuery = searchParams.get('q') || ''
  const page = parseInt(searchParams.get('page') || '1', 10)
  const offset = (page - 1) * PAGE_SIZE

  const loadScans = async () => {
    setLoading(true)
    try {
      const params: Record<string, string | number> = { limit: PAGE_SIZE, offset }
      if (statusFilter) params.status = statusFilter
      if (modeFilter) params.scan_mode = modeFilter
      const res = await listScans(params)
      setScans(res.scans)
      setTotal(res.total)

      const appRes = await listApps()
      setApps(appRes.apps)
    } catch { /* ignore */ }
    finally { setLoading(false) }
  }

  useEffect(() => { loadScans() }, [statusFilter, page])

  const updateFilter = (key: string, val: string) => {
    const params = new URLSearchParams(searchParams)
    if (val) params.set(key, val)
    else params.delete(key)
    if (key !== 'page') params.set('page', '1')
    setSearchParams(params)
  }

  const appMap = Object.fromEntries(apps.map((a) => [a.id, a]))
  const filteredScans = searchQuery
    ? scans.filter((s) => s.id.includes(searchQuery) || (appMap[s.app_id]?.filename || '').toLowerCase().includes(searchQuery.toLowerCase()))
    : scans

  const totalPages = Math.ceil(total / PAGE_SIZE)

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-medium">All Scans</h1>
        <button onClick={() => navigate('/scans/new')} className="btn-primary text-sm">New Scan</button>
      </div>

      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-xs">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-tertiary" />
          <input
            className="w-full pl-9 text-sm"
            placeholder="Search by ID or app name..."
            value={searchQuery}
            onChange={(e) => updateFilter('q', e.target.value)}
          />
        </div>
        <select className="text-sm w-32" value={statusFilter} onChange={(e) => updateFilter('status', e.target.value)}>
          <option value="">All status</option>
          <option value="running">Running</option>
          <option value="completed">Completed</option>
          <option value="failed">Failed</option>
          <option value="queued">Queued</option>
          <option value="cancelled">Cancelled</option>
        </select>
        <select className="text-sm w-32" value={modeFilter} onChange={(e) => updateFilter('mode', e.target.value)}>
          <option value="">All modes</option>
          <option value="fast">Fast</option>
          <option value="standard">Standard</option>
          <option value="thorough">Thorough</option>
          <option value="bb">Bug Bounty</option>
        </select>
        <span className="text-xs text-text-tertiary">{total} total</span>
      </div>

      {loading ? (
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin w-8 h-8 border-2 border-accent border-t-transparent rounded-full" />
        </div>
      ) : filteredScans.length === 0 ? (
        <div className="flex flex-col items-center justify-center h-32 gap-2">
          <p className="text-text-secondary text-sm">No scans match your filters</p>
          <button onClick={() => navigate('/scans/new')} className="btn-primary text-sm">Create Scan</button>
        </div>
      ) : (
        <>
          <div className="card overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-text-tertiary border-b border-border">
                  <th className="text-left py-3 px-4 font-medium">App</th>
                  <th className="text-left py-3 px-4 font-medium">ID</th>
                  <th className="text-left py-3 px-4 font-medium">Mode</th>
                  <th className="text-left py-3 px-4 font-medium">Status</th>
                  <th className="text-left py-3 px-4 font-medium">Duration</th>
                  <th className="text-right py-3 px-4 font-medium">Created</th>
                  <th className="text-right py-3 px-4 font-medium"></th>
                </tr>
              </thead>
              <tbody>
                {filteredScans.map((scan) => {
                  const appInfo = appMap[scan.app_id]
                  return (
                    <tr
                      key={scan.id}
                      className="border-b border-border hover:bg-surface-secondary/50 cursor-pointer"
                      onClick={() => navigate(`/scans/${scan.id}`)}
                    >
                      <td className="py-3 px-4 text-text-primary max-w-[120px] truncate" title={appInfo?.filename || ''}>
                        {appInfo?.filename || scan.id.slice(0, 8)}
                      </td>
                      <td className="py-3 px-4 font-mono text-xs text-text-secondary">{scan.id.slice(0, 8)}...</td>
                      <td className="py-3 px-4">
                        <span className="badge bg-surface-secondary text-text-secondary border border-border">{scan.scan_mode}</span>
                      </td>
                      <td className="py-3 px-4">
                        <span className={`badge border ${statusColors[scan.status] || statusColors.queued}`}>
                          {scan.status === 'running' && (
                            <span className="inline-block w-1.5 h-1.5 rounded-full bg-blue-400 animate-pulse mr-1.5" />
                          )}
                          {scan.status}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-text-secondary">{scan.duration_secs ? `${scan.duration_secs}s` : '-'}</td>
                      <td className="py-3 px-4 text-right text-text-secondary text-xs">{scan.created_at ? new Date(scan.created_at).toLocaleDateString() : '-'}</td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={(e) => { e.stopPropagation(); navigate(`/scans/${scan.id}`) }}
                          className="text-accent hover:text-accent-hover text-xs"
                        >
                          View
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>

          {totalPages > 1 && (
            <div className="flex items-center justify-center gap-2">
              <button
                disabled={page <= 1}
                onClick={() => updateFilter('page', String(page - 1))}
                className="btn-secondary text-sm disabled:opacity-30"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <span className="text-sm text-text-secondary">Page {page} of {totalPages}</span>
              <button
                disabled={page >= totalPages}
                onClick={() => updateFilter('page', String(page + 1))}
                className="btn-secondary text-sm disabled:opacity-30"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          )}
        </>
      )}
    </div>
  )
}

const statusColors: Record<string, string> = {
  queued: 'text-gray-400 bg-gray-500/10 border-gray-500/30',
  running: 'text-blue-400 bg-blue-500/10 border-blue-500/30',
  completed: 'text-green-400 bg-green-500/10 border-green-500/30',
  failed: 'text-red-400 bg-red-500/10 border-red-500/30',
  cancelled: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30',
}
