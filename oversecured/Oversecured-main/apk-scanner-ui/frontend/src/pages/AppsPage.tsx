import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { listApps, deleteApp } from '../api/apps'
import { listScans } from '../api/scans'
import { useToastStore } from '../store/useToastStore'
import type { AppInfo } from '../types/config'
import type { Scan } from '../types/scan'
import { Package, Trash2, Upload, Search, ChevronLeft, ChevronRight } from 'lucide-react'

const PAGE_SIZE = 20

export function AppsPage() {
  const navigate = useNavigate()
  const [apps, setApps] = useState<AppInfo[]>([])
  const [scans, setScans] = useState<Scan[]>([])
  const [loading, setLoading] = useState(true)
  const [searchQuery, setSearchQuery] = useState('')
  const [page, setPage] = useState(1)
  const [deleteTarget, setDeleteTarget] = useState<AppInfo | null>(null)
  const addToast = useToastStore((s) => s.addToast)

  useEffect(() => {
    const load = async () => {
      try {
        const [appRes, scanRes] = await Promise.all([listApps(), listScans({ limit: 500 })])
        setApps(appRes.apps)
        setScans(scanRes.scans)
      } catch {
        addToast('error', 'Failed to load apps')
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [])

  const scanCounts = scans.reduce<Record<string, number>>((acc, s) => {
    acc[s.app_id] = (acc[s.app_id] || 0) + 1
    return acc
  }, {})

  const handleDelete = async () => {
    if (!deleteTarget) return
    try {
      await deleteApp(deleteTarget.id)
      setApps((prev) => prev.filter((a) => a.id !== deleteTarget.id))
      addToast('success', `Deleted ${deleteTarget.filename}`)
    } catch {
      addToast('error', 'Failed to delete app')
    } finally {
      setDeleteTarget(null)
    }
  }

  const filtered = searchQuery
    ? apps.filter((a) => a.filename.toLowerCase().includes(searchQuery.toLowerCase()) || (a.package_name || '').toLowerCase().includes(searchQuery.toLowerCase()))
    : apps

  const totalPages = Math.ceil(filtered.length / PAGE_SIZE)
  const paged = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE)

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin w-8 h-8 border-2 border-accent border-t-transparent rounded-full" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-medium">App Management</h1>
        <button onClick={() => navigate('/scans/new')} className="btn-primary flex items-center gap-2 text-sm">
          <Upload className="w-4 h-4" /> Upload APK
        </button>
      </div>

      <div className="relative max-w-xs">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-tertiary" />
        <input className="w-full pl-9 text-sm" placeholder="Search by name or package..." value={searchQuery} onChange={(e) => { setSearchQuery(e.target.value); setPage(1) }} />
      </div>

      {paged.length === 0 ? (
        <div className="flex flex-col items-center justify-center h-32 gap-2">
          <Package className="w-8 h-8 text-text-tertiary" />
          <p className="text-text-secondary text-sm">{searchQuery ? 'No apps match your search' : 'No apps uploaded yet'}</p>
          <button onClick={() => navigate('/scans/new')} className="btn-primary text-sm">Upload APK</button>
        </div>
      ) : (
        <>
          <div className="card overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-text-tertiary border-b border-border">
                  <th className="text-left py-3 px-4 font-medium">Filename</th>
                  <th className="text-left py-3 px-4 font-medium">Package</th>
                  <th className="text-left py-3 px-4 font-medium">Version</th>
                  <th className="text-left py-3 px-4 font-medium">Size</th>
                  <th className="text-left py-3 px-4 font-medium">Scans</th>
                  <th className="text-right py-3 px-4 font-medium">Uploaded</th>
                  <th className="text-right py-3 px-4 font-medium"></th>
                </tr>
              </thead>
              <tbody>
                {paged.map((app) => (
                  <tr key={app.id} className="border-b border-border hover:bg-surface-secondary/50">
                    <td className="py-3 px-4 text-text-primary font-medium">{app.filename}</td>
                    <td className="py-3 px-4 text-text-secondary font-mono text-xs">{app.package_name || '-'}</td>
                    <td className="py-3 px-4 text-text-secondary">{app.version_name ? `v${app.version_name}` : '-'}</td>
                    <td className="py-3 px-4 text-text-secondary">{app.size_bytes ? `${(app.size_bytes / 1024 / 1024).toFixed(1)} MB` : '-'}</td>
                    <td className="py-3 px-4">
                      <span className="badge bg-accent/10 text-accent border border-accent/20">{scanCounts[app.id] || 0}</span>
                    </td>
                    <td className="py-3 px-4 text-right text-text-secondary text-xs">{app.uploaded_at ? new Date(app.uploaded_at).toLocaleDateString() : '-'}</td>
                    <td className="py-3 px-4 text-right">
                      <button onClick={() => setDeleteTarget(app)} className="text-red-400 hover:text-red-300">
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {totalPages > 1 && (
            <div className="flex items-center justify-center gap-2">
              <button disabled={page <= 1} onClick={() => setPage((p) => p - 1)} className="btn-secondary text-sm disabled:opacity-30">
                <ChevronLeft className="w-4 h-4" />
              </button>
              <span className="text-sm text-text-secondary">Page {page} of {totalPages}</span>
              <button disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)} className="btn-secondary text-sm disabled:opacity-30">
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          )}
        </>
      )}

      {deleteTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={() => setDeleteTarget(null)}>
          <div className="card p-6 max-w-sm mx-4" onClick={(e) => e.stopPropagation()}>
            <h3 className="text-sm font-medium text-text-primary mb-2">Delete App</h3>
            <p className="text-sm text-text-secondary mb-4">Delete "{deleteTarget.filename}" and all associated scans? This cannot be undone.</p>
            <div className="flex justify-end gap-2">
              <button onClick={() => setDeleteTarget(null)} className="btn-secondary text-sm">Cancel</button>
              <button onClick={handleDelete} className="btn-danger text-sm">Delete</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
