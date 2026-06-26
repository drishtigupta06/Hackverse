import { useEffect, useState } from 'react'
import { listScans } from '../api/scans'
import type { Scan } from '../types/scan'
import { FileText, Download } from 'lucide-react'

export function ReportsPage() {
  const [scans, setScans] = useState<Scan[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    listScans({ status: 'completed', limit: 100 })
      .then((res) => setScans(res.scans))
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin w-8 h-8 border-2 border-accent border-t-transparent rounded-full" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <h1 className="text-lg font-medium">Reports</h1>

      {scans.length === 0 ? (
        <div className="flex flex-col items-center justify-center h-32 gap-2">
          <FileText className="w-10 h-10 text-text-tertiary" />
          <p className="text-text-secondary text-sm">No completed scans yet</p>
        </div>
      ) : (
        <div className="card overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-text-tertiary border-b border-border">
                <th className="text-left py-3 px-4 font-medium">App</th>
                <th className="text-left py-3 px-4 font-medium">Mode</th>
                <th className="text-left py-3 px-4 font-medium">Date</th>
                <th className="text-right py-3 px-4 font-medium">Duration</th>
                <th className="text-right py-3 px-4 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((scan) => (
                <tr key={scan.id} className="border-b border-border hover:bg-surface-secondary/50">
                  <td className="py-3 px-4 text-text-primary">{scan.id.slice(0, 8)}...</td>
                  <td className="py-3 px-4">
                    <span className="badge bg-surface-secondary text-text-secondary border border-border">
                      {scan.scan_mode}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-text-secondary">
                    {scan.completed_at ? new Date(scan.completed_at).toLocaleDateString() : '-'}
                  </td>
                  <td className="py-3 px-4 text-right text-text-secondary">
                    {scan.duration_secs ? `${scan.duration_secs}s` : '-'}
                  </td>
                  <td className="py-3 px-4 text-right">
                    <div className="flex items-center justify-end gap-2">
                      {scan.html_report_path && (
                        <a
                          href={`/api/v1/reports/${scan.id}/html`}
                          className="text-accent hover:text-accent-hover text-xs flex items-center gap-1"
                        >
                          <Download className="w-3 h-3" />
                          HTML
                        </a>
                      )}
                      {scan.sarif_path && (
                        <a
                          href={`/api/v1/reports/${scan.id}/sarif`}
                          className="text-accent hover:text-accent-hover text-xs flex items-center gap-1"
                        >
                          <Download className="w-3 h-3" />
                          SARIF
                        </a>
                      )}
                      <a
                        href={`/api/v1/reports/${scan.id}/json`}
                        className="text-accent hover:text-accent-hover text-xs flex items-center gap-1"
                      >
                        <Download className="w-3 h-3" />
                        JSON
                      </a>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
