import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { getChains } from '../api/findings'
import { listScans } from '../api/scans'
import { ChainList } from '../components/chains/ChainList'
import { useToastStore } from '../store/useToastStore'
import type { Scan } from '../types/scan'
import type { Severity } from '../types/finding'

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

export function ChainsPage() {
  const [searchParams] = useSearchParams()
  const [chains, setChains] = useState<ExploitChainData[]>([])
  const [scans, setScans] = useState<Scan[]>([])
  const [selectedScanId, setSelectedScanId] = useState(searchParams.get('scan_id') || '')
  const [loading, setLoading] = useState(true)
  const addToast = useToastStore((s) => s.addToast)

  useEffect(() => {
    listScans({ limit: 50 }).then((res) => {
      setScans(res.scans)
      if (!selectedScanId && res.scans.length > 0) {
        setSelectedScanId(res.scans[0].id)
      }
    }).catch(() => addToast('error', 'Failed to load scans'))
  }, [])

  useEffect(() => {
    if (!selectedScanId) return
    setLoading(true)
    getChains(selectedScanId)
      .then(setChains)
      .catch(() => addToast('error', 'Failed to load exploit chains'))
      .finally(() => setLoading(false))
  }, [selectedScanId])

  return (
    <div className="space-y-6">
      <h1 className="text-lg font-medium">Exploit Chains</h1>

      <div className="flex items-center gap-3">
        <label className="text-sm text-text-secondary">Scan:</label>
        <select
          className="text-sm flex-1 max-w-sm"
          value={selectedScanId}
          onChange={(e) => setSelectedScanId(e.target.value)}
        >
          <option value="">Select a scan...</option>
          {scans.map((s) => (
            <option key={s.id} value={s.id}>
              {s.id.slice(0, 8)}... ({s.scan_mode}) - {s.status}
            </option>
          ))}
        </select>
      </div>

      {loading ? (
        <div className="flex items-center justify-center h-32">
          <div className="animate-spin w-6 h-6 border-2 border-accent border-t-transparent rounded-full" />
        </div>
      ) : chains.length === 0 ? (
        <div className="text-text-secondary text-sm">No exploit chains found for this scan.</div>
      ) : (
        <ChainList chains={chains} />
      )}
    </div>
  )
}
