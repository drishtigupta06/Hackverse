import { useState, useCallback } from 'react'
import { api } from '../api/client'
import { useToastStore } from '../store/useToastStore'
import { Shield, Search, ExternalLink, Bug, ChevronDown, ChevronRight, Loader } from 'lucide-react'

interface CveResult {
  id: string
  summary?: string
  severity?: string
  cvss?: number
  affected_packages?: string[]
  published?: string
  url?: string
}

export function CveBrowserPage() {
  const [query, setQuery] = useState('')
  const [days, setDays] = useState(90)
  const [results, setResults] = useState<CveResult[]>([])
  const [loading, setLoading] = useState(false)
  const [searched, setSearched] = useState(false)
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const addToast = useToastStore((s) => s.addToast)

  const handleSearch = useCallback(async () => {
    if (!query.trim()) return
    setLoading(true)
    setSearched(true)
    try {
      const { data } = await api.get('/cves/search', {
        params: { q: query, days },
        timeout: 30000,
      })
      const items = data.results || data.cves || []
      setResults(items)
      if (!Array.isArray(items) || items.length === 0) {
        addToast('info', 'No CVEs found for your query')
      }
    } catch {
      setResults([])
      addToast('error', 'CVE search failed (ensure CVE database is updated)')
    } finally {
      setLoading(false)
    }
  }, [query, days, addToast])

  const toggleExpand = (id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const severityColor = (sev?: string) => {
    if (!sev) return 'text-text-tertiary'
    const s = sev.toUpperCase()
    if (s === 'CRITICAL') return 'text-red-400'
    if (s === 'HIGH') return 'text-orange-400'
    if (s === 'MEDIUM') return 'text-yellow-400'
    if (s === 'LOW') return 'text-green-400'
    return 'text-text-tertiary'
  }

  return (
    <div className="max-w-[800px] mx-auto space-y-6">
      <h1 className="text-lg font-medium">CVE Browser</h1>

      <div className="card p-6 space-y-4">
        <h2 className="text-sm font-medium">Search Android CVEs</h2>
        <div className="flex gap-3">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-tertiary" />
            <input
              className="w-full pl-9 text-sm"
              placeholder="Search CVE keywords (e.g. WebView RCE, Bluetooth, WiFi)"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
            />
          </div>
          <div className="w-24">
            <input
              type="number"
              className="w-full text-sm"
              placeholder="Days"
              value={days}
              onChange={(e) => setDays(parseInt(e.target.value) || 90)}
              title="Days back to search"
            />
          </div>
          <button onClick={handleSearch} disabled={loading || !query.trim()} className="btn-primary text-sm flex items-center gap-2">
            {loading ? <Loader className="w-4 h-4 animate-spin" /> : <Bug className="w-4 h-4" />}
            Search
          </button>
        </div>
      </div>

      {loading && (
        <div className="flex items-center justify-center py-12">
          <Loader className="w-6 h-6 animate-spin text-text-secondary" />
        </div>
      )}

      {!loading && searched && results.length === 0 && (
        <div className="flex flex-col items-center justify-center py-12 gap-3">
          <Shield className="w-12 h-12 text-text-tertiary" />
          <p className="text-text-secondary text-sm">No CVEs found. Try different keywords or update the CVE database.</p>
        </div>
      )}

      {results.length > 0 && (
        <div className="space-y-2">
          <p className="text-sm text-text-secondary">{results.length} CVE(s) found</p>
          {results.map((cve) => (
            <div key={cve.id} className="card overflow-hidden">
              <button
                onClick={() => toggleExpand(cve.id)}
                className="w-full px-4 py-3 flex items-center justify-between gap-3 hover:bg-surface-secondary/50 transition-colors text-left"
              >
                <div className="flex items-center gap-3 min-w-0">
                  {expanded.has(cve.id) ? <ChevronDown className="w-4 h-4 shrink-0 text-text-tertiary" /> : <ChevronRight className="w-4 h-4 shrink-0 text-text-tertiary" />}
                  <span className="font-mono text-sm text-accent shrink-0">{cve.id}</span>
                  {cve.severity && (
                    <span className={`badge border ${severityColor(cve.severity)}`}>{cve.severity}</span>
                  )}
                  {cve.cvss && (
                    <span className="text-xs text-text-tertiary">CVSS {cve.cvss}</span>
                  )}
                  <span className="text-sm text-text-secondary truncate">{cve.summary || ''}</span>
                </div>
                {cve.url && (
                  <a href={cve.url} target="_blank" rel="noopener noreferrer" onClick={(e) => e.stopPropagation()} className="text-text-tertiary hover:text-accent shrink-0">
                    <ExternalLink className="w-4 h-4" />
                  </a>
                )}
              </button>
              {expanded.has(cve.id) && (
                <div className="px-4 pb-4 pt-0 border-t border-border mt-0">
                  <div className="pt-3 space-y-2 text-sm">
                    {cve.summary && <p className="text-text-secondary">{cve.summary}</p>}
                    {cve.published && <p className="text-text-tertiary text-xs">Published: {new Date(cve.published).toLocaleDateString()}</p>}
                    {cve.affected_packages && cve.affected_packages.length > 0 && (
                      <div>
                        <p className="text-xs text-text-tertiary mb-1">Affected packages:</p>
                        <div className="flex flex-wrap gap-1">
                          {cve.affected_packages.map((pkg) => (
                            <span key={pkg} className="badge bg-surface-secondary text-xs text-text-secondary border border-border">{pkg}</span>
                          ))}
                        </div>
                      </div>
                    )}
                    {cve.url && (
                      <a href={cve.url} target="_blank" rel="noopener noreferrer" className="text-accent hover:text-accent-hover text-xs flex items-center gap-1">
                        <ExternalLink className="w-3 h-3" /> View on NVD
                      </a>
                    )}
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
