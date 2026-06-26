import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { listFindings, getFindingSummary } from '../api/findings'
import type { Finding, FindingSummary } from '../types/finding'
import { FindingsTable } from '../components/findings/FindingsTable'
import { SeverityBadge } from '../components/findings/SeverityBadge'
import { Search, Filter, SlidersHorizontal } from 'lucide-react'

export function FindingsPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const [findings, setFindings] = useState<Finding[]>([])
  const [summary, setSummary] = useState<FindingSummary | null>(null)
  const [loading, setLoading] = useState(true)
  const [total, setTotal] = useState(0)

  const filters = {
    severity: searchParams.get('severity') || '',
    source: searchParams.get('source') || '',
    search: searchParams.get('search') || '',
    validated: searchParams.get('validated') || '',
    sortBy: searchParams.get('sort_by') || 'severity',
    order: searchParams.get('order') || 'desc',
    limit: parseInt(searchParams.get('limit') || '50'),
    offset: parseInt(searchParams.get('offset') || '0'),
  }

  const loadFindings = async () => {
    setLoading(true)
    try {
      const params: Record<string, string | number | boolean | undefined> = { ...filters }
      if (params.validated === 'true') params.validated = true
      else if (params.validated === 'false') params.validated = false
      else delete params.validated
      if (!params.severity) delete params.severity
      if (!params.source) delete params.source
      if (!params.search) delete params.search

      const [f, s] = await Promise.all([
        listFindings(params),
        getFindingSummary(),
      ])
      setFindings(f.findings)
      setTotal(f.total)
      setSummary(s)
    } catch (e) {
      console.error('Failed to load findings', e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { loadFindings() }, [searchParams])

  const updateFilter = (key: string, value: string) => {
    const newParams = new URLSearchParams(searchParams)
    if (value) newParams.set(key, value)
    else newParams.delete(key)
    newParams.set('offset', '0')
    setSearchParams(newParams)
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-medium">Findings</h1>
        {summary && (
          <div className="flex items-center gap-2 text-sm text-text-secondary">
            <span>Total: {summary.total}</span>
            {Object.entries(summary.by_severity).filter(([, c]) => c > 0).map(([sev, c]) => (
              <SeverityBadge key={sev} severity={sev} count={c} />
            ))}
          </div>
        )}
      </div>

      {/* Filter bar */}
      <div className="card p-3 flex items-center gap-3 flex-wrap">
        <div className="flex items-center gap-2 text-text-tertiary">
          <Filter className="w-4 h-4" />
          <span className="text-xs">Filters</span>
        </div>

        <select
          className="text-sm min-w-[120px]"
          value={filters.severity}
          onChange={(e) => updateFilter('severity', e.target.value)}
        >
          <option value="">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
          <option value="INFO">Info</option>
        </select>

        <select
          className="text-sm min-w-[120px]"
          value={filters.source}
          onChange={(e) => updateFilter('source', e.target.value)}
        >
          <option value="">All Sources</option>
          <option value="manifest">Manifest</option>
          <option value="source">Source</option>
          <option value="phase2">Phase 2</option>
          <option value="taint">Taint</option>
          <option value="frida">Frida</option>
          <option value="cve">CVE</option>
        </select>

        <select
          className="text-sm"
          value={filters.validated}
          onChange={(e) => updateFilter('validated', e.target.value)}
        >
          <option value="">All Status</option>
          <option value="true">Validated</option>
          <option value="false">Not Validated</option>
        </select>

        <div className="flex items-center gap-1 flex-1 max-w-xs">
          <Search className="w-4 h-4 text-text-tertiary" />
          <input
            className="text-sm flex-1"
            placeholder="Search rule ID or title..."
            value={filters.search}
            onChange={(e) => updateFilter('search', e.target.value)}
          />
        </div>

        <select
          className="text-sm"
          value={filters.sortBy}
          onChange={(e) => updateFilter('sort_by', e.target.value)}
        >
          <option value="severity">Severity</option>
          <option value="confidence">Confidence</option>
          <option value="rule_id">Rule ID</option>
        </select>
      </div>

      {loading ? (
        <div className="flex items-center justify-center h-32">
          <div className="animate-spin w-6 h-6 border-2 border-accent border-t-transparent rounded-full" />
        </div>
      ) : (
        <>
          <FindingsTable findings={findings} />

          {/* Pagination */}
          {total > filters.limit && (
            <div className="flex items-center justify-between text-sm text-text-secondary">
              <span>Showing {filters.offset + 1}-{Math.min(filters.offset + filters.limit, total)} of {total}</span>
              <div className="flex gap-2">
                <button
                  disabled={filters.offset === 0}
                  onClick={() => updateFilter('offset', String(Math.max(0, filters.offset - filters.limit)))}
                  className="btn-secondary text-xs"
                >
                  Previous
                </button>
                <button
                  disabled={filters.offset + filters.limit >= total}
                  onClick={() => updateFilter('offset', String(filters.offset + filters.limit))}
                  className="btn-secondary text-xs"
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  )
}
