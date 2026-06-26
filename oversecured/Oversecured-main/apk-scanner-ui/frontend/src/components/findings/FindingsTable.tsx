import { useState } from 'react'
import type { Finding } from '../../types/finding'
import { SeverityBadge } from './SeverityBadge'
import { FindingDrawer } from './FindingDrawer'

export function FindingsTable({ findings }: { findings: Finding[] }) {
  const [selected, setSelected] = useState<Finding | null>(null)

  if (findings.length === 0) {
    return <div className="text-text-secondary text-sm">No findings.</div>
  }

  return (
    <>
      <div className="card overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-text-tertiary border-b border-border">
              <th className="text-left py-3 px-4 font-medium">Severity</th>
              <th className="text-left py-3 px-4 font-medium">Rule ID</th>
              <th className="text-left py-3 px-4 font-medium">Title</th>
              <th className="text-left py-3 px-4 font-medium">Source</th>
              <th className="text-left py-3 px-4 font-medium">Confidence</th>
              <th className="text-center py-3 px-4 font-medium">Validated</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f) => (
              <tr
                key={f.id}
                className="border-b border-border hover:bg-surface-secondary/50 cursor-pointer"
                onClick={() => setSelected(f)}
              >
                <td className="py-3 px-4">
                  <SeverityBadge severity={f.severity} />
                </td>
                <td className="py-3 px-4 font-mono text-xs text-text-secondary">{f.rule_id}</td>
                <td className="py-3 px-4 text-text-primary max-w-md truncate">{f.title}</td>
                <td className="py-3 px-4">
                  <span className="badge bg-surface-secondary text-text-secondary border border-border">
                    {f.source || 'unknown'}
                  </span>
                </td>
                <td className="py-3 px-4">
                  <div className="flex items-center gap-2">
                    <div className="w-16 h-1.5 bg-surface-secondary rounded-full overflow-hidden">
                      <div
                        className={`h-full rounded-full ${
                          (f.confidence ?? 0) >= 70 ? 'bg-green-400' :
                          (f.confidence ?? 0) >= 40 ? 'bg-yellow-400' : 'bg-red-400'
                        }`}
                        style={{ width: `${f.confidence ?? 0}%` }}
                      />
                    </div>
                    <span className="text-xs text-text-secondary">{f.confidence ?? '-'}</span>
                  </div>
                </td>
                <td className="py-3 px-4 text-center">
                  {f.validated ? (
                    <span className="text-green-400 text-sm">✓</span>
                  ) : (
                    <span className="text-text-tertiary text-sm">-</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {selected && <FindingDrawer finding={selected} onClose={() => setSelected(null)} />}
    </>
  )
}
