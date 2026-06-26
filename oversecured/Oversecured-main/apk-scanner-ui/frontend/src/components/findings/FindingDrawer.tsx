import { useEffect } from 'react'
import { X } from 'lucide-react'
import type { Finding } from '../../types/finding'
import { SeverityBadge } from './SeverityBadge'
import { PoCBlock } from './PoCBlock'

export function FindingDrawer({ finding, onClose }: { finding: Finding; onClose: () => void }) {
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [onClose])

  return (
    <>
      <div className="fixed inset-0 bg-black/50 z-40" onClick={onClose} />
      <div className="fixed top-0 right-0 h-full w-[480px] bg-surface-card border-l border-border z-50 overflow-y-auto shadow-2xl">
        <div className="sticky top-0 bg-surface-card border-b border-border p-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <SeverityBadge severity={finding.severity} />
            <span className="font-mono text-xs text-text-secondary">{finding.rule_id}</span>
          </div>
          <button onClick={onClose} className="text-text-tertiary hover:text-text-primary">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-4 space-y-5">
          <div>
            <h2 className="text-base font-medium text-text-primary">{finding.title}</h2>
          </div>

          {finding.description && (
            <div>
              <h3 className="text-xs font-medium text-text-secondary uppercase tracking-wider mb-1">Description</h3>
              <p className="text-sm text-text-secondary">{finding.description}</p>
            </div>
          )}

          {finding.location && (
            <div>
              <h3 className="text-xs font-medium text-text-secondary uppercase tracking-wider mb-1">Location</h3>
              <div className="font-mono text-xs text-text-primary bg-[#0d0f14] p-2 rounded">{finding.location}</div>
            </div>
          )}

          {finding.sectors && finding.sectors.length > 0 && (
            <div>
              <h3 className="text-xs font-medium text-text-secondary uppercase tracking-wider mb-1">Sectors</h3>
              <div className="flex gap-1.5 flex-wrap">
                {finding.sectors.map((s) => (
                  <span key={s} className="badge bg-accent/10 text-accent border border-accent/20">{s}</span>
                ))}
              </div>
            </div>
          )}

          {finding.escalation_rule && (
            <div>
              <h3 className="text-xs font-medium text-text-secondary uppercase tracking-wider mb-1">Escalation</h3>
              <div className="text-sm text-text-secondary">
                {finding.original_sev && (
                  <span>Original: <SeverityBadge severity={finding.original_sev} /></span>
                )}
                <span className="mx-2">→</span>
                <span>Rule: <code className="font-mono text-accent">{finding.escalation_rule}</code></span>
              </div>
            </div>
          )}

          {finding.confidence !== undefined && (
            <div>
              <h3 className="text-xs font-medium text-text-secondary uppercase tracking-wider mb-1">Confidence</h3>
              <div className="flex items-center gap-2">
                <div className="flex-1 h-2 bg-surface-secondary rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full ${
                      finding.confidence >= 70 ? 'bg-green-400' :
                      finding.confidence >= 40 ? 'bg-yellow-400' : 'bg-red-400'
                    }`}
                    style={{ width: `${finding.confidence}%` }}
                  />
                </div>
                <span className="text-sm font-medium text-text-primary">{finding.confidence}%</span>
              </div>
            </div>
          )}

          {finding.impact && (
            <div>
              <h3 className="text-xs font-medium text-text-secondary uppercase tracking-wider mb-1">Impact</h3>
              <p className="text-sm text-text-secondary">{finding.impact}</p>
            </div>
          )}

          {finding.poc_command && (
            <div>
              <h3 className="text-xs font-medium text-text-secondary uppercase tracking-wider mb-1">Proof of Concept</h3>
              <PoCBlock command={finding.poc_command} vector={finding.poc_vector} />
            </div>
          )}

          {finding.recommendation && (
            <div>
              <h3 className="text-xs font-medium text-text-secondary uppercase tracking-wider mb-1">Recommendation</h3>
              <p className="text-sm text-text-secondary">{finding.recommendation}</p>
            </div>
          )}

          <div className="flex items-center gap-3 pt-2 border-t border-border">
            {finding.validated ? (
              <span className="badge bg-green-500/20 text-green-400 border-green-500/30">Validated</span>
            ) : (
              <span className="badge bg-yellow-500/20 text-yellow-400 border-yellow-500/30">Not Validated</span>
            )}
            <span className="text-xs text-text-tertiary">
              {finding.created_at ? new Date(finding.created_at).toLocaleString() : ''}
            </span>
          </div>
        </div>
      </div>
    </>
  )
}
