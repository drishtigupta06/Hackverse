import { useState } from 'react'
import { SeverityBadge } from '../findings/SeverityBadge'
import { PoCBlock } from '../findings/PoCBlock'
import { CheckCircle, XCircle } from 'lucide-react'

interface Chain {
  id: string
  title: string
  severity: string
  validated: boolean
  steps: Array<{ role: string; finding_id: string; label: string }>
  poc_sequence: string[]
  created_at?: string
}

const roleColors: Record<string, string> = {
  entry: 'text-blue-400',
  pivot: 'text-amber-400',
  impact: 'text-red-400',
}

const roleLabels: Record<string, string> = {
  entry: 'Entry Point',
  pivot: 'Pivot',
  impact: 'Impact',
}

export function ChainList({ chains }: { chains: Chain[] }) {
  const [selected, setSelected] = useState<Chain | null>(null)

  if (chains.length === 0) {
    return <div className="text-text-secondary text-sm">No exploit chains found.</div>
  }

  return (
    <div className="grid grid-cols-5 gap-4">
      {/* Chain list */}
      <div className="col-span-2 space-y-2">
        {chains.map((chain) => (
          <button
            key={chain.id}
            onClick={() => setSelected(chain)}
            className={`w-full card p-3 text-left transition-colors ${
              selected?.id === chain.id ? 'border-accent' : 'hover:border-border-hover'
            }`}
          >
            <div className="flex items-center justify-between">
              <SeverityBadge severity={chain.severity} />
              {chain.validated ? (
                <CheckCircle className="w-4 h-4 text-green-400" />
              ) : (
                <XCircle className="w-4 h-4 text-text-tertiary" />
              )}
            </div>
            <div className="mt-2 text-sm text-text-primary font-medium">{chain.title}</div>
            <div className="mt-1 text-xs text-text-secondary">{chain.steps.length} steps</div>
          </button>
        ))}
      </div>

      {/* Detail */}
      <div className="col-span-3">
        {selected ? (
          <div className="card p-4 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-medium">{selected.title}</h3>
              <SeverityBadge severity={selected.severity} />
            </div>

            {/* Graph */}
            <div className="flex items-center gap-1 py-4">
              {selected.steps.map((step, i) => (
                <div key={step.finding_id} className="flex items-center gap-1">
                  <div className={`px-3 py-1.5 rounded text-xs font-medium border ${
                    step.role === 'entry' ? 'border-blue-500/30 bg-blue-500/10 text-blue-400' :
                    step.role === 'pivot' ? 'border-amber-500/30 bg-amber-500/10 text-amber-400' :
                    'border-red-500/30 bg-red-500/10 text-red-400'
                  }`}>
                    {step.label || step.finding_id.slice(0, 8)}
                  </div>
                  {i < selected.steps.length - 1 && (
                    <div className="text-text-tertiary text-xs">→</div>
                  )}
                </div>
              ))}
            </div>

            {/* Step details */}
            <div className="space-y-2">
              {selected.steps.map((step, i) => (
                <div key={step.finding_id} className="flex items-start gap-2 text-sm">
                  <span className={`text-xs font-medium w-20 flex-shrink-0 ${roleColors[step.role] || 'text-text-secondary'}`}>
                    {roleLabels[step.role] || step.role}
                  </span>
                  <span className="text-text-secondary">{step.label}</span>
                  <span className="font-mono text-xs text-text-tertiary">{step.finding_id.slice(0, 8)}</span>
                </div>
              ))}
            </div>

            {/* PoC sequence */}
            {selected.poc_sequence && selected.poc_sequence.length > 0 && (
              <div className="space-y-2">
                <h4 className="text-xs font-medium text-text-secondary uppercase tracking-wider">PoC Sequence</h4>
                {selected.poc_sequence.map((cmd, i) => (
                  <div key={i}>
                    <div className="text-xs text-text-tertiary mb-1">Step {i + 1}</div>
                    <PoCBlock command={cmd} vector="adb" />
                  </div>
                ))}
              </div>
            )}
          </div>
        ) : (
          <div className="card p-8 flex items-center justify-center">
            <p className="text-text-secondary text-sm">Select a chain to view details</p>
          </div>
        )}
      </div>
    </div>
  )
}
