const severityStyles: Record<string, string> = {
  CRITICAL: 'bg-severity-critical-bg text-severity-critical-text border-severity-critical-border',
  HIGH: 'bg-severity-high-bg text-severity-high-text border-severity-high-border',
  MEDIUM: 'bg-severity-medium-bg text-severity-medium-text border-severity-medium-border',
  LOW: 'bg-severity-low-bg text-severity-low-text border-severity-low-border',
  INFO: 'bg-severity-info-bg text-severity-info-text border-severity-info-border',
}

import type { Severity } from '../../types/finding'

export function SeverityBadge({ severity, count }: { severity: Severity | string; count?: number }) {
  const s = severity.toUpperCase()
  const style = severityStyles[s] || severityStyles.INFO
  return (
    <span className={`badge border ${style}`}>
      {s}{count !== undefined ? ` (${count})` : ''}
    </span>
  )
}
