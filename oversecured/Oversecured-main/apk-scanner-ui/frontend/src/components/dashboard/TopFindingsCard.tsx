import type { FindingSummary } from '../../types/finding'

export function TopFindingsCard({ summary }: { summary: FindingSummary | null }) {
  if (!summary) return null

  const topRules = Object.entries(summary.by_rule_group)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 5)

  if (topRules.length === 0) return null

  return (
    <div className="card p-4">
      <h3 className="text-sm font-medium text-text-primary mb-3">Top Rule Groups</h3>
      <div className="space-y-2">
        {topRules.map(([group, count]) => (
          <div key={group} className="flex items-center justify-between">
            <span className="text-sm text-text-secondary">{group}</span>
            <span className="badge bg-surface-secondary text-text-secondary border border-border">
              {count}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}
