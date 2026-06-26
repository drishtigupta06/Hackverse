import type { ComponentType } from 'react'

export function KpiCard({
  icon: Icon,
  label,
  value,
  color,
}: {
  icon: ComponentType<{ className?: string }>
  label: string
  value: number | string
  color?: string
}) {
  return (
    <div className="card p-4 flex items-center gap-3">
      <div className={`p-2 rounded-lg bg-surface ${color || 'text-accent'}`}>
        <Icon className="w-5 h-5" />
      </div>
      <div>
        <div className={`text-2xl font-medium ${color || 'text-text-primary'}`}>{value}</div>
        <div className="text-xs text-text-secondary">{label}</div>
      </div>
    </div>
  )
}
