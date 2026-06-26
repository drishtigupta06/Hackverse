import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'
import type { FindingSummary } from '../../types/finding'

const severityColors: Record<string, string> = {
  CRITICAL: '#f87171',
  HIGH: '#fb923c',
  MEDIUM: '#60a5fa',
  LOW: '#4ade80',
  INFO: '#9ca3af',
}

export function SeverityChart({ summary }: { summary: FindingSummary | null }) {
  if (!summary) return null

  const data = Object.entries(summary.by_severity)
    .filter(([, count]) => count > 0)
    .map(([severity, count]) => ({
      name: severity,
      count,
      fill: severityColors[severity] || '#9ca3af',
    }))

  if (data.length === 0) return null

  return (
    <div className="card p-4">
      <h3 className="text-sm font-medium text-text-primary mb-3">Severity Distribution</h3>
      <ResponsiveContainer width="100%" height={160}>
        <BarChart data={data} layout="vertical">
          <XAxis type="number" hide />
          <YAxis dataKey="name" type="category" axisLine={false} tickLine={false} tick={{ fill: '#9ca3af', fontSize: 12 }} />
          <Tooltip
            contentStyle={{ background: '#1c1f27', border: '1px solid #2a2d36', borderRadius: 8, fontSize: 13 }}
            labelStyle={{ color: '#f0f0f0' }}
          />
          <Bar dataKey="count" radius={[0, 4, 4, 0]} barSize={20}>
            {data.map((entry, i) => (
              <Cell key={i} fill={entry.fill} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}
