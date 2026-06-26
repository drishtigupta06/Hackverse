import { Copy, Check } from 'lucide-react'
import { useState } from 'react'

export function PoCBlock({ command, vector }: { command?: string; vector?: string }) {
  const [copied, setCopied] = useState(false)

  if (!command) return null

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(command)
    } catch {
      return
    }
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="bg-[#0d0f14] rounded-lg overflow-hidden">
      <div className="flex items-center justify-between px-3 py-1.5 bg-surface-secondary border-b border-border">
        <span className="text-xs font-medium text-accent uppercase">{vector || 'COMMAND'}</span>
        <button onClick={handleCopy} className="text-text-tertiary hover:text-text-primary transition-colors">
          {copied ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
        </button>
      </div>
      <pre className="p-3 text-xs text-text-secondary font-mono overflow-x-auto whitespace-pre-wrap break-all">
        {command}
      </pre>
    </div>
  )
}
