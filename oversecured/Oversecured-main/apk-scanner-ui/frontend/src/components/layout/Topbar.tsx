import { useEffect, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { api } from '../../api/client'
import { Wifi, WifiOff, FlaskConical, Plus } from 'lucide-react'

function getBreadcrumb(pathname: string): string[] {
  const parts = pathname.split('/').filter(Boolean)
  if (parts.length === 0) return ['Dashboard']
  if (parts[0] === 'scans' && parts[1] && parts[1] !== 'new') return ['Scans', parts[1].slice(0, 8) + '...']
  return parts.map((p) => p.charAt(0).toUpperCase() + p.slice(1))
}

export function Topbar() {
  const location = useLocation()
  const navigate = useNavigate()
  const [adbStatus, setAdbStatus] = useState<'connected' | 'offline'>('offline')
  const [fridaStatus, setFridaStatus] = useState<'available' | 'unavailable'>('unavailable')
  const breadcrumb = getBreadcrumb(location.pathname)

  useEffect(() => {
    const checkAdb = async () => {
      try {
        const { data } = await api.get('/health/adb')
        setAdbStatus(data.status === 'connected' ? 'connected' : 'offline')
      } catch {
        setAdbStatus('offline')
      }
    }
    checkAdb()
    const interval = setInterval(checkAdb, 10000)
    return () => clearInterval(interval)
  }, [])

  useEffect(() => {
    const checkFrida = async () => {
      try {
        const { data } = await api.get('/health/frida')
        setFridaStatus(data.status === 'available' ? 'available' : 'unavailable')
      } catch {
        setFridaStatus('unavailable')
      }
    }
    checkFrida()
  }, [])

  return (
    <header className="h-14 min-h-[56px] bg-surface-card border-b border-border flex items-center justify-between px-6">
      <div className="flex items-center gap-2">
        {breadcrumb.map((crumb, i) => (
          <span key={crumb} className="text-sm text-text-secondary">
            {i > 0 && <span className="mx-1">/</span>}
            {crumb}
          </span>
        ))}
      </div>

      <div className="flex items-center gap-3">
        <StatusPill
          icon={adbStatus === 'connected' ? Wifi : WifiOff}
          label={`ADB ${adbStatus === 'connected' ? 'connected' : 'offline'}`}
          color={adbStatus === 'connected' ? 'text-green-400' : 'text-red-400'}
        />
        <StatusPill
          icon={FlaskConical}
          label={`Frida ${fridaStatus === 'available' ? 'available' : 'unavailable'}`}
          color={fridaStatus === 'available' ? 'text-green-400' : 'text-red-400'}
        />
        <button
          onClick={() => navigate('/scans/new')}
          className="btn-primary flex items-center gap-1.5 text-sm"
        >
          <Plus className="w-4 h-4" />
          New Scan
        </button>
      </div>
    </header>
  )
}

function StatusPill({
  icon: Icon,
  label,
  color,
}: {
  icon: React.ComponentType<{ className?: string }>
  label: string
  color: string
}) {
  return (
    <div className="flex items-center gap-1.5 px-2 py-1 rounded text-xs bg-surface border border-border">
      <Icon className={`w-3 h-3 ${color}`} />
      <span className="text-text-secondary">{label}</span>
    </div>
  )
}
