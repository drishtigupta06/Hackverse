import { NavLink } from 'react-router-dom'
import { Shield, Upload, List, AlertTriangle, Link, FileText, Settings, LayoutDashboard, Package, Bug } from 'lucide-react'

const navItems = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/scans/new', icon: Upload, label: 'New Scan' },
  { to: '/apps', icon: Package, label: 'Apps' },
  { to: '/scans', icon: List, label: 'All Scans' },
  { to: '/findings', icon: AlertTriangle, label: 'Findings' },
  { to: '/chains', icon: Link, label: 'Exploit Chains' },
  { to: '/cves', icon: Bug, label: 'CVEs' },
  { to: '/reports', icon: FileText, label: 'Reports' },
  { to: '/settings', icon: Settings, label: 'Settings' },
]

export function Sidebar() {
  return (
    <aside className="w-[200px] min-w-[200px] bg-surface-secondary flex flex-col border-r border-border">
      <div className="flex items-center gap-2 px-4 h-14 border-b border-border">
        <Shield className="w-6 h-6 text-accent" />
        <span className="font-medium text-text-primary">APK Scanner</span>
      </div>

      <nav className="flex-1 py-2 overflow-y-auto">
        {navItems.map((item) => (
          <NavLink
            key={item.to + item.label}
            to={item.to}
            end={item.to === '/'}
            className={({ isActive }) =>
              `flex items-center gap-3 px-4 py-2.5 text-sm transition-colors ${
                isActive
                  ? 'bg-accent/10 text-accent border-r-2 border-accent'
                  : 'text-text-secondary hover:text-text-primary hover:bg-surface-card'
              }`
            }
          >
            <item.icon className="w-4 h-4" />
            {item.label}
          </NavLink>
        ))}
      </nav>

      <div className="px-4 py-3 border-t border-border">
        <div className="text-xs text-text-tertiary">v1.1.0</div>
      </div>
    </aside>
  )
}
