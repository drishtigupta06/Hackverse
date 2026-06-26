import { Routes, Route, Link } from 'react-router-dom'
import { DashboardPage } from './pages/DashboardPage'
import { NewScanPage } from './pages/NewScanPage'
import { ScanDetailPage } from './pages/ScanDetailPage'
import { AllScansPage } from './pages/AllScansPage'
import { FindingsPage } from './pages/FindingsPage'
import { ChainsPage } from './pages/ChainsPage'
import { ReportsPage } from './pages/ReportsPage'
import { SettingsPage } from './pages/SettingsPage'
import { AppsPage } from './pages/AppsPage'
import { CveBrowserPage } from './pages/CveBrowserPage'

function NotFound() {
  return (
    <div className="flex flex-col items-center justify-center h-[60vh] gap-4">
      <h1 className="text-2xl font-medium text-text-primary">404</h1>
      <p className="text-text-secondary">Page not found</p>
      <Link to="/" className="btn-primary text-sm">Go Home</Link>
    </div>
  )
}

export function AppRouter() {
  return (
    <Routes>
      <Route path="/" element={<DashboardPage />} />
      <Route path="/scans/new" element={<NewScanPage />} />
      <Route path="/scans" element={<AllScansPage />} />
      <Route path="/scans/:scanId" element={<ScanDetailPage />} />
      <Route path="/findings" element={<FindingsPage />} />
      <Route path="/chains" element={<ChainsPage />} />
      <Route path="/reports" element={<ReportsPage />} />
      <Route path="/settings" element={<SettingsPage />} />
      <Route path="/apps" element={<AppsPage />} />
      <Route path="/cves" element={<CveBrowserPage />} />
      <Route path="*" element={<NotFound />} />
    </Routes>
  )
}
