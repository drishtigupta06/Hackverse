import { create } from 'zustand'
import type { Scan } from '../types/scan'
import type { Finding, FindingSummary } from '../types/finding'
import type { AppInfo } from '../types/config'

interface ScanStore {
  scans: Scan[]
  currentScan: Scan | null
  findings: Finding[]
  findingSummary: FindingSummary | null
  apps: AppInfo[]
  setScans: (scans: Scan[]) => void
  setCurrentScan: (scan: Scan | null) => void
  setFindings: (findings: Finding[]) => void
  setFindingSummary: (summary: FindingSummary | null) => void
  setApps: (apps: AppInfo[]) => void
  addScan: (scan: Scan) => void
  updateScan: (id: string, updates: Partial<Scan>) => void
  addApp: (app: AppInfo) => void
}

export const useScanStore = create<ScanStore>((set) => ({
  scans: [],
  currentScan: null,
  findings: [],
  findingSummary: null,
  apps: [],
  setScans: (scans) => set({ scans }),
  setCurrentScan: (scan) => set({ currentScan: scan }),
  setFindings: (findings) => set({ findings }),
  setFindingSummary: (summary) => set({ findingSummary: summary }),
  setApps: (apps) => set({ apps }),
  addScan: (scan) => set((state) => ({ scans: [scan, ...state.scans] })),
  updateScan: (id, updates) =>
    set((state) => ({
      scans: state.scans.map((s) => (s.id === id ? { ...s, ...updates } : s)),
      currentScan:
        state.currentScan?.id === id
          ? { ...state.currentScan, ...updates }
          : state.currentScan,
    })),
  addApp: (app) => set((state) => ({ apps: [app, ...state.apps] })),
}))
