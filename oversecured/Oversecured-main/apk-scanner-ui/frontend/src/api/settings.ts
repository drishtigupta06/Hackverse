import { api } from './client'

export interface Settings {
  scannerPath: string
  jadxPath: string
  adbPath: string
  fridaPath: string
  fridaServerPath: string
  emulatorPath: string
  ollamaUrl: string
  defaultScanMode: string
  defaultFridaTimeout: number
}

export async function getSettings(): Promise<Settings> {
  const { data } = await api.get<Settings>('/settings')
  return data
}

export async function updateSettings(settings: Settings): Promise<void> {
  await api.put('/settings', settings)
}
