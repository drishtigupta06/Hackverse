import { api } from './client'
import type { AppInfo, AppListResponse } from '../types/config'

export async function uploadApk(file: File): Promise<AppInfo> {
  const form = new FormData()
  form.append('file', file)
  const { data } = await api.post<AppInfo>('/apps/upload', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
    timeout: 120000,
  })
  return data
}

export async function listApps(): Promise<AppListResponse> {
  const { data } = await api.get<AppListResponse>('/apps')
  return data
}

export async function getApp(id: string): Promise<AppInfo> {
  const { data } = await api.get<AppInfo>(`/apps/${id}`)
  return data
}

export async function deleteApp(id: string): Promise<void> {
  await api.delete(`/apps/${id}`)
}
