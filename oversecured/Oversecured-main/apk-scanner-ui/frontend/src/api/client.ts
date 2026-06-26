import axios from 'axios'

const API_BASE = '/api/v1'
const WS_BASE = `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/ws`

export const api = axios.create({
  baseURL: API_BASE,
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
})

export function getWsUrl(path: string): string {
  return `${WS_BASE}${path}`
}
