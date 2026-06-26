import { create } from 'zustand'

export interface Toast {
  id: number
  type: 'success' | 'error' | 'info' | 'warning'
  message: string
}

interface ToastStore {
  toasts: Toast[]
  addToast: (type: Toast['type'], message: string) => void
  removeToast: (id: number) => void
}

let nextId = 1

export const useToastStore = create<ToastStore>((set) => ({
  toasts: [],
  addToast: (type, message) => {
    const id = nextId++
    set((s) => ({ toasts: [...s.toasts, { id, type, message }] }))
    setTimeout(() => {
      set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) }))
    }, 4000)
  },
  removeToast: (id) => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })),
}))
