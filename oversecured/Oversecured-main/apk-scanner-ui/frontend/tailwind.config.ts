import type { Config } from 'tailwindcss'

export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        surface: {
          DEFAULT: '#0f1117',
          secondary: '#16181f',
          card: '#1c1f27',
        },
        border: {
          DEFAULT: '#2a2d36',
          hover: '#3a3d4a',
        },
        text: {
          primary: '#f0f0f0',
          secondary: '#9ca3af',
          tertiary: '#6b7280',
        },
        accent: {
          DEFAULT: '#6c5dd3',
          hover: '#7c6de3',
        },
        severity: {
          critical: { bg: '#3d1515', text: '#f87171', border: '#7f1d1d' },
          high: { bg: '#3d2800', text: '#fb923c', border: '#7c2d12' },
          medium: { bg: '#1a2d40', text: '#60a5fa', border: '#1e3a5f' },
          low: { bg: '#1a2e1a', text: '#4ade80', border: '#14532d' },
          info: { bg: '#1f2028', text: '#9ca3af', border: '#374151' },
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      fontSize: {
        base: '14px',
      },
    },
  },
  plugins: [],
} satisfies Config
