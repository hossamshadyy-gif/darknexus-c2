/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,jsx}",
  ],
  theme: {
    extend: {
      colors: {
        nexus: {
          50:  '#f0f4ff',
          100: '#e0e8ff',
          200: '#c0d0ff',
          300: '#8ba8ff',
          400: '#5c7cff',
          500: '#3b52ff',
          600: '#2835f5',
          700: '#1f25d8',
          800: '#1d20af',
          900: '#1e2189',
          950: '#0a0c2e',
        },
        surface: {
          0:   '#09090b',
          1:   '#111113',
          2:   '#18181b',
          3:   '#1f1f23',
          4:   '#27272a',
        },
        accent: {
          green:  '#22c55e',
          red:    '#ef4444',
          amber:  '#f59e0b',
          cyan:   '#06b6d4',
          purple: '#a855f7',
        },
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', '"Fira Code"', 'monospace'],
      },
    },
  },
  plugins: [],
}
