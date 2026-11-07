import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// In development the browser talks only to Vite (5173); /api and /ws are proxied to the backend,
// so there is no CORS and no hard-coded backend URL in the code.
const backend = process.env.VITE_BACKEND || 'http://localhost:8000'

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': { target: backend, changeOrigin: true },
      '/ws': { target: backend.replace(/^http/, 'ws'), ws: true, changeOrigin: true },
    },
  },
})
