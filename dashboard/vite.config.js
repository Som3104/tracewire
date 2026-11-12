import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { viteSingleFile } from 'vite-plugin-singlefile'

// `npm run build:single` inlines JS, CSS, fonts and data into one portable HTML file
export default defineConfig(({ mode }) => ({
  plugins: [react(), ...(mode === 'single' ? [viteSingleFile()] : [])],
  build: { assetsInlineLimit: mode === 'single' ? 100_000_000 : 4096 },
}))
