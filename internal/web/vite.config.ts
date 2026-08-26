import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'

const api = process.env.SUBIDX_API ?? 'http://127.0.0.1:8080'

export default defineConfig({
  plugins: [svelte()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
  server: {
    proxy: {
      '/v1': api,
    },
  },
})
