import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vite'

const root = dirname(fileURLToPath(import.meta.url))

export default defineConfig({
  resolve: {
    // did-jwt-eip712-signer carries its own (older, github-pinned) did-jwt copy in
    // its node_modules; without dedupe Vite pre-bundles that one, which lacks
    // CompositeSigner/CompositeVerifier. Force every did-jwt import to the demo's
    // root copy — the live local fork.
    dedupe: ['did-jwt'],
  },
  build: {
    rollupOptions: {
      input: resolve(root, 'index.html'),
    },
  },
})
