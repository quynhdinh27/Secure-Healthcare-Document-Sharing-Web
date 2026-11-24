// Chạy kịch bản e2e (mock server + module crypto thật) trong Node: npm run test:e2e
import { build } from 'esbuild';
import { pathToFileURL } from 'node:url';
const out = 'test-e2e/.out.mjs';
await build({
  entryPoints: ['test-e2e/e2e.mjs'], bundle: true, platform: 'node', format: 'esm', outfile: out, logLevel: 'error',
  define: { 'import.meta.env.VITE_USE_MOCK': '"true"', 'import.meta.env.VITE_API_BASE': '"/api/v1"', 'import.meta.env.VITE_CSRF_HEADER': '"X-CSRF-Token"' },
});
await import(pathToFileURL(out).href);
