import { build } from 'esbuild';
const common = { bundle: true, minify: true, target: 'es2022', sourcemap: false, logLevel: 'warning' };
await Promise.all([
  build({ ...common, entryPoints: ['src/client/app.js'], format: 'esm', outfile: 'public/app.js' }),
  build({ ...common, entryPoints: ['src/client/e2ee-worker.js'], format: 'iife', outfile: 'public/e2ee-worker.js' }),
  build({ ...common, entryPoints: ['src/client/sw.js'], format: 'iife', outfile: 'public/sw.js' }),
]);
console.log('Built public/app.js, public/e2ee-worker.js, public/sw.js');
