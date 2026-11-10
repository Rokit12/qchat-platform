// Builds preview/qchat-preview.html: one self-contained page (app + in-page server + demo contacts).
import { build } from 'esbuild';
import fs from 'node:fs';
const r = await build({ entryPoints: ['src/preview/main.js'], bundle: true, minify: true, format: 'esm', target: 'es2022', write: false });
let js = r.outputFiles[0].text.replace(/<\/script/gi, '<\\/script').replace(/['"]icon\.svg['"]/g, JSON.stringify(''));
const icon = 'data:image/svg+xml;base64,' + fs.readFileSync('public/icon.svg').toString('base64');
const css = fs.readFileSync('public/style.css', 'utf8') + `
.preview-pill { position: fixed; left: 12px; bottom: 12px; z-index: 40; background: rgba(34,26,54,.96); border: 1px solid var(--accent); color: var(--muted); font-size: 12px; line-height: 1.4; padding: 6px 12px; border-radius: 12px; max-width: 356px; pointer-events: none; }
.preview-pill b { color: var(--accent); }
@media (max-width: 760px) { .preview-pill { right: 12px; max-width: none; font-size: 11px; } .app.in-chat ~ .preview-pill { display: none; } }`;
let html = fs.readFileSync('public/index.html', 'utf8')
  .replace('<link rel="manifest" href="manifest.webmanifest" />', '')
  .replace('<link rel="stylesheet" href="style.css" />', `<style>${css}</style>`)
  .replace('<script type="module" src="app.js"></script>', () => `<script type="module">${js}</script>`)
  .replace(/(src|href)="icon\.svg"/g, `$1="${icon}"`)
  .replace('<title>QChat — post-quantum private messenger</title>', '<title>QChat preview</title>');
fs.mkdirSync('preview', { recursive: true });
fs.writeFileSync('preview/qchat-preview.html', html);
console.log('preview/qchat-preview.html', (html.length / 1024).toFixed(0) + ' KB');
