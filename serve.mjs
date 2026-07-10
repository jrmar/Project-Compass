import { createServer } from 'http';
import { readFile } from 'fs/promises';
import { extname, join } from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

const mime = {
  '.html': 'text/html',
  '.css':  'text/css',
  '.js':   'application/javascript',
  '.mjs':  'application/javascript',
  '.json': 'application/json',
  '.png':  'image/png',
  '.jpg':  'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg':  'image/svg+xml',
  '.ico':  'image/x-icon',
  '.pdf':  'application/pdf',
  '.csv':  'text/csv',
  '.woff2':'font/woff2',
  '.woff': 'font/woff',
};

const server = createServer(async (req, res) => {
  let url      = decodeURIComponent(req.url.split('?')[0]);
  let filePath = url === '/' ? '/index.html' : url;
  filePath     = join(__dirname, filePath);

  try {
    const data = await readFile(filePath);
    const ext  = extname(filePath).toLowerCase();
    res.writeHead(200, {
      'Content-Type':  mime[ext] || 'application/octet-stream',
      'Cache-Control': 'no-cache',
    });
    res.end(data);
  } catch {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('404 Not Found');
  }
});

server.listen(3000, () => {
  console.log('Compass dev server → http://localhost:3000');
  console.log('App  →  http://localhost:3000/app/login.html');
});
