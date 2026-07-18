import { createServer } from 'http';
import { readFile, readFile as rf } from 'fs/promises';
import { readFileSync, existsSync } from 'fs';
import { extname, join } from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

// ── Load .env file (never committed) ──────────────────────────────────────────
function loadEnv() {
  const envPath = join(__dirname, '.env');
  if (!existsSync(envPath)) return;
  const lines = readFileSync(envPath, 'utf8').split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx < 0) continue;
    const key = trimmed.slice(0, eqIdx).trim();
    const val = trimmed.slice(eqIdx + 1).trim().replace(/^["']|["']$/g, '');
    if (!process.env[key]) process.env[key] = val;
  }
}
loadEnv();

// ── Read POST body ─────────────────────────────────────────────────────────────
function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try { resolve(JSON.parse(body || '{}')); }
      catch { resolve({}); }
    });
    req.on('error', reject);
  });
}

// ── Anthropic API call ─────────────────────────────────────────────────────────
async function callClaude(controlId, controlName, status, findingText) {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    throw new Error('ANTHROPIC_API_KEY not set in .env');
  }

  const userPrompt =
    `NIST AI RMF Control: ${controlId} — ${controlName}\n` +
    `Status: ${status}\n` +
    `Finding: ${findingText}\n\n` +
    `In 2-3 sentences, explain what this gap means for the organization in plain language. ` +
    `Then provide exactly 3 concrete next steps (numbered list) to address it. ` +
    `Keep the entire response under 200 words.`;

  const resp = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'x-api-key':         apiKey,
      'anthropic-version': '2023-06-01',
      'content-type':      'application/json',
    },
    body: JSON.stringify({
      model:      'claude-haiku-4-5-20251001',
      max_tokens: 400,
      system:     'You are a concise NIST AI RMF compliance advisor helping security and compliance professionals understand governance gaps and fix them. Never mention the organization name. Never add disclaimers. Be direct and actionable.',
      messages:   [{ role: 'user', content: userPrompt }],
    }),
  });

  if (!resp.ok) {
    const errText = await resp.text();
    throw new Error(`Anthropic API error ${resp.status}: ${errText}`);
  }

  const json = await resp.json();
  return json.content?.[0]?.text || 'No explanation returned.';
}

// ── MIME types ────────────────────────────────────────────────────────────────
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

// ── Server ────────────────────────────────────────────────────────────────────
const server = createServer(async (req, res) => {
  const url = decodeURIComponent(req.url.split('?')[0]);

  // ── POST /api/explain ──────────────────────────────────────────────────────
  if (req.method === 'POST' && url === '/api/explain') {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Access-Control-Allow-Origin', '*');
    try {
      const body = await readBody(req);
      const { control_id, control_name, status, finding_text } = body;

      if (!control_id || !finding_text) {
        res.writeHead(400);
        return res.end(JSON.stringify({ error: 'Missing control_id or finding_text' }));
      }

      const explanation = await callClaude(control_id, control_name || control_id, status || 'GAP', finding_text);
      res.writeHead(200);
      res.end(JSON.stringify({ explanation }));
    } catch (err) {
      console.error('[/api/explain]', err.message);
      res.writeHead(500);
      res.end(JSON.stringify({ error: err.message }));
    }
    return;
  }

  // ── OPTIONS preflight ──────────────────────────────────────────────────────
  if (req.method === 'OPTIONS') {
    res.writeHead(204, { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET,POST', 'Access-Control-Allow-Headers': 'Content-Type' });
    return res.end();
  }

  // ── Clean URL rewrites (mirrors vercel.json) ───────────────────────────────
  const CLEAN_URLS = {
    '/login':         '/app/login.html',
    '/dashboard':     '/app/dashboard.html',
    '/compliance':    '/app/compliance.html',
    '/governance':    '/app/compass-governance.html',
    '/inventory':     '/app/inventory.html',
    '/report':        '/app/report.html',
    '/about':         '/app/info.html',
    '/news':          '/app/news.html',
    '/assess':        '/app/assess.html',
    '/detect':        '/app/detect.html',
    '/upload':        '/app/upload.html',
    '/scanning':      '/app/scanning.html',
    '/sample-report': '/app/sample-report.html',
  };
  const rewritten = CLEAN_URLS[url];

  // ── Static files ───────────────────────────────────────────────────────────
  let filePath = rewritten || (url === '/' ? '/index.html' : url);
  filePath = join(__dirname, filePath);

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
  console.log('API  →  POST http://localhost:3000/api/explain');
  if (!process.env.ANTHROPIC_API_KEY) {
    console.warn('⚠  ANTHROPIC_API_KEY not set — add it to .env to enable AI explanations');
  } else {
    console.log('✓  ANTHROPIC_API_KEY loaded');
  }
});
