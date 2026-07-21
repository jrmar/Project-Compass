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

// ── MDCA connection state (dev server — ephemeral per process) ────────────────
const mdcaSessions = new Map(); // tenantId → { connectedAt }

const MDCA_BASE = process.env.MDCA_API_URL
  || 'https://projectcompass722.us2.portal.cloudappsecurity.com';

async function pushMdcaTag(appDomain, mdcaTag) {
  const token = process.env.MDCA_API_TOKEN;
  if (!token) throw new Error('no_token');

  const hdrs = { Authorization: `Token ${token}`, 'Content-Type': 'application/json' };

  const searchResp = await fetch(
    `${MDCA_BASE}/cas/api/v1/discovery/app_catalog/?query=${encodeURIComponent(appDomain)}&limit=5`,
    { headers: hdrs }
  );
  if (!searchResp.ok) throw new Error(`catalog_${searchResp.status}`);

  const body = await searchResp.json();
  const apps = body.data ?? body.apps ?? (Array.isArray(body) ? body : []);
  if (!apps.length) return { pushed: false };

  const appId     = apps[0].appId ?? apps[0].app_id ?? apps[0].id;
  const tagNumMap = { sanctioned: 1, unsanctioned: 2, monitored: 3 };
  const tagNum    = tagNumMap[mdcaTag] ?? 1;

  const payloads = [
    { appId, tag: tagNum },
    { appId, add_tag: mdcaTag },
    { tag: tagNum, apps: [{ id: appId }] },
    { app_id: appId, tag: tagNum },
  ];

  for (const payload of payloads) {
    const r = await fetch(`${MDCA_BASE}/cas/api/v1/discovery/set_app_tags/`, {
      method: 'POST', headers: hdrs, body: JSON.stringify(payload),
    });
    const txt = await r.text().catch(() => '');
    console.log(`[mdca/tag] ${JSON.stringify(payload)} → ${r.status}: ${txt.slice(0, 120)}`);
    if (r.ok) return { pushed: true, app_id: appId };
  }
  throw new Error(`tag_api_${payloads.length}_attempts_failed`);
}

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

  // ── GET /auth/mdca/connect ──────────────────────────────────────────────────
  if (req.method === 'GET' && url === '/auth/mdca/connect') {
    const clientId    = process.env.MDCA_CLIENT_ID;
    const redirectUri = process.env.MDCA_REDIRECT_URI || 'http://localhost:3000/auth/mdca/callback';
    const params      = new URLSearchParams({ client_id: clientId, redirect_uri: redirectUri, state: Date.now().toString(36) });
    res.writeHead(302, { Location: `https://login.microsoftonline.com/common/adminconsent?${params}` });
    return res.end();
  }

  // ── GET /auth/mdca/callback ─────────────────────────────────────────────────
  if (req.method === 'GET' && url === '/auth/mdca/callback') {
    const qs      = req.url.includes('?') ? req.url.slice(req.url.indexOf('?') + 1) : '';
    const p       = new URLSearchParams(qs);
    const tenant  = p.get('tenant');
    const consent = p.get('admin_consent');
    const error   = p.get('error');
    const errDesc = p.get('error_description');

    if (error || !tenant || consent !== 'True') {
      const msg = encodeURIComponent(errDesc || error || 'Consent was not completed');
      res.writeHead(302, { Location: `/inventory?mdca_error=${msg}` });
      return res.end();
    }

    mdcaSessions.set(tenant, { connectedAt: new Date().toISOString() });
    res.writeHead(302, {
      Location:     '/inventory?mdca=connected',
      'Set-Cookie': `mdca_tid=${tenant}; HttpOnly; SameSite=Lax; Max-Age=604800; Path=/`,
    });
    return res.end();
  }

  // ── GET /api/mdca/status ────────────────────────────────────────────────────
  if (req.method === 'GET' && url === '/api/mdca/status') {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Access-Control-Allow-Origin', '*');
    const cookie = req.headers.cookie || '';
    const match  = cookie.match(/mdca_tid=([a-f0-9-]{36})/i);
    const tid    = match ? match[1] : null;
    res.writeHead(200);
    return res.end(JSON.stringify({ connected: !!tid, tenant_id: tid }));
  }

  // ── POST /api/mdca/disconnect ───────────────────────────────────────────────
  if (req.method === 'POST' && url === '/api/mdca/disconnect') {
    const { default: disconnectHandler } = await import('./api/mdca/disconnect.js');
    return disconnectHandler(req, res);
  }

  // ── POST /api/mdca/upload ───────────────────────────────────────────────────
  if (req.method === 'POST' && url === '/api/mdca/upload') {
    const { default: uploadHandler } = await import('./api/mdca/upload.js');
    return uploadHandler(req, res);
  }

  // ── POST /api/mdca/tag ──────────────────────────────────────────────────────
  if (req.method === 'POST' && url === '/api/mdca/tag') {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Access-Control-Allow-Origin', '*');
    const cookie = req.headers.cookie || '';
    const match  = cookie.match(/mdca_tid=([a-f0-9-]{36})/i);
    const tid    = match ? match[1] : null;

    if (!tid) {
      res.writeHead(401);
      return res.end(JSON.stringify({ error: 'Microsoft 365 not connected' }));
    }

    try {
      const body    = await readBody(req);
      const { app_domain, app_name, tag } = body;
      if (!app_domain || !tag) {
        res.writeHead(400);
        return res.end(JSON.stringify({ error: 'Missing app_domain or tag' }));
      }

      const tagMap  = { approved: 'sanctioned', review: 'monitored', blocked: 'unsanctioned' };
      const mdcaTag = tagMap[tag] || tag;
      const label   = app_name || app_domain;

      let live = false;
      let message;
      try {
        const result = await pushMdcaTag(app_domain, mdcaTag);
        if (result.pushed) {
          live    = true;
          message = `${label} tagged as "${mdcaTag}" in Microsoft Defender for Cloud Apps`;
        } else {
          message = `${label} policy saved — app not yet in Cloud Discovery (upload traffic logs to surface it)`;
        }
      } catch (e) {
        const code = e.message;
        console.warn('[/api/mdca/tag]', code);
        if (code === 'no_token') {
          message = `Policy saved locally — add MDCA_API_TOKEN to .env to push live tags`;
        } else if (code.startsWith('tag_api_')) {
          const status = code.replace('tag_api_', '');
          message = `${label} tagged as "${mdcaTag}" in Compass — MDCA returned ${status} (check server logs)`;
        } else {
          message = `${label} tagged as "${mdcaTag}" in Compass — MDCA sync error: ${code}`;
        }
      }

      res.writeHead(200);
      return res.end(JSON.stringify({ success: true, tag: mdcaTag, app: label, tenant_id: tid, live, message }));
    } catch (err) {
      console.error('[/api/mdca/tag]', err.message);
      res.writeHead(500);
      return res.end(JSON.stringify({ error: err.message }));
    }
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
    '/executive':     '/app/use-case-executive.html',
    '/security-team': '/app/use-case-security.html',
    '/auditor':       '/app/use-case-auditor.html',
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
