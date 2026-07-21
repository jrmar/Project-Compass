/**
 * POST /api/mdca/upload
 * Receives a log file from Compass and pushes it to MDCA Cloud Discovery.
 * Requires mdca_tid cookie (set by /auth/mdca/callback).
 *
 * Body (JSON): { file_content: string (base64 dataURL or raw text),
 *               file_name: string,
 *               log_type: 'dns' | 'proxy' | 'firewall' | 'watchguard' }
 *
 * MDCA Cloud Discovery 3-step upload:
 *   1. POST /cas/api/v1/discovery/upload_url/  → { url, contentType }
 *   2. PUT  <url>                               (raw log bytes)
 *   3. POST /cas/api/v1/discovery/done_uploading/  { uploadUrl: url }
 */

const MDCA_BASE = process.env.MDCA_API_URL
  || 'https://projectcompass722.us2.portal.cloudappsecurity.com';

// Approximate MDCA log-type IDs.
// Squid native (17) is closest for proxy/DNS; use for all types in demo.
const MDCA_LOG_TYPE = {
  proxy:      17,  // Squid Native
  dns:        17,
  firewall:   17,
  watchguard: 17,
};

async function readBody(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', c => (data += c));
    req.on('end', () => {
      try { resolve(JSON.parse(data || '{}')); } catch { resolve({}); }
    });
  });
}

function decodeFileContent(raw) {
  if (!raw) return Buffer.from('');
  // Handle base64 dataURL (data:text/csv;base64,...)
  if (raw.startsWith('data:')) {
    const idx = raw.indexOf(',');
    if (idx !== -1) {
      const b64 = raw.slice(idx + 1);
      return Buffer.from(b64, 'base64');
    }
  }
  // Plain text
  return Buffer.from(raw, 'utf8');
}

module.exports = async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Access-Control-Allow-Origin', '*');
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }
  if (req.method !== 'POST') {
    res.writeHead(405);
    return res.end(JSON.stringify({ error: 'Method not allowed' }));
  }

  // Require M365 connection (cookie)
  const cookie = req.headers.cookie || '';
  const match  = cookie.match(/mdca_tid=([a-f0-9-]{36})/i);
  if (!match) {
    res.writeHead(401);
    return res.end(JSON.stringify({ error: 'Microsoft 365 not connected' }));
  }

  const token = process.env.MDCA_API_TOKEN;
  if (!token) {
    res.writeHead(503);
    return res.end(JSON.stringify({ error: 'MDCA_API_TOKEN not configured' }));
  }

  const body = await readBody(req);
  const { file_content, file_name = 'compass_log.csv', log_type = 'proxy' } = body;

  if (!file_content) {
    res.writeHead(400);
    return res.end(JSON.stringify({ error: 'file_content required' }));
  }

  const fileBuffer = decodeFileContent(file_content);
  const logTypeId  = MDCA_LOG_TYPE[log_type] || 17;
  const hdrs       = { Authorization: `Token ${token}`, 'Content-Type': 'application/json' };

  try {
    // Step 1: Request upload URL from MDCA
    const step1 = await fetch(`${MDCA_BASE}/cas/api/v1/discovery/upload_url/`, {
      method:  'POST',
      headers: hdrs,
      body:    JSON.stringify({ filename: file_name, logType: logTypeId }),
    });

    const step1Text = await step1.text();
    console.log(`[mdca/upload] step1 ${step1.status}: ${step1Text.slice(0, 300)}`);

    if (!step1.ok) {
      const isHtml = step1Text.startsWith('<!');
      res.writeHead(200);
      return res.end(JSON.stringify({
        success: false,
        stage:   'get_upload_url',
        status:  step1.status,
        reason:  isHtml ? 'License limitation — Cloud Discovery upload requires Defender for Cloud Apps' : step1Text,
      }));
    }

    let step1Json;
    try { step1Json = JSON.parse(step1Text); } catch {
      res.writeHead(200);
      return res.end(JSON.stringify({ success: false, stage: 'parse_url_response', reason: step1Text }));
    }

    const uploadUrl = step1Json.url || step1Json.uploadUrl;
    if (!uploadUrl) {
      res.writeHead(200);
      return res.end(JSON.stringify({ success: false, stage: 'no_upload_url', response: step1Json }));
    }

    // Step 2: PUT the log file to the blob URL
    const step2 = await fetch(uploadUrl, {
      method:  'PUT',
      headers: {
        'Content-Type':    'text/plain',
        'x-ms-blob-type':  'BlockBlob',
        'Content-Length':  String(fileBuffer.length),
      },
      body: fileBuffer,
    });

    console.log(`[mdca/upload] step2 (PUT file) ${step2.status}`);

    if (!step2.ok) {
      res.writeHead(200);
      return res.end(JSON.stringify({
        success: false,
        stage:   'put_file',
        status:  step2.status,
        reason:  await step2.text().catch(() => ''),
      }));
    }

    // Step 3: Notify MDCA that upload is complete
    const step3 = await fetch(`${MDCA_BASE}/cas/api/v1/discovery/done_uploading/`, {
      method:  'POST',
      headers: hdrs,
      body:    JSON.stringify({ uploadUrl }),
    });

    const step3Text = await step3.text();
    console.log(`[mdca/upload] step3 ${step3.status}: ${step3Text.slice(0, 200)}`);

    res.writeHead(200);
    res.end(JSON.stringify({
      success:    step3.ok,
      stage:      'complete',
      file_name,
      log_type,
      bytes:      fileBuffer.length,
      upload_url: uploadUrl.slice(0, 80) + '...',
    }));

  } catch (err) {
    console.error('[mdca/upload]', err.message);
    res.writeHead(200);
    res.end(JSON.stringify({ success: false, stage: 'network_error', reason: err.message }));
  }
};
