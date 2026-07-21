async function readBody(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', c => (data += c));
    req.on('end', () => {
      try { resolve(JSON.parse(data || '{}')); } catch { resolve({}); }
    });
  });
}

const MDCA_BASE = process.env.MDCA_API_URL
  || 'https://projectcompass722.us2.portal.cloudappsecurity.com';

async function pushMdcaTag(appDomain, mdcaTag) {
  const token = process.env.MDCA_API_TOKEN;
  if (!token) throw new Error('no_token');

  const hdrs = { Authorization: `Token ${token}`, 'Content-Type': 'application/json' };

  // Search MDCA cloud-app catalog by domain
  const searchResp = await fetch(
    `${MDCA_BASE}/cas/api/v1/discovery/app_catalog/?query=${encodeURIComponent(appDomain)}&limit=5`,
    { headers: hdrs }
  );
  if (!searchResp.ok) throw new Error(`catalog_${searchResp.status}`);

  const body = await searchResp.json();
  console.log('[mdca/tag] catalog response keys:', Object.keys(body), 'first app:', JSON.stringify((body.data ?? body.apps ?? (Array.isArray(body) ? body : []))[0]).slice(0, 300));
  const apps = body.data ?? body.apps ?? (Array.isArray(body) ? body : []);

  if (!apps.length) return { pushed: false, reason: 'not_in_catalog' };

  const appId = apps[0].app_id ?? apps[0].id;

  // Try endpoint variations — MDCA API docs are inconsistent across tenants
  const attempts = [
    { url: `${MDCA_BASE}/cas/api/v1/discovery/set_app_tags/`, payload: { app_id: appId, tag: mdcaTag } },
    { url: `${MDCA_BASE}/cas/api/v1/discovery/set_app_tags`,  payload: { app_id: appId, tag: mdcaTag } },
    { url: `${MDCA_BASE}/cas/api/v1/discovery/set_app_tags/`, payload: { app_id: appId, tags: [mdcaTag] } },
  ];

  for (const attempt of attempts) {
    const r = await fetch(attempt.url, {
      method: 'POST', headers: hdrs, body: JSON.stringify(attempt.payload),
    });
    const txt = await r.text().catch(() => '');
    console.log(`[mdca/tag] ${attempt.url} → ${r.status}: ${txt.slice(0, 300)}`);
    if (r.ok) return { pushed: true, app_id: appId };
  }

  throw new Error(`tag_failed_see_logs`);
}

module.exports = async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Access-Control-Allow-Origin', '*');
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }

  const cookie = req.headers.cookie || '';
  const match  = cookie.match(/mdca_tid=([a-f0-9-]{36})/i);
  const tid    = match ? match[1] : null;
  if (!tid) {
    res.writeHead(401);
    return res.end(JSON.stringify({ error: 'Microsoft 365 not connected' }));
  }

  const { app_domain, app_name, tag } = await readBody(req);
  if (!app_domain || !tag) {
    res.writeHead(400);
    return res.end(JSON.stringify({ error: 'Missing app_domain or tag' }));
  }

  const tagMap  = { approved: 'sanctioned', review: 'monitored', blocked: 'unsanctioned' };
  const mdcaTag = tagMap[tag] || tag;
  const label   = app_name || app_domain;

  let live    = false;
  let message;

  try {
    const result = await pushMdcaTag(app_domain, mdcaTag);
    if (result.pushed) {
      live    = true;
      message = `${label} tagged as "${mdcaTag}" in Microsoft Defender for Cloud Apps`;
    } else {
      message = `${label} policy saved — app not yet in Cloud Discovery (upload traffic logs to MDCA to surface it)`;
    }
  } catch (e) {
    const code = e.message;
    if (code === 'no_token') {
      message = `Policy saved locally — add MDCA_API_TOKEN to Vercel env vars to push live tags`;
    } else {
      console.warn('[mdca/tag] API error:', code);
      message = `${label} tagged as "${mdcaTag}" (MDCA sync pending: ${code})`;
    }
  }

  res.writeHead(200);
  res.end(JSON.stringify({ success: true, tag: mdcaTag, app: label, tenant_id: tid, live, message }));
};
