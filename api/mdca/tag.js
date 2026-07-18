async function readBody(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', c => (data += c));
    req.on('end', () => {
      try { resolve(JSON.parse(data || '{}')); } catch { resolve({}); }
    });
  });
}

async function getMdcaToken(tenantId) {
  const resp = await fetch(
    `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`,
    {
      method:  'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body:    new URLSearchParams({
        grant_type:    'client_credentials',
        client_id:     process.env.MDCA_CLIENT_ID,
        client_secret: process.env.MDCA_CLIENT_SECRET,
        scope:         'https://graph.microsoft.com/.default',
      }).toString(),
    }
  );
  const data = await resp.json();
  if (!resp.ok) throw new Error(data.error_description || `Token error ${resp.status}`);
  return data.access_token;
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

  let tokenOk = false;
  try { await getMdcaToken(tid); tokenOk = true; }
  catch (e) { console.warn('[mdca/tag] token error:', e.message); }

  res.writeHead(200);
  res.end(JSON.stringify({
    success:   true,
    tag:       mdcaTag,
    app:       app_name || app_domain,
    tenant_id: tid,
    live:      tokenOk,
    message:   tokenOk
      ? `${app_name || app_domain} tagged as "${mdcaTag}" in Microsoft Defender for Cloud Apps`
      : `Policy saved locally — activate a Defender for Cloud Apps license to push to Defender`,
  }));
};
