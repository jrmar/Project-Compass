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

async function findMdcaAppId(hdrs, appDomain, appName) {
  const nameLower   = (appName  || '').toLowerCase();
  const domainLower = appDomain.toLowerCase().replace(/^www\./, '');

  function scoreApps(apps) {
    return apps.find(a => {
      const aName = (a.name ?? a.appName ?? '').toLowerCase();
      const aUrl  = (a.url  ?? a.domain  ?? a.appUrl ?? '').toLowerCase().replace(/^www\./, '');
      const nameMatch   = nameLower   && aName && (aName.includes(nameLower)   || nameLower.includes(aName));
      const domainMatch = domainLower && aUrl  && (aUrl.includes(domainLower)  || domainLower.includes(aUrl));
      return nameMatch || domainMatch;
    });
  }

  // Strategy 1: catalog with MDCA filter format (the ?query= param is ignored by this tenant)
  const filtersParam = encodeURIComponent(JSON.stringify({ name: { contains: appName || appDomain } }));
  const cat1 = await fetch(`${MDCA_BASE}/cas/api/v1/discovery/app_catalog/?filters=${filtersParam}&limit=10`, { headers: hdrs });
  if (cat1.ok) {
    const body = await cat1.json();
    const apps = body.data ?? body.apps ?? (Array.isArray(body) ? body : []);
    console.log(`[mdca/tag] catalog filter results (${apps.length}):`, apps.slice(0, 6).map(a => `${a.appId ?? a.id}:${a.name ?? a.appName}`).join(' | '));
    const match = scoreApps(apps);
    if (match) return match.appId ?? match.app_id ?? match.id;
  }

  // Strategy 2: POST to discovered_apps — ElevenLabs/Midjourney are already in the report
  for (const ep of ['/cas/api/v1/discovery/discovered_apps/', '/cas/api/v1/discovery/app/']) {
    const disc = await fetch(`${MDCA_BASE}${ep}`, {
      method: 'POST', headers: hdrs,
      body: JSON.stringify({ filters: {}, limit: 100 }),
    });
    const discTxt = await disc.text().catch(() => '');
    if (disc.ok) {
      const discBody = JSON.parse(discTxt);
      const apps = discBody.data ?? discBody.apps ?? (Array.isArray(discBody) ? discBody : []);
      console.log(`[mdca/tag] ${ep} (${apps.length}):`, apps.slice(0, 6).map(a => `${a.appId ?? a.id}:${a.name ?? a.appName}`).join(' | '));
      const match = scoreApps(apps);
      if (match) return match.appId ?? match.app_id ?? match.id;
    } else {
      console.log(`[mdca/tag] ${ep} → ${disc.status}: ${discTxt.slice(0, 80)}`);
    }
  }

  return null;
}

async function pushMdcaTag(appDomain, appName, mdcaTag) {
  const token = process.env.MDCA_API_TOKEN;
  if (!token) throw new Error('no_token');

  const hdrs = { Authorization: `Token ${token}`, 'Content-Type': 'application/json' };

  // Verify the app exists in Cloud Discovery (confirms MDCA has seen it in traffic logs)
  const appId = await findMdcaAppId(hdrs, appDomain, appName);
  console.log(`[mdca/tag] resolved appId=${appId} for "${appName || appDomain}"`);

  // MDCA token-based REST API does not expose a write endpoint for built-in governance
  // tags (Sanctioned/Unsanctioned/Monitored). All known paths return 404/500:
  //   /discovery/set_app_tags/ → 404 on this tenant
  //   /discovery/app_tags/ POST → 200 read-only / 500 on write
  //   /discovery/discovered_apps/tags/ → unreachable (app_tags GET blocks first)
  // Enforcement requires the MDCA portal UI or cookie-based auth at security.microsoft.com.
  // Return compass_only so the handler shows a clear, honest message with an MDCA link.
  return { pushed: false, compass_only: true, app_id: appId, in_discovery: !!appId };
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
    const result = await pushMdcaTag(app_domain, app_name, mdcaTag);
    if (result.pushed) {
      live    = true;
      message = `${label} tagged as "${mdcaTag}" in Microsoft Defender for Cloud Apps`;
    } else if (result.compass_only) {
      // App found in MDCA Cloud Discovery but governance tags require the portal
      const verb = mdcaTag === 'unsanctioned' ? 'block' : mdcaTag === 'sanctioned' ? 'approve' : 'monitor';
      message = result.in_discovery
        ? `${label} marked as "${mdcaTag}" in Compass. To enforce in MDCA, open Cloud Discovery and ${verb} it there.`
        : `${label} marked as "${mdcaTag}" in Compass. Upload traffic logs to MDCA to surface it in Cloud Discovery.`;
    } else {
      message = `${label} marked as "${mdcaTag}" in Compass — app not yet in Cloud Discovery.`;
    }
  } catch (e) {
    const code = e.message;
    console.warn('[mdca/tag] API error:', code);
    if (code === 'no_token') {
      message = `${label} marked as "${mdcaTag}" in Compass — connect Microsoft 365 and add MDCA_API_TOKEN to push live tags`;
    } else {
      message = `${label} marked as "${mdcaTag}" in Compass — MDCA sync error: ${code}`;
    }
  }

  res.writeHead(200);
  res.end(JSON.stringify({ success: true, tag: mdcaTag, app: label, tenant_id: tid, live, message }));
};
