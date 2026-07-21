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

  // List discovery streams — needed as discovery_stream_id in the tag call
  const streamsResp = await fetch(`${MDCA_BASE}/cas/api/v1/discovery/`, { headers: hdrs });
  const streamsData  = streamsResp.ok ? await streamsResp.json() : {};
  const streams = streamsData.data ?? (Array.isArray(streamsData) ? streamsData : []);
  const streamId = streams[0]?._id ?? streams[0]?.id ?? null;
  console.log('[mdca/tag] streams:', JSON.stringify(streams).slice(0, 300));

  // Search app catalog by domain
  const searchResp = await fetch(
    `${MDCA_BASE}/cas/api/v1/discovery/app_catalog/?query=${encodeURIComponent(appDomain)}&limit=5`,
    { headers: hdrs }
  );
  if (!searchResp.ok) throw new Error(`catalog_${searchResp.status}`);

  const catBody = await searchResp.json();
  const apps = catBody.data ?? catBody.apps ?? (Array.isArray(catBody) ? catBody : []);
  console.log('[mdca/tag] catalog first app:', JSON.stringify(apps[0]).slice(0, 300));

  if (!apps.length) return { pushed: false, reason: 'not_in_catalog' };

  const appId = apps[0].appId ?? apps[0].app_id ?? apps[0].id;

  // Confirmed working: POST /cas/api/v1/discovery/app_tags/ with { app_id, tags: [num] }
  // set_app_tags returns 404 on this tenant; app_tags returns 200 with tag state.
  const tagNumMap = { sanctioned: 1, unsanctioned: 2, monitored: 3 };
  const tagNum = tagNumMap[mdcaTag] ?? 1;

  const r = await fetch(`${MDCA_BASE}/cas/api/v1/discovery/app_tags/`, {
    method: 'POST', headers: hdrs,
    body: JSON.stringify({ app_id: appId, tags: [tagNum] }),
  });
  const txt = await r.text().catch(() => '');
  const body = txt.startsWith('<!') ? '[HTML]' : txt.slice(0, 200);
  console.log(`[mdca/tag] app_tags app_id=${appId} tags=[${tagNum}] → ${r.status}: ${body}`);

  if (!r.ok) throw new Error(`tag_api_${r.status}`);
  return { pushed: true, app_id: appId };
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
    console.warn('[mdca/tag] API error:', code);
    if (code === 'no_token') {
      message = `Policy saved locally — add MDCA_API_TOKEN to Vercel env vars to push live tags`;
    } else if (code === 'not_in_catalog') {
      message = `${label} tagged as "${mdcaTag}" in Compass — app not found in MDCA catalog`;
    } else if (code.startsWith('tag_api_')) {
      const status = code.replace('tag_api_', '');
      message = `${label} tagged as "${mdcaTag}" in Compass — MDCA returned ${status} (check Vercel logs for payload details)`;
    } else {
      message = `${label} tagged as "${mdcaTag}" in Compass — MDCA sync error: ${code}`;
    }
  }

  res.writeHead(200);
  res.end(JSON.stringify({ success: true, tag: mdcaTag, app: label, tenant_id: tid, live, message }));
};
