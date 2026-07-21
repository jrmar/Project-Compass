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

  const appId = await findMdcaAppId(hdrs, appDomain, appName);
  console.log(`[mdca/tag] resolved appId=${appId} for "${appName || appDomain}"`);
  if (!appId) return { pushed: false, reason: 'not_in_catalog' };

  const tagNumMap = { sanctioned: 1, unsanctioned: 2, monitored: 3 };
  const tagNum = tagNumMap[mdcaTag] ?? 1;

  // Step 1: GET current tags to find the target tag's _id and current appIds list
  const getResp = await fetch(`${MDCA_BASE}/cas/api/v1/discovery/app_tags/`, { headers: hdrs });
  if (!getResp.ok) throw new Error(`tag_api_${getResp.status}`);
  const tagsData = await getResp.json();
  const allTags  = tagsData.data ?? (Array.isArray(tagsData) ? tagsData : []);
  console.log(`[mdca/tag] tags GET:`, allTags.map(t => `${t._id ?? t.id}:${t.name}(${(t.appIds??[]).length}apps)`).join(' | '));

  const targetTag = allTags.find(t =>
    (t.name ?? '').toLowerCase() === mdcaTag.toLowerCase() || t.tag === tagNum
  );

  if (targetTag) {
    const tagObjId    = targetTag._id ?? targetTag.id;
    const currentIds  = targetTag.appIds ?? [];
    const alreadySet  = currentIds.includes(appId);
    console.log(`[mdca/tag] target tag _id=${tagObjId} currentAppIds=${currentIds.length} alreadyHasApp=${alreadySet}`);

    if (!alreadySet) {
      // Step 2a: PATCH the tag with updated appIds (add our app)
      const newIds   = [...currentIds, appId];
      const patchResp = await fetch(`${MDCA_BASE}/cas/api/v1/discovery/app_tags/${tagObjId}/`, {
        method: 'PATCH', headers: hdrs,
        body: JSON.stringify({ appIds: newIds }),
      });
      const patchTxt = await patchResp.text().catch(() => '');
      console.log(`[mdca/tag] PATCH app_tags/${tagObjId} → ${patchResp.status}: ${patchTxt.startsWith('<!') ? '[HTML]' : patchTxt.slice(0, 150)}`);

      if (patchResp.ok) return { pushed: true, app_id: appId };

      // Step 2b: PATCH failed — try PUT with full replacement
      const putResp = await fetch(`${MDCA_BASE}/cas/api/v1/discovery/app_tags/${tagObjId}/`, {
        method: 'PUT', headers: hdrs,
        body: JSON.stringify({ ...targetTag, appIds: newIds }),
      });
      const putTxt = await putResp.text().catch(() => '');
      console.log(`[mdca/tag] PUT app_tags/${tagObjId} → ${putResp.status}: ${putTxt.startsWith('<!') ? '[HTML]' : putTxt.slice(0, 150)}`);
      if (putResp.ok) return { pushed: true, app_id: appId };
    } else {
      return { pushed: true, app_id: appId }; // already tagged
    }
  }

  // Step 2c: No tag object found or PATCH/PUT failed — fall back to POST
  const postResp = await fetch(`${MDCA_BASE}/cas/api/v1/discovery/app_tags/`, {
    method: 'POST', headers: hdrs,
    body: JSON.stringify({ app_id: appId, tags: [tagNum] }),
  });
  const postTxt = await postResp.text().catch(() => '');
  console.log(`[mdca/tag] POST app_tags fallback → ${postResp.status}: ${postTxt.startsWith('<!') ? '[HTML]' : postTxt.slice(0, 150)}`);
  if (!postResp.ok) throw new Error(`tag_api_${postResp.status}`);
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
    const result = await pushMdcaTag(app_domain, app_name, mdcaTag);
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
