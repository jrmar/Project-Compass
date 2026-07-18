module.exports = function handler(req, res) {
  const clientId = process.env.MDCA_CLIENT_ID;
  if (!clientId) {
    res.writeHead(500, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'MDCA_CLIENT_ID not configured' }));
  }

  const host     = req.headers['x-forwarded-host'] || req.headers.host || 'www.projectcompass.io';
  const proto    = req.headers['x-forwarded-proto'] || 'https';
  const callback = `${proto}://${host}/auth/mdca/callback`;

  const params = new URLSearchParams({
    client_id:    clientId,
    redirect_uri: callback,
    state:        Math.random().toString(36).slice(2, 10),
  });

  res.writeHead(302, { Location: `https://login.microsoftonline.com/common/adminconsent?${params}` });
  res.end();
};
