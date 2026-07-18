module.exports = function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Access-Control-Allow-Origin', '*');

  const cookie = req.headers.cookie || '';
  const match  = cookie.match(/mdca_tid=([a-f0-9-]{36})/i);
  const tid    = match ? match[1] : null;

  res.writeHead(200);
  res.end(JSON.stringify({ connected: !!tid, tenant_id: tid }));
};
