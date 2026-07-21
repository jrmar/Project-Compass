/**
 * POST /api/mdca/disconnect
 * Clears the mdca_tid HttpOnly cookie so the MDCA connection is revoked.
 * JavaScript cannot delete HttpOnly cookies directly — this server response does it.
 */
module.exports = function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Access-Control-Allow-Origin', '*');
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }

  // Expire the cookie immediately — same flags it was set with
  res.setHeader('Set-Cookie', 'mdca_tid=; HttpOnly; SameSite=Lax; Max-Age=0; Path=/');
  res.writeHead(200);
  res.end(JSON.stringify({ success: true }));
};
