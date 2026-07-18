module.exports = function handler(req, res) {
  const qs      = req.url.includes('?') ? req.url.slice(req.url.indexOf('?') + 1) : '';
  const params  = new URLSearchParams(qs);
  const tenant  = params.get('tenant');
  const consent = params.get('admin_consent');
  const error   = params.get('error');
  const errDesc = params.get('error_description');

  if (error || !tenant || consent !== 'True') {
    const msg = encodeURIComponent(errDesc || error || 'Consent was not completed');
    res.writeHead(302, { Location: `/inventory?mdca_error=${msg}` });
    return res.end();
  }

  const isLocal  = (req.headers.host || '').startsWith('localhost');
  const secure   = isLocal ? '' : '; Secure';
  const cookie   = `mdca_tid=${tenant}; HttpOnly; SameSite=Lax; Max-Age=604800; Path=/${secure}`;

  res.writeHead(302, { Location: '/inventory?mdca=connected', 'Set-Cookie': cookie });
  res.end();
};
