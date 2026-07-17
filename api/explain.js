export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { control_id, control_name, status, finding_text } = req.body || {};

  if (!control_id || !finding_text) {
    return res.status(400).json({ error: 'Missing control_id or finding_text' });
  }

  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    return res.status(500).json({ error: 'ANTHROPIC_API_KEY not set in Vercel environment variables' });
  }

  const userPrompt =
    `NIST AI RMF Control: ${control_id} — ${control_name || control_id}\n` +
    `Status: ${status || 'GAP'}\n` +
    `Finding: ${finding_text}\n\n` +
    `In 2-3 sentences, explain what this gap means for the organization in plain language. ` +
    `Then provide exactly 3 concrete next steps (numbered list) to address it. ` +
    `Keep the entire response under 200 words.`;

  try {
    const resp = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'x-api-key':         apiKey,
        'anthropic-version': '2023-06-01',
        'content-type':      'application/json',
      },
      body: JSON.stringify({
        model:    'claude-haiku-4-5-20251001',
        max_tokens: 400,
        system:   'You are a concise NIST AI RMF compliance advisor helping security and compliance professionals understand governance gaps and fix them. Never mention the organization name. Never add disclaimers. Be direct and actionable.',
        messages: [{ role: 'user', content: userPrompt }],
      }),
    });

    if (!resp.ok) {
      const errText = await resp.text();
      return res.status(500).json({ error: `Anthropic API error ${resp.status}: ${errText}` });
    }

    const json = await resp.json();
    const explanation = json.content?.[0]?.text || 'No explanation returned.';
    return res.status(200).json({ explanation });
  } catch (err) {
    console.error('[/api/explain]', err.message);
    return res.status(500).json({ error: err.message });
  }
}
