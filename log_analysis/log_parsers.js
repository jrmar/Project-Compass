/**
 * log_analysis/log_parsers.js
 * Client-side AI domain detection — ported from parser_codes/*.py.
 * parser_codes/ is untouched; this file adapts that logic for the browser.
 */
(function (global) {
  'use strict';

  // ── Combined AI domain ruleset (merged from all 3 Python parsers) ──────────
  // Each entry: [domain_suffix, category, risk_level]
  // Sorted longest-first so subdomains match before their parent.
  const RULESET = [
    ['api-inference.huggingface.co', 'LLM API',           'high'],
    ['generativelanguage.googleapis.com', 'LLM API',      'high'],
    ['api.anthropic.com',           'LLM API',            'high'],
    ['api.stability.ai',            'Image Gen API',      'high'],
    ['api.elevenlabs.io',           'Audio Gen API',      'high'],
    ['api.together.xyz',            'LLM API',            'high'],
    ['api.mistral.ai',              'LLM API',            'high'],
    ['api.cohere.com',              'LLM API',            'high'],
    ['api.groq.com',                'LLM API',            'high'],
    ['chat.openai.com',             'LLM Assistant',      'high'],
    ['api.openai.com',              'LLM API',            'high'],
    ['copilot.github.com',          'AI Code Assistant',  'medium'],
    ['copilot.microsoft.com',       'LLM Assistant',      'medium'],
    ['gemini.google.com',           'LLM Assistant',      'medium'],
    ['bard.google.com',             'LLM Assistant',      'medium'],
    ['aistudio.google.com',         'LLM Platform',       'medium'],
    ['stablediffusionweb.com',      'Image Generation',   'high'],
    ['openai.com',                  'LLM Platform',       'high'],
    ['claude.ai',                   'LLM Assistant',      'medium'],
    ['anthropic.com',               'LLM Platform',       'medium'],
    ['perplexity.ai',               'AI Search',          'medium'],
    ['phind.com',                   'AI Dev Search',      'low'],
    ['you.com',                     'AI Search',          'low'],
    ['bing.com',                    'AI Search',          'low'],
    ['midjourney.com',              'Image Generation',   'high'],
    ['stability.ai',                'Image Generation',   'high'],
    ['runwayml.com',                'Video Generation',   'high'],
    ['runway.ml',                   'Video Generation',   'high'],
    ['pika.art',                    'Video Generation',   'high'],
    ['synthesia.io',                'Video Generation',   'high'],
    ['elevenlabs.io',               'Audio Generation',   'high'],
    ['suno.ai',                     'Audio Generation',   'high'],
    ['udio.com',                    'Audio Generation',   'high'],
    ['cursor.sh',                   'AI Code Assistant',  'medium'],
    ['codeium.com',                 'AI Code Tool',       'medium'],
    ['tabnine.com',                 'AI Code Tool',       'low'],
    ['replit.com',                  'AI Code Assistant',  'low'],
    ['github.com',                  'AI Code Assistant',  'low'],
    ['character.ai',                'AI Chatbot',         'high'],
    ['pi.ai',                       'AI Chatbot',         'medium'],
    ['inflection.ai',               'AI Chatbot',         'medium'],
    ['poe.com',                     'AI Chatbot',         'medium'],
    ['huggingface.co',              'ML Platform',        'medium'],
    ['replicate.com',               'ML Platform',        'high'],
    ['together.ai',                 'ML Platform',        'high'],
    ['groq.com',                    'LLM API',            'high'],
    ['mistral.ai',                  'LLM Provider',       'medium'],
    ['cohere.com',                  'LLM API',            'high'],
    ['grok.x.ai',                   'LLM Assistant',      'high'],
    ['meta.ai',                     'LLM Assistant',      'medium'],
    ['jasper.ai',                   'AI Writing',         'medium'],
    ['writesonic.com',              'AI Writing',         'medium'],
    ['copy.ai',                     'AI Writing',         'medium'],
    ['grammarly.com',               'AI Writing',         'low'],
    ['notion.so',                   'AI Productivity',    'low'],
  ];

  const RISK_ORDER = { high: 2, medium: 1, low: 0, unknown: -1 };

  // ── Category → representative domain (for firewall logs without domain/URL) ─
  const CAT_DOMAIN_MAP = {
    'LLM Assistant':    { domain: 'claude.ai',          category: 'LLM Assistant',    risk: 'medium' },
    'AI Assistant':     { domain: 'claude.ai',          category: 'LLM Assistant',    risk: 'medium' },
    'LLM API':          { domain: 'api.openai.com',     category: 'LLM API',          risk: 'high'   },
    'AI Search':        { domain: 'perplexity.ai',      category: 'AI Search',        risk: 'medium' },
    'Audio Generation': { domain: 'elevenlabs.io',      category: 'Audio Generation', risk: 'high'   },
    'Image Generation': { domain: 'midjourney.com',     category: 'Image Generation', risk: 'high'   },
    'Video Generation': { domain: 'runwayml.com',       category: 'Video Generation', risk: 'high'   },
    'AI Code Assistant':{ domain: 'cursor.sh',          category: 'AI Code Assistant',risk: 'medium' },
    'AI Code Tool':     { domain: 'cursor.sh',          category: 'AI Code Tool',     risk: 'medium' },
    'ML Platform':      { domain: 'huggingface.co',     category: 'ML Platform',      risk: 'medium' },
    'AI Writing':       { domain: 'grammarly.com',      category: 'AI Writing',       risk: 'low'    },
    'Productivity':     { domain: 'notion.so',          category: 'AI Productivity',  risk: 'low'    },
    'AI Productivity':  { domain: 'notion.so',          category: 'AI Productivity',  risk: 'low'    },
    'Unknown AI':       { domain: '(unknown-ai)',        category: 'Unknown AI',       risk: 'unknown'},
  };

  // App-name → domain (firewall `app` field)
  const APP_NAME_MAP = {
    'ms-copilot':        { domain: 'copilot.microsoft.com', category: 'LLM Assistant',    risk: 'medium' },
    'microsoft-copilot': { domain: 'copilot.microsoft.com', category: 'LLM Assistant',    risk: 'medium' },
    'chatgpt':           { domain: 'chat.openai.com',       category: 'LLM Assistant',    risk: 'high'   },
    'openai':            { domain: 'openai.com',            category: 'LLM Platform',     risk: 'high'   },
    'claude':            { domain: 'claude.ai',             category: 'LLM Assistant',    risk: 'medium' },
    'gemini':            { domain: 'gemini.google.com',     category: 'LLM Assistant',    risk: 'medium' },
    'perplexity':        { domain: 'perplexity.ai',         category: 'AI Search',        risk: 'medium' },
    'midjourney':        { domain: 'midjourney.com',        category: 'Image Generation', risk: 'high'   },
    'elevenlabs':        { domain: 'elevenlabs.io',         category: 'Audio Generation', risk: 'high'   },
    'cursor':            { domain: 'cursor.sh',             category: 'AI Code Assistant',risk: 'medium' },
    'github-copilot':    { domain: 'copilot.github.com',   category: 'AI Code Assistant',risk: 'medium' },
  };

  // ── Helpers ────────────────────────────────────────────────────────────────

  function matchDomain(domain) {
    if (!domain) return null;
    const d = domain.toLowerCase().replace(/\.$/, '').replace(/^www\./, '');
    for (const [rd, category, risk] of RULESET) {
      if (d === rd || d.endsWith('.' + rd)) return { category, risk };
    }
    return null;
  }

  function extractDomain(url) {
    if (!url) return '';
    url = url.trim();
    if (!url.startsWith('http')) url = 'https://' + url;
    try {
      return new URL(url).hostname.replace(/^www\./, '').toLowerCase();
    } catch {
      return url.toLowerCase();
    }
  }

  function parseCSVLine(line) {
    const out = [];
    let cur = '', inQ = false;
    for (let i = 0; i < line.length; i++) {
      const c = line[i];
      if (c === '"') {
        if (inQ && line[i + 1] === '"') { cur += '"'; i++; }
        else inQ = !inQ;
      } else if (c === ',' && !inQ) {
        out.push(cur.trim()); cur = '';
      } else {
        cur += c;
      }
    }
    out.push(cur.trim());
    return out;
  }

  function safeInt(v) {
    const n = parseInt(String(v || '').replace(/,/g, ''), 10);
    return isNaN(n) ? 0 : n;
  }

  function formatBytes(b) {
    if (b < 1024)         return b + ' B';
    if (b < 1048576)      return (b / 1024).toFixed(1) + ' KB';
    if (b < 1073741824)   return (b / 1048576).toFixed(1) + ' MB';
    return (b / 1073741824).toFixed(2) + ' GB';
  }

  function buildSummary(flagged) {
    const byDomain = {}, byUser = {};
    const byRisk = { high: 0, medium: 0, low: 0, unknown: 0 };
    let totalBytes = 0;

    for (const e of flagged) {
      const domain = e.matched_domain || e.query || '(unknown)';
      const user   = e.user || e.src_ip || 'unknown';
      const risk   = e.risk_level || 'unknown';
      const bytes  = (e.bytes_sent || 0) + (e.bytes_received || 0);

      if (!byDomain[domain]) {
        byDomain[domain] = {
          category: e.detected_category, risk, count: 0, bytes: 0,
          users: new Set(), methods: new Set(), actions: new Set(),
        };
      }
      byDomain[domain].count++;
      byDomain[domain].bytes += bytes;
      byDomain[domain].users.add(user);
      if (e.method)  byDomain[domain].methods.add(e.method.toUpperCase());
      if (e.action)  byDomain[domain].actions.add(e.action.toLowerCase());

      if (!byUser[user]) byUser[user] = { domains: new Set(), count: 0, bytes: 0 };
      byUser[user].domains.add(domain);
      byUser[user].count++;
      byUser[user].bytes += bytes;

      byRisk[risk] = (byRisk[risk] || 0) + 1;
      totalBytes += bytes;
    }

    for (const d of Object.values(byDomain)) {
      d.users    = [...d.users];
      d.methods  = [...d.methods];
      d.actions  = [...d.actions];
    }
    for (const u of Object.values(byUser)) {
      u.domains = [...u.domains];
    }

    return { byDomain, byUser, byRisk, totalBytes };
  }

  // ── DNS parser ────────────────────────────────────────────────────────────
  // Formats: timestamp,src_ip,user,query,type,response_ip,rcode,category,risk_level
  //          or shorter: timestamp,client_ip,query_domain,query_type,...
  function parseDNS(text) {
    const flagged = [];
    let skipped = 0, errors = 0;

    for (const raw of text.split('\n')) {
      const line = raw.trim();
      if (!line || line.startsWith('#')) continue;
      if (/^timestamp[,;]/i.test(line)) continue;

      let row;
      try { row = parseCSVLine(line); } catch { errors++; continue; }
      if (row.length < 3) { errors++; continue; }

      let timestamp, src_ip, user, query, qtype = '', response_ip = '', rcode = '', log_cat = '', log_risk = '';

      if (row.length >= 9) {
        [timestamp, src_ip, user, query, qtype, response_ip, rcode, log_cat, log_risk] = row;
      } else {
        [timestamp, src_ip, query = '', qtype = ''] = row;
        user = src_ip;
      }

      if (!query) { skipped++; continue; }
      const match = matchDomain(query);
      if (!match) { skipped++; continue; }

      const effective_risk =
        (RISK_ORDER[log_risk] > RISK_ORDER[match.risk]) ? log_risk : match.risk;

      flagged.push({
        timestamp, src_ip, user: user || src_ip,
        query, query_type: qtype, response_ip, rcode,
        matched_domain:    query,
        detected_category: match.category,
        risk_level:        effective_risk,
        bytes_sent: 0, bytes_received: 0,
      });
    }

    return { flagged, skipped, errors };
  }

  // ── Proxy parser ───────────────────────────────────────────────────────────
  // Generic: timestamp,src_ip,user,http_method,url,status,bytes_sent,bytes_received,...
  // Squid:   timestamp,duration,client_ip,result_code,bytes,method,url,user,...
  // Zscaler: timestamp,user,department,location,url,category,...
  function parseProxy(text) {
    const flagged = [];
    let skipped = 0, errors = 0;
    let colMap = null, logFormat = 'generic';

    for (const raw of text.split('\n')) {
      const line = raw.trim();
      if (!line || line.startsWith('#')) continue;

      let row;
      try { row = parseCSVLine(line); } catch { errors++; continue; }

      if (colMap === null) {
        const h = row.map(c => c.toLowerCase().trim());
        if (h.includes('url') || /^(timestamp|date|time)$/.test(h[0])) {
          colMap = {};
          h.forEach((k, i) => { colMap[k] = i; });
          if (h.includes('department') || h.includes('risk_score')) logFormat = 'zscaler';
          else if (h.includes('result_code') || h.includes('hierarchy'))  logFormat = 'squid';
          continue;
        } else {
          colMap = { timestamp: 0, src_ip: 1, user: 2, http_method: 3, url: 4,
                     status: 5, bytes_sent: 6, bytes_received: 7 };
        }
      }

      if (row.length < 3) { errors++; continue; }

      const get = (f, def = '') => {
        const i = colMap[f];
        return (i !== undefined && i < row.length) ? (row[i] || '').trim() : def;
      };

      let url, user, bytes_sent, bytes_recv, action, method;

      if (logFormat === 'squid') {
        const rc = get('result_code', '');
        action = rc.toUpperCase().includes('DENIED') ? 'blocked' : 'allowed';
        url = get('url');
        user = get('user') || get('client_ip') || '';
        method = get('method', 'GET');
        bytes_sent = 0;
        bytes_recv = safeInt(get('bytes', '0'));
      } else if (logFormat === 'zscaler') {
        const ar = get('action', 'allowed').toLowerCase();
        action = ar.includes('block') ? 'blocked' : 'allowed';
        url = get('url');
        user = get('user') || get('src_ip') || '';
        method = get('method', 'GET');
        bytes_sent = safeInt(get('bytes_sent', '0'));
        bytes_recv = safeInt(get('bytes_received', '0'));
      } else {
        url = get('url');
        user = get('user') || get('src_ip') || '';
        method = get('http_method', get('method', 'GET'));
        action = get('policy_action', get('action', 'allowed'));
        bytes_sent = safeInt(get('bytes_sent', '0'));
        bytes_recv = safeInt(get('bytes_received', get('bytes_recv', '0')));
      }

      const domain = extractDomain(url);
      const match  = matchDomain(domain);
      if (!match) { skipped++; continue; }

      flagged.push({
        timestamp:         get('timestamp'),
        src_ip:            get('src_ip'),
        user,
        method,
        url,
        matched_domain:    domain,
        status_code:       get('status_code', get('status', '200')),
        bytes_sent,
        bytes_received:    bytes_recv,
        action,
        detected_category: match.category,
        risk_level:        match.risk,
      });
    }

    return { flagged, skipped, errors };
  }

  // ── Firewall parser ────────────────────────────────────────────────────────
  // Compass CSV: timestamp,device,src_ip,dst_ip,src_port,dst_port,protocol,app,action,rule,bytes,threat,category,risk_level
  // Generic:     timestamp,src_ip,src_port,dst_ip,dst_port,protocol,action,application,url,bytes_sent,bytes_received,...
  // Matching priority: url field → app field (as domain or known name) → category field
  function parseFirewall(text) {
    const flagged = [];
    let skipped = 0, errors = 0;
    let colMap = null;

    for (const raw of text.split('\n')) {
      const line = raw.trim();
      if (!line || line.startsWith('#')) continue;

      let row;
      try { row = parseCSVLine(line); } catch { errors++; continue; }

      if (colMap === null) {
        const h = row.map(c => c.toLowerCase().trim());
        if (h[0] === 'timestamp' || h.includes('src_ip')) {
          colMap = {};
          h.forEach((k, i) => { colMap[k] = i; });
          continue;
        } else {
          colMap = { timestamp: 0, src_ip: 2, dst_ip: 3, app: 7, action: 8, bytes: 10, category: 12, risk_level: 13 };
        }
      }

      if (row.length < 3) { errors++; continue; }

      const get = (f, def = '') => {
        const i = colMap[f];
        return (i !== undefined && i < row.length) ? (row[i] || '').trim() : def;
      };

      const urlField = get('url');
      const appField = (get('app', get('application', ''))).toLowerCase();
      const catField = get('category', '');
      const logRisk  = get('risk_level', '');

      let match = null, matchedDomain = '';

      if (urlField) {
        const d = extractDomain(urlField);
        const m = matchDomain(d);
        if (m) { match = m; matchedDomain = d; }
      }

      if (!match && appField) {
        const m1 = matchDomain(appField);
        if (m1) { match = m1; matchedDomain = appField; }
        else {
          const m2 = APP_NAME_MAP[appField];
          if (m2) { match = m2; matchedDomain = m2.domain; }
        }
      }

      if (!match && catField) {
        const m3 = CAT_DOMAIN_MAP[catField];
        if (m3) { match = m3; matchedDomain = m3.domain; }
      }

      if (!match) { skipped++; continue; }

      const effectiveRisk =
        (RISK_ORDER[logRisk] > RISK_ORDER[match.risk]) ? logRisk : match.risk;

      flagged.push({
        timestamp:         get('timestamp'),
        src_ip:            get('src_ip'),
        user:              get('user', get('src_ip')),
        dst_ip:            get('dst_ip'),
        protocol:          get('protocol'),
        application:       appField,
        action:            get('action', ''),
        bytes_sent:        safeInt(get('bytes_sent', get('bytes', '0'))),
        bytes_received:    safeInt(get('bytes_received', '0')),
        matched_domain:    matchedDomain,
        detected_category: match.category,
        risk_level:        effectiveRisk,
      });
    }

    return { flagged, skipped, errors };
  }

  // ── WatchGuard / semicolon-delimited parser ────────────────────────────────
  // Fields include "Dst. Domain", "Src. Ip", "In", "Out"
  function parseWatchGuard(text) {
    const flagged = [];
    let skipped = 0, errors = 0;
    let colMap = null;

    for (const raw of text.split('\n')) {
      const line = raw.trim();
      if (!line || line.startsWith('#')) continue;

      const row = line.split(';').map(c => c.trim());

      if (colMap === null) {
        const h = row.map(c => c.toLowerCase().trim());
        if (h.some(k => k.includes('domain') || k.includes('application'))) {
          colMap = {};
          h.forEach((k, i) => { colMap[k] = i; });
          continue;
        } else { errors++; continue; }
      }

      const get = (f, def = '') => {
        const i = colMap[f];
        return (i !== undefined && i < row.length) ? row[i] : def;
      };

      const domain =
        get('dst. domain') || get('dst_domain') || get('destination domain') || get('dstdomain') || '';
      const match = matchDomain(domain);
      if (!match) { skipped++; continue; }

      flagged.push({
        timestamp:         (get('date', '') + ' ' + get('time', '')).trim(),
        src_ip:            get('src. ip', get('src_ip', get('srcip', ''))),
        user:              get('user', get('src. ip', '')),
        matched_domain:    domain,
        action:            get('action', get('disp', '')),
        bytes_sent:        safeInt(get('out', get('sent bytes', get('bytes_sent', '0')))),
        bytes_received:    safeInt(get('in',  get('received bytes', get('bytes_received', '0')))),
        detected_category: match.category,
        risk_level:        match.risk,
      });
    }

    return { flagged, skipped, errors };
  }

  // ── Tool name lookup ───────────────────────────────────────────────────────
  const TOOL_NAME_MAP = {
    'openai.com': 'OpenAI', 'chat.openai.com': 'ChatGPT', 'api.openai.com': 'OpenAI API',
    'claude.ai': 'Claude', 'anthropic.com': 'Anthropic', 'gemini.google.com': 'Google Gemini',
    'copilot.github.com': 'GitHub Copilot', 'copilot.microsoft.com': 'Microsoft Copilot',
    'midjourney.com': 'Midjourney', 'huggingface.co': 'Hugging Face',
    'character.ai': 'Character.AI', 'perplexity.ai': 'Perplexity AI',
    'notion.so': 'Notion AI', 'stability.ai': 'Stability AI',
    'runwayml.com': 'Runway ML', 'elevenlabs.io': 'ElevenLabs',
    'cursor.sh': 'Cursor', 'codeium.com': 'Codeium', 'grammarly.com': 'Grammarly',
    'jasper.ai': 'Jasper AI', 'writesonic.com': 'Writesonic', 'poe.com': 'Poe',
    'together.ai': 'Together AI', 'mistral.ai': 'Mistral AI', 'groq.com': 'Groq',
    'cohere.com': 'Cohere', 'meta.ai': 'Meta AI', 'grok.x.ai': 'Grok',
    'suno.ai': 'Suno', 'udio.com': 'Udio', 'pika.art': 'Pika',
    'replicate.com': 'Replicate', 'synthesia.io': 'Synthesia',
    '(unknown-ai)': 'Unknown AI Tool',
  };

  function toToolName(domain) {
    if (TOOL_NAME_MAP[domain]) return TOOL_NAME_MAP[domain];
    const base = domain.split('.').slice(-2, -1)[0] || domain;
    return base.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase()) + ' AI';
  }

  // ── Detection payload builder (matches detect.html expected format) ────────
  function buildDetectionPayload(logType, parseResult, fileNames) {
    const { flagged, summary: s } = parseResult;
    const { byDomain, byUser, byRisk } = s;

    const detected_tools = Object.entries(byDomain)
      .sort((a, b) => b[1].count - a[1].count)
      .map(([domain, info]) => ({
        domain,
        tool_name:       toToolName(domain),
        category:        info.category,
        risk_level:      info.risk,
        approved_status: info.risk === 'high'   ? 'restricted'
                       : info.risk === 'medium' ? 'review_required'
                       : 'approved',
        event_count:     info.count,
        users:           info.users || [],
        source_ips:      [],
        sources:         [logType],
        actions:         info.risk === 'high' ? ['review_required', 'blocked'] : ['resolved'],
        bytes:           info.bytes || 0,
      }));

    const eventsBySource = { dns: 0, proxy: 0, firewall: 0 };
    if (logType in eventsBySource) eventsBySource[logType] = flagged.length;

    return {
      assessment_id:   `assessment-${new Date().toISOString().slice(0, 10)}-live`,
      assessment_name: `Compass ${logType.toUpperCase()} Analysis — ${(fileNames || []).join(', ')}`,
      _live:           true,
      _registry_size:  RULESET.length,
      _log_type:       logType,
      summary: {
        total_events:              flagged.length,
        unique_tools_or_domains:   detected_tools.length,
        events_by_source:          eventsBySource,
        events_by_risk_level:      {
          high:    byRisk.high    || 0,
          medium:  byRisk.medium  || 0,
          low:     byRisk.low     || 0,
          unknown: byRisk.unknown || 0,
        },
        events_by_observed_action: {
          resolved:        byRisk.low    || 0,
          review_required: byRisk.medium || 0,
          blocked:         byRisk.high   || 0,
        },
        high_or_unknown_events: (byRisk.high || 0) + (byRisk.unknown || 0),
        users_observed:     Object.keys(byUser),
        source_ips_observed:[],
      },
      detected_tools,
    };
  }

  // ── Public API ─────────────────────────────────────────────────────────────
  global.CompassParsers = {
    RULESET,
    matchDomain,
    extractDomain,
    formatBytes,
    toToolName,

    parseDNS(text) {
      const r = parseDNS(text);
      r.summary = buildSummary(r.flagged);
      return r;
    },
    parseProxy(text) {
      const r = parseProxy(text);
      r.summary = buildSummary(r.flagged);
      return r;
    },
    parseFirewall(text) {
      const r = parseFirewall(text);
      r.summary = buildSummary(r.flagged);
      return r;
    },
    parseWatchGuard(text) {
      const r = parseWatchGuard(text);
      r.summary = buildSummary(r.flagged);
      return r;
    },

    // Pick the right parser by log type string
    parse(logType, text) {
      const fn = {
        dns:        this.parseDNS,
        proxy:      this.parseProxy,
        firewall:   this.parseFirewall,
        watchguard: this.parseWatchGuard,
      }[logType];
      return fn ? fn.call(this, text) : this.parseProxy(text);
    },

    buildDetectionPayload,
  };

}(typeof window !== 'undefined' ? window : global));
