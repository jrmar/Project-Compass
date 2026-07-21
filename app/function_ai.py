import azure.functions as func
import tempfile, os, traceback, csv
import pymssql
from urllib.parse import urlparse

app = func.FunctionApp()

HTML_PAGE = """
<!DOCTYPE html>
<html>
<head>
  <title>Compass Log Parser</title>
  <style>
    body { font-family: Arial, sans-serif; background: #0A1628; color: #E8F0FF; max-width: 800px; margin: 60px auto; padding: 20px; }
    h1 { color: #00C9B1; }
    .subtitle { color: #8BA4C8; margin-bottom: 30px; }
    .upload-box { background: #0F2040; border: 2px dashed #00C9B1; border-radius: 10px; padding: 40px; text-align: center; margin: 20px 0; }
    .type-row { display: flex; gap: 10px; justify-content: center; margin-bottom: 16px; }
    .type-btn { background: #0F2040; border: 1.5px solid #1A3A5C; color: #8BA4C8; padding: 8px 18px; border-radius: 6px; cursor: pointer; font-size: 13px; font-weight: bold; transition: all 0.15s; }
    .type-btn.selected { border-color: #00C9B1; color: #00C9B1; background: rgba(0,201,177,0.08); }
    input[type=file] { margin: 15px 0; color: #E8F0FF; }
    button.submit-btn { background: #00C9B1; color: #0A1628; border: none; padding: 12px 30px; border-radius: 6px; font-size: 15px; font-weight: bold; cursor: pointer; margin-top: 10px; }
    button.submit-btn:hover { background: #00A8E8; }
    pre { background: #0F2040; padding: 20px; border-radius: 8px; overflow-x: auto; font-size: 13px; line-height: 1.6; white-space: pre-wrap; }
    .loading { display: none; color: #00C9B1; margin-top: 10px; }
  </style>
</head>
<body>
  <h1>Project Compass</h1>
  <p class="subtitle">AI Access Detection — powered by Azure SQL registry (1,199 domains)</p>

  <div class="upload-box">
    <p>Select log type and upload your file to scan for AI-related traffic</p>
    <div class="type-row">
      <button class="type-btn selected" id="btn-dns"      onclick="selectType('dns')">🌐 DNS Log</button>
      <button class="type-btn"          id="btn-firewall" onclick="selectType('firewall')">🔥 Firewall Log</button>
      <button class="type-btn"          id="btn-proxy"    onclick="selectType('proxy')">🔁 Proxy Log</button>
    </div>
    <form id="uploadForm" enctype="multipart/form-data">
      <input type="hidden" id="log_type" name="log_type" value="dns">
      <input type="file" id="logfile" name="logfile" accept=".log,.csv" required><br>
      <button type="submit" class="submit-btn">Run Parser</button>
    </form>
    <p class="loading" id="loading">⏳ Analyzing log file against Azure registry...</p>
  </div>

  <div id="results"></div>

  <script>
    function selectType(type) {
      document.querySelectorAll('.type-btn').forEach(b => b.classList.remove('selected'));
      document.getElementById('btn-' + type).classList.add('selected');
      document.getElementById('log_type').value = type;
    }

    document.getElementById('uploadForm').addEventListener('submit', async function(e) {
      e.preventDefault();
      const loading = document.getElementById('loading');
      const results = document.getElementById('results');
      loading.style.display = 'block';
      results.innerHTML = '';

      const formData = new FormData();
      formData.append('logfile', document.getElementById('logfile').files[0]);
      formData.append('log_type', document.getElementById('log_type').value);

      try {
        const resp = await fetch('/api/parse', { method: 'POST', body: formData });
        const text = await resp.text();
        loading.style.display = 'none';
        results.innerHTML = '<h2>Results</h2><pre>' + text + '</pre>';
      } catch(err) {
        loading.style.display = 'none';
        results.innerHTML = '<pre style="color:#FF4D4D">Error: ' + err + '</pre>';
      }
    });
  </script>
</body>
</html>
"""

# ---------------------------------------------------------------------------
# Azure SQL registry
# ---------------------------------------------------------------------------
def build_ruleset_from_azure():
    server   = "compass-registry-srv.database.windows.net"
    database = "compass-registry"
    user     = "compassadmin"
    password = "TheServerMap1456&"

    ruleset = []
    conn = pymssql.connect(
        server=server, user=user, password=password,
        database=database, port=1433, tds_version="7.4", conn_properties=""
    )
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT normalized_domain, category, risk_level
            FROM compass.approved_ai_registry
            WHERE active = 1
        """)
        for normalized_domain, category, risk_level in cursor.fetchall():
            ruleset.append((
                normalized_domain.strip().lower(),
                category.strip() if category else "Unclassified",
                risk_level.strip().lower() if risk_level else "medium"
            ))
    finally:
        conn.close()

    if len(ruleset) == 0:
        raise RuntimeError("Azure registry returned 0 domains.")
    return ruleset


# ---------------------------------------------------------------------------
# Shared domain matching
# ---------------------------------------------------------------------------
def match_domain(domain, ruleset):
    if not domain:
        return None
    d = domain.lower().rstrip(".")
    for rule_domain, category, risk in ruleset:
        rd = rule_domain.lower()
        if d == rd or d.endswith("." + rd):
            return category, risk
    return None


def extract_domain_from_url(url):
    if not url:
        return ""
    url = url.strip()
    if not url.startswith("http"):
        url = "https://" + url
    try:
        host = urlparse(url).hostname or ""
        if host.startswith("www."):
            host = host[4:]
        return host.lower()
    except Exception:
        return ""


RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "unknown": -1}

def risk_gte(risk, min_risk):
    return RISK_ORDER.get(risk, -1) >= RISK_ORDER.get(min_risk, 0)


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------
def detect_log_type(filepath, hint="dns"):
    """
    Auto-detect log type from header row.
    Uses the hint from the form if provided, but validates against
    actual file content so mismatches are handled gracefully.
    """
    with open(filepath, newline="", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                row = next(csv.reader([line]))
            except Exception:
                continue
            headers = [h.strip().lower() for h in row]

            # Firewall signals
            if any(h in headers for h in ["dst_ip", "bytes_sent", "bytes_received", "duration"]):
                return "firewall"
            # Proxy signals
            if any(h in headers for h in ["method", "status_code", "url", "content_type", "result_code"]):
                return "proxy"
            # DNS signals
            if any(h in headers for h in ["query_domain", "query_type", "response_code", "qtype"]):
                return "dns"
            # 9-col DNS format
            if "query" in headers and "src_ip" in headers:
                return "dns"
            break

    # Fall back to hint
    return hint if hint in ("dns", "firewall", "proxy") else "dns"


# ---------------------------------------------------------------------------
# DNS parser
# ---------------------------------------------------------------------------
def parse_dns(filepath, ruleset):
    flagged, skipped, errors = [], 0, []
    col_map = None

    with open(filepath, newline="", encoding="utf-8") as f:
        for lineno, raw in enumerate(f, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.lower().startswith("timestamp,"):
                continue
            try:
                row = next(csv.reader([line]))
            except Exception as e:
                errors.append((lineno, raw.rstrip(), str(e))); continue

            if col_map is None:
                headers = [h.strip().lower() for h in row]
                if "query" in headers or "query_domain" in headers:
                    col_map = {h: i for i, h in enumerate(headers)}
                    continue
                else:
                    col_map = {}

            if len(row) < 3:
                errors.append((lineno, raw.rstrip(), "Too few fields")); continue

            def g(field, default=""):
                idx = col_map.get(field)
                return row[idx].strip() if idx is not None and idx < len(row) else default

            if col_map and "query" in col_map:
                # 9-col format
                query = g("query")
                src_ip = g("src_ip")
                user   = g("user", src_ip)
            elif len(row) >= 9:
                query  = row[3].strip()
                src_ip = row[1].strip()
                user   = row[2].strip()
            else:
                query  = row[2].strip() if len(row) > 2 else ""
                src_ip = row[1].strip() if len(row) > 1 else ""
                user   = src_ip

            match = match_domain(query, ruleset)
            if not match:
                skipped += 1; continue

            category, risk = match
            if not risk_gte(risk, "low"):
                skipped += 1; continue

            flagged.append({
                "timestamp":         row[0].strip() if row else "",
                "src_ip":            src_ip,
                "user":              user,
                "query":             query,
                "matched_domain":    query,
                "detected_category": category,
                "risk_level":        risk,
                "log_type":          "dns",
            })

    return flagged, skipped, errors


# ---------------------------------------------------------------------------
# Firewall parser
# ---------------------------------------------------------------------------
def parse_firewall(filepath, ruleset):
    flagged, skipped, errors = [], 0, []
    col_map = None

    with open(filepath, newline="", encoding="utf-8") as f:
        for lineno, raw in enumerate(f, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                row = next(csv.reader([line]))
            except Exception as e:
                errors.append((lineno, raw.rstrip(), str(e))); continue

            if col_map is None:
                headers = [h.strip().lower() for h in row]
                if "timestamp" in headers or "src_ip" in headers:
                    col_map = {h: i for i, h in enumerate(headers)}
                    continue
                else:
                    defaults = ["timestamp","src_ip","src_port","dst_ip","dst_port",
                                "protocol","action","application","url",
                                "bytes_sent","bytes_received","duration","user"]
                    col_map = {h: i for i, h in enumerate(defaults)}

            if len(row) < 3:
                errors.append((lineno, raw.rstrip(), "Too few fields")); continue

            def g(field, default=""):
                idx = col_map.get(field)
                return row[idx].strip() if idx is not None and idx < len(row) else default

            url_field = g("url")
            application = g("application")
            domain = extract_domain_from_url(url_field) or application.lower().strip()

            match = match_domain(domain, ruleset)
            if not match:
                skipped += 1; continue

            category, risk = match
            if not risk_gte(risk, "low"):
                skipped += 1; continue

            flagged.append({
                "timestamp":         g("timestamp"),
                "src_ip":            g("src_ip"),
                "user":              g("user", g("src_ip")),
                "url":               url_field,
                "matched_domain":    domain,
                "action":            g("action"),
                "bytes_sent":        g("bytes_sent", "0"),
                "bytes_received":    g("bytes_received", "0"),
                "detected_category": category,
                "risk_level":        risk,
                "log_type":          "firewall",
            })

    return flagged, skipped, errors


# ---------------------------------------------------------------------------
# Proxy parser
# ---------------------------------------------------------------------------
def parse_proxy(filepath, ruleset):
    flagged, skipped, errors = [], 0, []
    col_map = None

    with open(filepath, newline="", encoding="utf-8") as f:
        for lineno, raw in enumerate(f, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                row = next(csv.reader([line]))
            except Exception as e:
                errors.append((lineno, raw.rstrip(), str(e))); continue

            if col_map is None:
                headers = [h.strip().lower() for h in row]
                first = headers[0] if headers else ""
                if first in ("timestamp", "date", "time", "datetime") or "url" in headers:
                    col_map = {h: i for i, h in enumerate(headers)}
                    continue
                else:
                    defaults = ["timestamp","src_ip","user","method","url",
                                "status_code","bytes_sent","bytes_received",
                                "duration_ms","category","action"]
                    col_map = {h: i for i, h in enumerate(defaults)}

            if len(row) < 3:
                errors.append((lineno, raw.rstrip(), "Too few fields")); continue

            def g(field, default=""):
                idx = col_map.get(field)
                return row[idx].strip() if idx is not None and idx < len(row) else default

            url_field = g("url")
            domain = extract_domain_from_url(url_field)

            match = match_domain(domain, ruleset)
            if not match:
                skipped += 1; continue

            category, risk = match
            if not risk_gte(risk, "low"):
                skipped += 1; continue

            flagged.append({
                "timestamp":         g("timestamp"),
                "src_ip":            g("src_ip"),
                "user":              g("user", g("src_ip")),
                "method":            g("method", "GET"),
                "url":               url_field,
                "matched_domain":    domain,
                "status_code":       g("status_code", "200"),
                "action":            g("action", "allowed"),
                "bytes_sent":        g("bytes_sent", "0"),
                "bytes_received":    g("bytes_received", "0"),
                "detected_category": category,
                "risk_level":        risk,
                "log_type":          "proxy",
            })

    return flagged, skipped, errors


# ---------------------------------------------------------------------------
# Summary builder (works for all three log types)
# ---------------------------------------------------------------------------
def build_summary(flagged):
    by_domain = {}
    by_risk   = {"high": 0, "medium": 0, "low": 0, "unknown": 0}

    for e in flagged:
        domain = e.get("matched_domain", "")
        risk   = e.get("risk_level", "unknown")

        if domain not in by_domain:
            by_domain[domain] = {
                "category": e.get("detected_category", ""),
                "risk":     risk,
                "count":    0,
            }
        by_domain[domain]["count"] += 1
        by_risk[risk] = by_risk.get(risk, 0) + 1

    by_domain = dict(sorted(by_domain.items(), key=lambda x: x[1]["count"], reverse=True))
    return {"by_domain": by_domain, "by_risk": by_risk}


# ---------------------------------------------------------------------------
# Output formatter
# ---------------------------------------------------------------------------
def format_output(flagged, skipped, errors, summary, ruleset, log_type):
    LOG_TYPE_LABELS = {
        "dns":      "DNS queries",
        "firewall": "firewall entries",
        "proxy":    "proxy requests",
    }
    entry_label = LOG_TYPE_LABELS.get(log_type, "entries")

    output = []
    output.append(f"Log type:             {log_type.upper()}")
    output.append(f"Registry source:      Azure SQL (compass.approved_ai_registry)")
    output.append(f"Domains in registry:  {len(ruleset)}")
    output.append(f"Total entries parsed: {len(flagged) + skipped + len(errors)}")
    output.append(f"AI-related (flagged): {len(flagged)}")
    output.append(f"Non-AI / filtered:    {skipped}")
    output.append(f"Parse errors:         {len(errors)}\n")
    output.append("Risk Breakdown:")
    for level in ["high", "medium", "low", "unknown"]:
        count = summary["by_risk"].get(level, 0)
        output.append(f"  {level:<8} {count}")

    output.append(f"\nTop AI Domains:")
    for domain, info in list(summary["by_domain"].items())[:10]:
        output.append(
            f"  {domain:<35} {info['category']:<20} {info['risk']:<10} {info['count']} {entry_label}"
        )

    # Extra: POST warning for proxy logs
    if log_type == "proxy":
        post_count = sum(1 for e in flagged if e.get("method", "").upper() == "POST")
        if post_count > 0:
            output.append(f"\n⚠  {post_count} POST request(s) detected to AI services.")
            output.append(f"   POST requests may indicate data submission to external AI tools.")

    # Extra: blocked entries for firewall logs
    if log_type == "firewall":
        blocked = sum(1 for e in flagged if "block" in e.get("action", "").lower() or "deny" in e.get("action", "").lower())
        if blocked > 0:
            output.append(f"\n✓  {blocked} connection(s) were already blocked by the firewall.")

    return "\n".join(output)


# ---------------------------------------------------------------------------
# Azure Function routes
# ---------------------------------------------------------------------------
@app.function_name(name="parse")
@app.route(route="parse", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def parse_get(req: func.HttpRequest) -> func.HttpResponse:
    return func.HttpResponse(HTML_PAGE, status_code=200, mimetype="text/html")


@app.function_name(name="parse_post")
@app.route(route="parse", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
def parse_post(req: func.HttpRequest) -> func.HttpResponse:
    file = req.files.get("logfile")
    if not file:
        return func.HttpResponse("No file uploaded.", status_code=400)

    # Read log type hint from form data (sent by scanning.html)
    log_type_hint = req.form.get("log_type", "dns").lower()
    if log_type_hint not in ("dns", "firewall", "proxy"):
        log_type_hint = "dns"

    with tempfile.NamedTemporaryFile(delete=False, suffix=".log") as tmp:
        tmp.write(file.read())
        tmp_path = tmp.name

    try:
        # Auto-detect format from file content, using hint as fallback
        log_type = detect_log_type(tmp_path, hint=log_type_hint)

        # Load ruleset from Azure SQL
        ruleset = build_ruleset_from_azure()

        # Parse based on detected type
        if log_type == "firewall":
            flagged, skipped, errors = parse_firewall(tmp_path, ruleset)
        elif log_type == "proxy":
            flagged, skipped, errors = parse_proxy(tmp_path, ruleset)
        else:
            flagged, skipped, errors = parse_dns(tmp_path, ruleset)

        summary = build_summary(flagged)
        output  = format_output(flagged, skipped, errors, summary, ruleset, log_type)

        return func.HttpResponse(output, status_code=200)

    except Exception as e:
        return func.HttpResponse(
            f"Error: {str(e)}\n\n{traceback.format_exc()}", status_code=500
        )
    finally:
        os.unlink(tmp_path)
