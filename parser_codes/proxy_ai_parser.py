"""
Project Compass — Proxy Log AI Access Detector
===============================================
Parses proxy server CSV logs and flags HTTP/HTTPS traffic to known
AI-related destinations using the Azure SQL domain registry or the
built-in ruleset.

Supported proxy formats (auto-detected from header row):
  Generic:  timestamp, src_ip, user, method, url, status_code,
            bytes_sent, bytes_received, duration_ms, category, action
  Squid:    timestamp, duration, client_ip, result_code, bytes,
            method, url, user, hierarchy, content_type
  Zscaler:  timestamp, user, department, location, url, category,
            action, risk_score, bytes_sent, bytes_received

Usage:
  python3 proxy_ai_parser.py sample_proxy_logs.csv --output-dir reports
  python3 proxy_ai_parser.py sample_proxy_logs.csv --min-risk medium
  python3 proxy_ai_parser.py sample_proxy_logs.csv --use-azure-registry
  python3 proxy_ai_parser.py sample_proxy_logs.csv --summary-only
"""

import csv
import os
import sys
import json
import argparse
from datetime import datetime, timezone
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Risk ordering
# ---------------------------------------------------------------------------
RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "unknown": -1}


def risk_gte(risk, min_risk):
    return RISK_ORDER.get(risk, -1) >= RISK_ORDER.get(min_risk, 0)


# ---------------------------------------------------------------------------
# Built-in AI domain ruleset
# Format: (domain, category, risk_level)
# ---------------------------------------------------------------------------
def build_ruleset():
    return [
        # ── LLM Assistants ──
        ("openai.com",              "LLM Assistant",     "high"),
        ("chat.openai.com",         "LLM Assistant",     "high"),
        ("api.openai.com",          "LLM API",           "high"),
        ("claude.ai",               "LLM Assistant",     "medium"),
        ("anthropic.com",           "LLM Provider",      "medium"),
        ("gemini.google.com",       "LLM Assistant",     "medium"),
        ("bard.google.com",         "LLM Assistant",     "medium"),
        ("generativelanguage.googleapis.com", "LLM API", "high"),
        ("copilot.microsoft.com",   "LLM Assistant",     "medium"),
        ("bing.com",                "AI Search",         "low"),
        ("perplexity.ai",           "AI Search",         "medium"),
        ("you.com",                 "AI Search",         "low"),
        ("phind.com",               "AI Search",         "low"),
        # ── Image / Video / Audio Generation ──
        ("midjourney.com",          "Image Generation",  "high"),
        ("stability.ai",            "Image Generation",  "high"),
        ("stablediffusionweb.com",  "Image Generation",  "high"),
        ("runwayml.com",            "Video Generation",  "high"),
        ("pika.art",                "Video Generation",  "high"),
        ("suno.ai",                 "Audio Generation",  "high"),
        ("udio.com",                "Audio Generation",  "high"),
        ("elevenlabs.io",           "Audio Generation",  "high"),
        ("synthesia.io",            "Video Generation",  "high"),
        # ── Code Assistants ──
        ("copilot.github.com",      "AI Code Assistant", "medium"),
        ("github.com",              "AI Code Assistant", "low"),
        ("cursor.sh",               "AI Code Assistant", "medium"),
        ("codeium.com",             "AI Code Assistant", "medium"),
        ("tabnine.com",             "AI Code Assistant", "medium"),
        ("replit.com",              "AI Code Assistant", "low"),
        # ── AI Chatbots ──
        ("character.ai",            "AI Chatbot",        "high"),
        ("pi.ai",                   "AI Chatbot",        "medium"),
        ("inflection.ai",           "AI Chatbot",        "medium"),
        ("poe.com",                 "AI Chatbot",        "medium"),
        ("huggingface.co",          "ML Platform",       "medium"),
        # ── AI Writing / Productivity ──
        ("jasper.ai",               "AI Writing",        "medium"),
        ("writesonic.com",          "AI Writing",        "medium"),
        ("copy.ai",                 "AI Writing",        "medium"),
        ("grammarly.com",           "AI Writing",        "low"),
        ("notion.so",               "AI Productivity",   "low"),
        # ── AI Platforms / APIs ──
        ("replicate.com",           "ML Platform",       "high"),
        ("together.ai",             "ML Platform",       "high"),
        ("groq.com",                "LLM API",           "high"),
        ("mistral.ai",              "LLM Provider",      "medium"),
        ("cohere.com",              "LLM API",           "high"),
        ("grok.x.ai",               "LLM Assistant",     "high"),
        ("meta.ai",                 "LLM Assistant",     "medium"),
    ]


# ---------------------------------------------------------------------------
# Azure SQL registry loader
# ---------------------------------------------------------------------------
def build_ruleset_from_azure():
    try:
        import pymssql
    except ImportError:
        raise RuntimeError(
            "pymssql not installed. Run: pip3 install pymssql\n"
            "Or omit --use-azure-registry to use the built-in ruleset."
        )

    conn_str = os.environ.get("AZURE_SQL_CONN", "")
    server   = "compass-registry-srv.database.windows.net"
    database = "compass-registry"
    user     = os.environ.get("AZURE_SQL_USER", "compassadmin")
    password = os.environ.get("AZURE_SQL_PASS", "")

    if not password and "Pwd=" in conn_str:
        for part in conn_str.split(";"):
            if part.strip().startswith("Pwd="):
                password = part.strip()[4:]

    if not password:
        raise RuntimeError(
            "Azure SQL password not found.\n"
            "Set AZURE_SQL_CONN or AZURE_SQL_PASS environment variable."
        )

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
        for domain, category, risk_level in cursor.fetchall():
            ruleset.append((
                domain.strip().lower(),
                category.strip() if category else "Unclassified",
                risk_level.strip().lower() if risk_level else "medium"
            ))
    finally:
        conn.close()

    if not ruleset:
        raise RuntimeError("Azure registry returned 0 domains.")

    return ruleset


# ---------------------------------------------------------------------------
# Domain extraction helpers
# ---------------------------------------------------------------------------
def extract_domain_from_url(url):
    """Extract clean hostname from a full URL string."""
    if not url:
        return ""
    url = url.strip()
    if not url.startswith("http"):
        url = "https://" + url
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        if host.startswith("www."):
            host = host[4:]
        return host.lower()
    except Exception:
        return url.lower()


def match_domain(domain, ruleset):
    """Return (category, risk_level) if domain matches any rule, else None."""
    if not domain:
        return None
    d = domain.lower().rstrip(".")
    for rule_domain, category, risk in ruleset:
        rd = rule_domain.lower()
        if d == rd or d.endswith("." + rd):
            return category, risk
    return None


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------
FORMAT_GENERIC  = "generic"
FORMAT_SQUID    = "squid"
FORMAT_ZSCALER  = "zscaler"

def detect_format(headers):
    """
    Detect proxy log format from header row.
    Returns one of FORMAT_GENERIC, FORMAT_SQUID, FORMAT_ZSCALER.
    """
    h = [col.lower().strip() for col in headers]

    # Zscaler headers contain 'department' or 'location' and 'risk_score'
    if "department" in h or "risk_score" in h or "location" in h:
        return FORMAT_ZSCALER

    # Squid uses 'result_code' and 'hierarchy'
    if "result_code" in h or "hierarchy" in h or "content_type" in h:
        return FORMAT_SQUID

    return FORMAT_GENERIC


def map_row_generic(row, col_map):
    def get(field, default=""):
        idx = col_map.get(field)
        return row[idx].strip() if idx is not None and idx < len(row) else default

    return {
        "timestamp":    get("timestamp"),
        "src_ip":       get("src_ip"),
        "user":         get("user", get("src_ip")),
        "method":       get("method", "GET"),
        "url":          get("url"),
        "status_code":  get("status_code", "200"),
        "bytes_sent":   get("bytes_sent", "0"),
        "bytes_recv":   get("bytes_received", get("bytes_recv", "0")),
        "duration_ms":  get("duration_ms", get("duration", "0")),
        "category":     get("category", ""),
        "action":       get("action", "allowed"),
    }


def map_row_squid(row, col_map):
    def get(field, default=""):
        idx = col_map.get(field)
        return row[idx].strip() if idx is not None and idx < len(row) else default

    result_code = get("result_code", "TCP_MISS/200")
    status = result_code.split("/")[-1] if "/" in result_code else result_code
    action = "blocked" if "DENIED" in result_code.upper() else "allowed"

    return {
        "timestamp":    get("timestamp"),
        "src_ip":       get("client_ip"),
        "user":         get("user", get("client_ip")),
        "method":       get("method", "GET"),
        "url":          get("url"),
        "status_code":  status,
        "bytes_sent":   "0",
        "bytes_recv":   get("bytes", "0"),
        "duration_ms":  get("duration", "0"),
        "category":     get("content_type", ""),
        "action":       action,
    }


def map_row_zscaler(row, col_map):
    def get(field, default=""):
        idx = col_map.get(field)
        return row[idx].strip() if idx is not None and idx < len(row) else default

    action_raw = get("action", "allowed").lower()
    action = "blocked" if "block" in action_raw else "allowed"

    return {
        "timestamp":    get("timestamp"),
        "src_ip":       get("src_ip", ""),
        "user":         get("user", get("src_ip", "")),
        "method":       get("method", "GET"),
        "url":          get("url"),
        "status_code":  get("status_code", "200"),
        "bytes_sent":   get("bytes_sent", "0"),
        "bytes_recv":   get("bytes_received", "0"),
        "duration_ms":  get("duration_ms", "0"),
        "category":     get("category", ""),
        "action":       action,
    }


# ---------------------------------------------------------------------------
# Log parser
# ---------------------------------------------------------------------------
def parse_proxy_log(filepath, ruleset, min_risk="low"):
    """
    Parse a proxy CSV log and return:
      flagged  - list of dicts for AI-related entries at or above min_risk
      skipped  - count of non-AI or below-threshold entries
      errors   - list of (line_num, raw_line, error_msg) for unparseable rows
    """
    flagged = []
    skipped = 0
    errors  = []

    col_map    = None
    log_format = FORMAT_GENERIC

    with open(filepath, newline="", encoding="utf-8") as f:
        for lineno, raw in enumerate(f, start=1):
            line = raw.strip()

            if not line or line.startswith("#"):
                continue

            try:
                row = next(csv.reader([line]))
            except Exception as e:
                errors.append((lineno, raw.rstrip(), str(e)))
                continue

            # Detect header row
            if col_map is None:
                first = row[0].strip().lower() if row else ""
                if first in ("timestamp", "date", "time", "datetime") or "url" in [
                    c.strip().lower() for c in row
                ]:
                    headers    = [h.strip().lower() for h in row]
                    col_map    = {h: i for i, h in enumerate(headers)}
                    log_format = detect_format(row)
                    continue
                else:
                    # No header — default generic positional mapping
                    defaults = [
                        "timestamp","src_ip","user","method","url",
                        "status_code","bytes_sent","bytes_received",
                        "duration_ms","category","action"
                    ]
                    col_map    = {h: i for i, h in enumerate(defaults)}
                    log_format = FORMAT_GENERIC

            if len(row) < 3:
                errors.append((lineno, raw.rstrip(), "Too few fields"))
                continue

            # Map row fields based on detected format
            try:
                if log_format == FORMAT_SQUID:
                    fields = map_row_squid(row, col_map)
                elif log_format == FORMAT_ZSCALER:
                    fields = map_row_zscaler(row, col_map)
                else:
                    fields = map_row_generic(row, col_map)
            except Exception as e:
                errors.append((lineno, raw.rstrip(), f"Field mapping error: {e}"))
                continue

            # Extract domain from URL
            domain = extract_domain_from_url(fields["url"])

            match = match_domain(domain, ruleset)
            if not match:
                skipped += 1
                continue

            detected_category, detected_risk = match

            if not risk_gte(detected_risk, min_risk):
                skipped += 1
                continue

            # Parse numeric fields safely
            def safe_int(val):
                try:
                    return int(str(val).replace(",", "").strip())
                except Exception:
                    return 0

            flagged.append({
                "timestamp":         fields["timestamp"],
                "src_ip":            fields["src_ip"],
                "user":              fields["user"],
                "method":            fields["method"],
                "url":               fields["url"],
                "matched_domain":    domain,
                "status_code":       fields["status_code"],
                "bytes_sent":        safe_int(fields["bytes_sent"]),
                "bytes_received":    safe_int(fields["bytes_recv"]),
                "duration_ms":       safe_int(fields["duration_ms"]),
                "proxy_category":    fields["category"],
                "action":            fields["action"],
                "log_format":        log_format,
                "detected_category": detected_category,
                "risk_level":        detected_risk,
            })

    return flagged, skipped, errors


# ---------------------------------------------------------------------------
# Summary builder
# ---------------------------------------------------------------------------
def build_summary(flagged):
    by_domain  = {}
    by_user    = {}
    by_risk    = {"high": 0, "medium": 0, "low": 0, "unknown": 0}
    by_method  = {}
    by_action  = {}
    total_bytes = 0

    for e in flagged:
        domain = e["matched_domain"]
        user   = e["user"] or e["src_ip"] or "unknown"
        risk   = e["risk_level"]
        method = e["method"].upper() if e["method"] else "UNKNOWN"
        action = e["action"].lower() if e["action"] else "unknown"
        b_total = e["bytes_sent"] + e["bytes_received"]

        # by domain
        if domain not in by_domain:
            by_domain[domain] = {
                "category": e["detected_category"],
                "risk": risk,
                "count": 0,
                "bytes": 0,
                "methods": set(),
                "status_codes": set(),
                "users": set(),
            }
        by_domain[domain]["count"]  += 1
        by_domain[domain]["bytes"]  += b_total
        by_domain[domain]["methods"].add(method)
        by_domain[domain]["status_codes"].add(e["status_code"])
        by_domain[domain]["users"].add(user)

        # by user
        if user not in by_user:
            by_user[user] = {"domains": set(), "count": 0, "bytes": 0, "methods": set()}
        by_user[user]["domains"].add(domain)
        by_user[user]["count"]   += 1
        by_user[user]["bytes"]   += b_total
        by_user[user]["methods"].add(method)

        # aggregates
        by_risk[risk]     = by_risk.get(risk, 0) + 1
        by_method[method] = by_method.get(method, 0) + 1
        by_action[action] = by_action.get(action, 0) + 1
        total_bytes       += b_total

    # Convert sets to sorted lists
    for d in by_domain.values():
        d["methods"]      = sorted(d["methods"])
        d["status_codes"] = sorted(d["status_codes"])
        d["users"]        = sorted(d["users"])
    for u in by_user.values():
        u["domains"] = sorted(u["domains"])
        u["methods"] = sorted(u["methods"])

    by_domain = dict(sorted(by_domain.items(), key=lambda x: x[1]["count"], reverse=True))
    by_user   = dict(sorted(by_user.items(),   key=lambda x: x[1]["count"], reverse=True))

    return {
        "by_domain":   by_domain,
        "by_user":     by_user,
        "by_risk":     by_risk,
        "by_method":   by_method,
        "by_action":   by_action,
        "total_bytes": total_bytes,
    }


def format_bytes(b):
    if b < 1024:         return f"{b} B"
    if b < 1024**2:      return f"{b/1024:.1f} KB"
    if b < 1024**3:      return f"{b/1024**2:.1f} MB"
    return f"{b/1024**3:.2f} GB"


# ---------------------------------------------------------------------------
# Terminal output
# ---------------------------------------------------------------------------
def print_terminal_summary(flagged, summary, errors, skipped, log_file):
    sep = "=" * 64
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    total = len(flagged) + skipped

    print(f"\n{sep}")
    print(f"  Project Compass — Proxy Log AI Access Detection Report")
    print(f"  Log file : {os.path.basename(log_file)}")
    print(f"  Run time : {now}")
    print(f"{sep}\n")
    print(f"  Total entries parsed  : {total + len(errors)}")
    print(f"  AI-related (flagged)  : {len(flagged)}")
    print(f"  Non-AI / filtered     : {skipped}")
    print(f"  Parse errors          : {len(errors)}")

    # Detected format
    if flagged:
        fmt = flagged[0].get("log_format", "generic")
        fmt_labels = {"generic": "Generic Proxy", "squid": "Squid Proxy", "zscaler": "Zscaler"}
        print(f"  Log format detected   : {fmt_labels.get(fmt, fmt)}")

    # Risk breakdown
    print(f"\n--- Risk Breakdown ---")
    risk_colors = {
        "high":    "\033[91m",
        "medium":  "\033[93m",
        "low":     "\033[92m",
        "unknown": "\033[90m",
    }
    reset = "\033[0m"
    SCALE = 10
    for level in ["high", "medium", "low", "unknown"]:
        count = summary["by_risk"].get(level, 0)
        color = risk_colors[level]
        squares   = count // SCALE
        remainder = count % SCALE
        bar = f"{color}{'■' * squares}{'·' if remainder > 0 else ''}{reset}"
        print(f"  {color}{level:<8}{reset} {count:>4}  {bar}")
    print(f"  (each ■ = {SCALE} entries)")

    # HTTP method breakdown
    if summary["by_method"]:
        print(f"\n--- HTTP Methods ---")
        for method, count in sorted(summary["by_method"].items(), key=lambda x: -x[1]):
            color = "\033[91m" if method == "POST" else "\033[93m" if method == "PUT" else "\033[92m"
            print(f"  {color}{method:<10}{reset} {count:>4}  "
                  f"{'(data submission — review for data leakage)' if method == 'POST' else ''}")

    # Action breakdown
    if summary["by_action"]:
        print(f"\n--- Proxy Actions ---")
        for action, count in sorted(summary["by_action"].items(), key=lambda x: -x[1]):
            color = "\033[91m" if "block" in action or "deny" in action else "\033[92m"
            print(f"  {color}{action:<12}{reset} {count:>4}")

    # Top AI destinations
    print(f"\n--- Top AI Destinations ---")
    print(f"  {'Domain':<35} {'Category':<22} {'Risk':<10} {'Reqs':>5} {'Data':>10} {'Methods'}")
    print(f"  {'-'*35} {'-'*22} {'-'*10} {'-'*5} {'-'*10} {'-'*12}")
    for domain, info in list(summary["by_domain"].items())[:10]:
        risk  = info["risk"]
        color = risk_colors.get(risk, "")
        methods = ",".join(info["methods"])
        print(
            f"  {domain:<35} {info['category']:<22} "
            f"{color}{risk:<10}{reset} {info['count']:>5} "
            f"{format_bytes(info['bytes']):>10} {methods}"
        )

    # Top users
    print(f"\n--- Users with AI Proxy Traffic ---")
    print(f"  {'User':<22} {'Domains':>8} {'Requests':>10} {'Data':>12} {'Methods'}")
    print(f"  {'-'*22} {'-'*8} {'-'*10} {'-'*12} {'-'*12}")
    for user, info in list(summary["by_user"].items())[:10]:
        methods = ",".join(info["methods"])
        print(
            f"  {user:<22} {len(info['domains']):>8} "
            f"{info['count']:>10} {format_bytes(info['bytes']):>12} {methods}"
        )

    # POST request warning
    post_count = summary["by_method"].get("POST", 0)
    if post_count > 0:
        print(f"\n⚠  {post_count} POST request(s) detected to AI services.")
        print(f"   POST requests may indicate data submission to external AI tools.")
        print(f"   Review these entries for potential data leakage.")

    if errors:
        print(f"\n--- Parse Errors ---")
        for lineno, raw, msg in errors[:10]:
            print(f"  Line {lineno}: {msg}")
            print(f"    {raw[:80]}")

    print(f"\n--- Report Summary ---")
    print(f"  This report identifies proxy traffic to AI-related destinations.")
    print(f"  {len(flagged)} of {total + len(errors)} total requests matched known AI services,")
    print(f"  spanning {len(summary['by_domain'])} unique destinations and "
          f"{len(summary['by_user'])} unique users.")
    print(f"  Total data transferred to/from AI services: {format_bytes(summary['total_bytes'])}")
    print(f"  Full detail is available in the output files below.")
    print(f"\n{sep}\n")


# ---------------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------------
def write_csv(flagged, summary, output_dir, stem):
    os.makedirs(output_dir, exist_ok=True)

    entries_path = os.path.join(output_dir, f"{stem}_flagged.csv")
    if flagged:
        keys = list(flagged[0].keys())
        with open(entries_path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=keys)
            w.writeheader()
            w.writerows(flagged)

    domain_path = os.path.join(output_dir, f"{stem}_domain_summary.csv")
    with open(domain_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["domain","category","risk_level","request_count",
                    "total_bytes","http_methods","unique_users"])
        for domain, info in summary["by_domain"].items():
            w.writerow([
                domain, info["category"], info["risk"],
                info["count"], info["bytes"],
                "|".join(info["methods"]),
                len(info["users"]),
            ])

    user_path = os.path.join(output_dir, f"{stem}_user_summary.csv")
    with open(user_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["user","unique_domains","total_requests","total_bytes","http_methods"])
        for user, info in summary["by_user"].items():
            w.writerow([
                user, len(info["domains"]),
                info["count"], info["bytes"],
                "|".join(info["methods"]),
            ])

    return entries_path, domain_path, user_path


def write_json(flagged, summary, output_dir, stem):
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, f"{stem}_report.json")

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "log_stem":     stem,
        "log_format":   flagged[0]["log_format"] if flagged else "unknown",
        "totals": {
            "flagged":        len(flagged),
            "by_risk":        summary["by_risk"],
            "by_method":      summary["by_method"],
            "by_action":      summary["by_action"],
            "total_bytes":    summary["total_bytes"],
            "unique_domains": len(summary["by_domain"]),
            "unique_users":   len(summary["by_user"]),
            "post_requests":  summary["by_method"].get("POST", 0),
        },
        "top_domains": [
            {
                "domain":       domain,
                "category":     info["category"],
                "risk":         info["risk"],
                "requests":     info["count"],
                "bytes":        info["bytes"],
                "methods":      info["methods"],
                "unique_users": len(info["users"]),
            }
            for domain, info in list(summary["by_domain"].items())[:20]
        ],
        "top_users": [
            {
                "user":           user,
                "unique_domains": len(info["domains"]),
                "total_requests": info["count"],
                "total_bytes":    info["bytes"],
                "domains_seen":   info["domains"],
                "methods":        info["methods"],
            }
            for user, info in list(summary["by_user"].items())[:20]
        ],
        "flagged_entries": flagged,
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    return path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Project Compass — Proxy Log AI Access Detector"
    )
    parser.add_argument("log_file",
        help="Path to the proxy CSV log file")
    parser.add_argument("--output-dir", default="reports",
        help="Directory for output files (default: reports)")
    parser.add_argument("--min-risk", default="low",
        choices=["low", "medium", "high"],
        help="Minimum risk level to include in output (default: low)")
    parser.add_argument("--summary-only", action="store_true",
        help="Print summary only, skip per-entry output")
    parser.add_argument("--format", default="both",
        choices=["csv", "json", "both"],
        help="Output format (default: both)")
    parser.add_argument("--use-azure-registry", action="store_true",
        help="Fetch AI domain ruleset from Azure SQL instead of built-in list")
    args = parser.parse_args()

    if not os.path.isfile(args.log_file):
        print(f"Error: file not found: {args.log_file}", file=sys.stderr)
        sys.exit(1)

    print(f"Parsing {args.log_file} ...")

    if args.use_azure_registry:
        print("Fetching AI domain registry from Azure SQL...")
        try:
            ruleset = build_ruleset_from_azure()
            print(f"Loaded {len(ruleset)} domains from Azure registry.\n")
        except RuntimeError as e:
            print(f"Warning: {e}\nFalling back to built-in ruleset.", file=sys.stderr)
            ruleset = build_ruleset()
    else:
        ruleset = build_ruleset()

    flagged, skipped, errors = parse_proxy_log(
        args.log_file, ruleset, min_risk=args.min_risk
    )
    summary = build_summary(flagged)

    print_terminal_summary(flagged, summary, errors, skipped, args.log_file)

    if not args.summary_only:
        stem = os.path.splitext(os.path.basename(args.log_file))[0]

        written = []
        if args.format in ("csv", "both"):
            paths = write_csv(flagged, summary, args.output_dir, stem)
            written.extend(paths)
        if args.format in ("json", "both"):
            path = write_json(flagged, summary, args.output_dir, stem)
            written.append(path)

        print("Output files written:")
        for p in written:
            print(f"  {p}")
        print()


if __name__ == "__main__":
    main()
