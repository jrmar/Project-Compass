#!/usr/bin/env python3
"""
dns_ai_parser.py
----------------
Parses DNS logs and detects access to AI services.

Expected log format (CSV):
  timestamp, src_ip, user, query, type, response_ip, rcode, category, risk_level

Usage:
  python dns_ai_parser.py <log_file> [options]

Options:
  --output-dir DIR     Directory for output files (default: ./reports)
  --format FORMAT      Output format: csv, json, or both (default: both)
  --custom-domains     Path to a text file of additional domains to flag (one per line)
  --min-risk LEVEL     Only report entries at or above this risk: low, medium, high, unknown (default: low)
  --summary-only       Print only the summary table, not individual flagged entries
"""

import csv
import json
import argparse
import sys
import os
from datetime import datetime, timezone
from collections import defaultdict

# ---------------------------------------------------------------------------
# AI Domain Ruleset
# Each entry: (domain_suffix, category, risk_level)
# Matching is suffix-based so subdomains are caught automatically.
# ---------------------------------------------------------------------------
AI_DOMAINS = [
    # LLM APIs
    ("api.openai.com",              "LLM API",          "medium"),
    ("openai.com",                  "LLM Platform",     "medium"),
    ("chat.openai.com",             "LLM Assistant",    "medium"),
    ("claude.ai",                   "LLM Assistant",    "medium"),
    ("api.anthropic.com",           "LLM API",          "high"),
    ("anthropic.com",               "LLM Platform",     "medium"),
    ("generativelanguage.googleapis.com", "LLM API",    "high"),
    ("gemini.google.com",           "LLM Assistant",    "medium"),
    ("aistudio.google.com",         "LLM Platform",     "medium"),
    ("api.mistral.ai",              "LLM API",          "high"),
    ("mistral.ai",                  "LLM Platform",     "medium"),
    ("api.cohere.com",              "LLM API",          "high"),
    ("cohere.com",                  "LLM Platform",     "medium"),
    ("api.together.xyz",            "LLM API",          "high"),
    ("together.ai",                 "LLM Platform",     "medium"),
    ("api.groq.com",                "LLM API",          "high"),
    ("groq.com",                    "LLM Platform",     "medium"),
    ("huggingface.co",              "ML Platform",      "medium"),
    ("api-inference.huggingface.co","LLM API",          "high"),
    ("replicate.com",               "ML Platform",      "medium"),

    # AI-Powered Tools
    ("copilot.microsoft.com",       "AI Assistant",     "medium"),
    ("bing.com",                    "AI Search",        "low"),
    ("perplexity.ai",               "AI Search",        "medium"),
    ("you.com",                     "AI Search",        "low"),
    ("phind.com",                   "AI Dev Search",    "low"),
    ("cursor.sh",                   "AI Code Editor",   "medium"),
    ("codeium.com",                 "AI Code Tool",     "medium"),
    ("tabnine.com",                 "AI Code Tool",     "low"),
    ("github.com/features/copilot", "AI Code Tool",     "low"),

    # Image / Audio / Video Generation
    ("midjourney.com",              "Image Generation", "high"),
    ("api.stability.ai",            "Image Gen API",    "high"),
    ("stability.ai",                "Image Generation", "high"),
    ("runway.ml",                   "Video Generation", "high"),
    ("runwayml.com",                "Video Generation", "high"),
    ("elevenlabs.io",               "Audio Generation", "high"),
    ("api.elevenlabs.io",           "Audio Gen API",    "high"),
    ("suno.ai",                     "Audio Generation", "high"),
    ("udio.com",                    "Audio Generation", "high"),
    ("pika.art",                    "Video Generation", "high"),

    # Other notable AI services
    ("character.ai",                "AI Chatbot",       "medium"),
    ("inflection.ai",               "LLM Platform",     "medium"),
    ("pi.ai",                       "AI Assistant",     "medium"),
    ("jasper.ai",                   "AI Writing",       "medium"),
    ("writesonic.com",              "AI Writing",       "medium"),
    ("copy.ai",                     "AI Writing",       "medium"),
    ("notion.so",                   "AI-Powered Tool",  "low"),   # has AI features
]

RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "unknown": 3}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_custom_domains(path):
    """Load extra domains from a plain-text file (one domain per line)."""
    extras = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                extras.append((line, "Custom", "unknown"))
    return extras


def build_ruleset(custom_domains=None):
    rules = list(AI_DOMAINS)
    if custom_domains:
        rules.extend(custom_domains)
    # Sort longest suffix first so more-specific rules match before general ones
    rules.sort(key=lambda r: len(r[0]), reverse=True)
    return rules


def match_domain(query, ruleset):
    """Return (category, risk_level) if query matches any rule, else None."""
    q = query.lower().rstrip(".")
    for domain, category, risk in ruleset:
        d = domain.lower()
        if q == d or q.endswith("." + d):
            return category, risk
    return None


def risk_gte(risk, min_risk):
    return RISK_ORDER.get(risk, 3) >= RISK_ORDER.get(min_risk, 0)


def parse_log(filepath, ruleset, min_risk="low"):
    """
    Parse the DNS log CSV and return:
      flagged  - list of dicts for AI-related entries at or above min_risk
      skipped  - count of non-AI or below-threshold entries
      errors   - list of (line_num, raw_line, error_msg) for unparseable rows
    """
    flagged = []
    skipped = 0
    errors = []

    with open(filepath, newline="", encoding="utf-8") as f:
        for lineno, raw in enumerate(f, start=1):
            line = raw.strip()

            # Skip blank lines and comments
            if not line or line.startswith("#"):
                continue

            # Skip header row
            if line.startswith("timestamp,"):
                continue

            # Parse CSV row
            try:
                row = next(csv.reader([line]))
            except Exception as e:
                errors.append((lineno, raw.rstrip(), str(e)))
                continue

            if len(row) < 3:
                errors.append((lineno, raw.rstrip(), "Too few fields"))
                continue

            # Map fields to match: timestamp, client_ip, query_domain, query_type, response_code, bytes_out
            timestamp   = row[0].strip() if len(row) > 0 else ""
            src_ip      = row[1].strip() if len(row) > 1 else ""
            user        = src_ip  # no user field in this log; fall back to IP
            query       = row[2].strip() if len(row) > 2 else ""
            qtype       = row[3].strip() if len(row) > 3 else ""
            response_ip = ""
            rcode       = row[4].strip() if len(row) > 4 else ""
            log_cat     = ""
            log_risk    = ""

            match = match_domain(query, ruleset)
            if not match:
                skipped += 1
                continue

            detected_category, detected_risk = match

            # Use the log's own risk if it's more severe (takes the higher of the two)
            effective_risk = detected_risk
            if RISK_ORDER.get(log_risk, -1) > RISK_ORDER.get(detected_risk, -1):
                effective_risk = log_risk

            if not risk_gte(effective_risk, min_risk):
                skipped += 1
                continue

            flagged.append({
                "timestamp":          timestamp,
                "src_ip":             src_ip,
                "user":               user,
                "query":              query,
                "query_type":         qtype,
                "response_ip":        response_ip,
                "rcode":              rcode,
                "log_category":       log_cat,
                "detected_category":  detected_category,
                "risk_level":         effective_risk,
            })

    return flagged, skipped, errors


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def build_summary(flagged):
    """Aggregate flagged entries into per-user and per-domain summaries."""
    by_user   = defaultdict(lambda: defaultdict(int))   # user -> domain -> count
    by_domain = defaultdict(lambda: {"count": 0, "risk": "low", "category": ""})
    by_risk   = defaultdict(int)

    for entry in flagged:
        user   = entry["user"] or entry["src_ip"]
        domain = entry["query"]
        risk   = entry["risk_level"]

        by_user[user][domain] += 1
        by_domain[domain]["count"] += 1
        by_domain[domain]["category"] = entry["detected_category"]
        # Escalate stored risk if this entry is higher
        if RISK_ORDER.get(risk, 0) > RISK_ORDER.get(by_domain[domain]["risk"], 0):
            by_domain[domain]["risk"] = risk
        by_risk[risk] += 1

    return {
        "by_user":   {u: dict(domains) for u, domains in by_user.items()},
        "by_domain": dict(by_domain),
        "by_risk":   dict(by_risk),
    }


def write_csv(flagged, summary, output_dir, base_name):
    # Flagged entries
    entries_path = os.path.join(output_dir, f"{base_name}_flagged.csv")
    fieldnames = [
        "timestamp", "src_ip", "user", "query", "query_type",
        "response_ip", "rcode", "log_category", "detected_category", "risk_level"
    ]
    with open(entries_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(flagged)

    # Domain summary
    domain_path = os.path.join(output_dir, f"{base_name}_domain_summary.csv")
    with open(domain_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["domain", "category", "risk_level", "total_queries"])
        writer.writeheader()
        for domain, info in sorted(summary["by_domain"].items(),
                                   key=lambda x: -x[1]["count"]):
            writer.writerow({
                "domain":        domain,
                "category":      info["category"],
                "risk_level":    info["risk"],
                "total_queries": info["count"],
            })

    # User summary
    user_path = os.path.join(output_dir, f"{base_name}_user_summary.csv")
    with open(user_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["user", "domain", "query_count"])
        writer.writeheader()
        for user, domains in sorted(summary["by_user"].items()):
            for domain, count in sorted(domains.items(), key=lambda x: -x[1]):
                writer.writerow({"user": user, "domain": domain, "query_count": count})

    return entries_path, domain_path, user_path


def write_json(flagged, summary, output_dir, base_name):
    path = os.path.join(output_dir, f"{base_name}_report.json")
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_flagged_queries": len(flagged),
            "by_risk":   summary["by_risk"],
            "by_domain": summary["by_domain"],
            "by_user":   summary["by_user"],
        },
        "flagged_entries": flagged,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    return path


def print_terminal_summary(flagged, summary, errors, skipped, log_file):
    total = len(flagged) + skipped
    sep = "=" * 64

    print(f"\n{sep}")
    print(f"  DNS AI Access Detection Report")
    print(f"  Log file : {log_file}")
    print(f"  Run time : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(sep)
    print(f"\n  Total entries parsed : {total + len(errors)}")
    print(f"  AI-related (flagged) : {len(flagged)}")
    print(f"  Non-AI / filtered    : {skipped}")
    print(f"  Parse errors         : {len(errors)}")

    print(f"\n--- Risk Breakdown ---")
    risk_colors = {
        "high":    "\033[91m",  # red
        "medium":  "\033[93m",  # yellow
        "low":     "\033[92m",  # green
        "unknown": "\033[90m",  # gray
    }
    reset = "\033[0m"
    risk_square = "■"
    for level in ["high", "medium", "low", "unknown"]:
        count = summary["by_risk"].get(level, 0)
        color = risk_colors[level]
        squares = f"{color}{risk_square * count}{reset}"
        print(f"  {color}{level:<8}{reset} {count:>4}  {squares}")

    print(f"\n--- Top AI Domains ---")
    top_domains = sorted(summary["by_domain"].items(), key=lambda x: -x[1]["count"])[:10]
    print(f"  {'Domain':<35} {'Category':<20} {'Risk':<8} {'Queries':>7}")
    print(f"  {'-'*35} {'-'*20} {'-'*8} {'-'*7}")
    for domain, info in top_domains:
        print(f"  {domain:<35} {info['category']:<20} {info['risk']:<8} {info['count']:>7}")

    print(f"\n--- Users with AI Access ---")
    print(f"  {'User':<15} {'Unique Domains':>14} {'Total Queries':>13}")
    print(f"  {'-'*15} {'-'*14} {'-'*13}")
    for user, domains in sorted(summary["by_user"].items()):
        total_q = sum(domains.values())
        print(f"  {user:<15} {len(domains):>14} {total_q:>13}")

    if errors:
        print(f"\n--- Parse Errors ---")
        for lineno, raw, msg in errors[:10]:
            print(f"  Line {lineno}: {msg}")
            print(f"    {raw[:80]}")

    print(f"\n--- Report Summary ---")
    print(f"  This report identifies AI-related DNS activity across your network.")
    print(f"  {len(flagged)} of {total + len(errors)} total queries matched known AI services,")
    print(f"  spanning {len(summary['by_domain'])} unique domains and {len(summary['by_user'])} unique users/IPs.")
    print(f"  Risk levels reflect domain sensitivity (e.g. direct API access scores higher")
    print(f"  than browser-based assistants). Full detail is available in the output files below.")

    print(f"\n{sep}\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Detect AI service access in DNS logs."
    )
    parser.add_argument("log_file",
                        help="Path to the DNS log CSV file")
    parser.add_argument("--output-dir", default="reports",
                        help="Directory to write output files (default: ./reports)")
    parser.add_argument("--format", choices=["csv", "json", "both"], default="both",
                        help="Output format (default: both)")
    parser.add_argument("--custom-domains",
                        help="Path to a text file of additional domains to detect (one per line)")
    parser.add_argument("--min-risk", choices=["low", "medium", "high", "unknown"],
                        default="low",
                        help="Minimum risk level to include in report (default: low)")
    parser.add_argument("--summary-only", action="store_true",
                        help="Print only the summary table, skip per-entry listing")
    args = parser.parse_args()

    # Validate input
    if not os.path.isfile(args.log_file):
        print(f"ERROR: Log file not found: {args.log_file}", file=sys.stderr)
        sys.exit(1)

    # Load custom domains if provided
    custom = []
    if args.custom_domains:
        if not os.path.isfile(args.custom_domains):
            print(f"ERROR: Custom domains file not found: {args.custom_domains}", file=sys.stderr)
            sys.exit(1)
        custom = load_custom_domains(args.custom_domains)
        print(f"Loaded {len(custom)} custom domain(s) from {args.custom_domains}")

    ruleset = build_ruleset(custom)

    # Parse
    print(f"Parsing {args.log_file} ...")
    flagged, skipped, errors = parse_log(args.log_file, ruleset, args.min_risk)
    summary = build_summary(flagged)

    # Terminal output
    print_terminal_summary(flagged, summary, errors, skipped, args.log_file)

    if not args.summary_only and flagged:
        print("--- Flagged Entries ---")
        print(f"  {'Timestamp':<22} {'User':<10} {'Domain':<35} {'Category':<20} {'Risk'}")
        print(f"  {'-'*22} {'-'*10} {'-'*35} {'-'*20} {'-'*8}")
        for e in flagged:
            print(f"  {e['timestamp']:<22} {e['user']:<10} {e['query']:<35} "
                  f"{e['detected_category']:<20} {e['risk_level']}")
        print()

    # Write files
    os.makedirs(args.output_dir, exist_ok=True)
    base_name = os.path.splitext(os.path.basename(args.log_file))[0]
    written = []

    if args.format in ("csv", "both"):
        paths = write_csv(flagged, summary, args.output_dir, base_name)
        written.extend(paths)

    if args.format in ("json", "both"):
        path = write_json(flagged, summary, args.output_dir, base_name)
        written.append(path)

    print("Output files written:")
    for p in written:
        print(f"  {p}")
    print()


if __name__ == "__main__":
    main()
