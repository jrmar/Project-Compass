"""
import_purview_domains.py
------------------------
Pulls the Microsoft Purview supported AI sites list, extracts domain patterns,
and stages any new domains in compass.pending_ai_registry for human review.

This script NEVER writes to approved_ai_registry directly.
It only stages findings in the pending table.

Requirements:
    pip install pyodbc requests beautifulsoup4 python-dotenv

Usage:
    python import_purview_domains.py
    python import_purview_domains.py --dry-run    (preview only, no DB writes)
"""

import os
import sys
import hashlib
import argparse
import re
from datetime import datetime, timezone

import requests
import pyodbc
from bs4 import BeautifulSoup
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# ---- Configuration ----
PURVIEW_URL = (
    "https://learn.microsoft.com/en-us/purview/ai-microsoft-purview-supported-sites"
)

# Fallback known AI domains if scraping fails or for offline testing
FALLBACK_DOMAINS = [
    "*.openai.com",
    "*.chatgpt.com",
    "*.anthropic.com",
    "*.claude.ai",
    "*.gemini.google.com",
    "*.bard.google.com",
    "*.midjourney.com",
    "*.perplexity.ai",
    "*.copilot.microsoft.com",
    "*.github.com",
    "*.notion.so",
    "*.elevenlabs.io",
]

# Default suggested risk levels by keyword match
RISK_HINTS = {
    "openai":       "High",
    "chatgpt":      "High",
    "claude":       "Medium",
    "anthropic":    "Medium",
    "midjourney":   "High",
    "elevenlabs":   "High",
    "gemini":       "Medium",
    "bard":         "Medium",
    "perplexity":   "Medium",
    "copilot":      "Low",
    "github":       "Low",
    "notion":       "Low",
}

CATEGORY_HINTS = {
    "openai":       "Generative AI",
    "chatgpt":      "Generative AI",
    "claude":       "Generative AI",
    "anthropic":    "Generative AI",
    "midjourney":   "AI Image Generation",
    "elevenlabs":   "AI Audio/Voice",
    "gemini":       "Generative AI",
    "bard":         "Generative AI",
    "perplexity":   "AI Search",
    "copilot":      "AI Assistant",
    "github":       "Code Assistant",
    "notion":       "Productivity / AI",
}


def get_connection():
    """Build pyodbc connection from environment variables."""
    server   = os.getenv("AZURE_SQL_SERVER")
    database = os.getenv("AZURE_SQL_DATABASE")
    username = os.getenv("AZURE_SQL_USERNAME")
    password = os.getenv("AZURE_SQL_PASSWORD")
    driver   = os.getenv("AZURE_SQL_DRIVER", "{ODBC Driver 18 for SQL Server}")

    if not all([server, database, username, password]):
        print("[ERROR] Missing required environment variables.")
        print("        Copy .env.example to .env and fill in your Azure SQL credentials.")
        sys.exit(1)

    conn_str = (
        f"DRIVER={driver};"
        f"SERVER={server};"
        f"DATABASE={database};"
        f"UID={username};"
        f"PWD={password};"
        f"Encrypt=yes;"
        f"TrustServerCertificate=no;"
        f"Connection Timeout=30;"
    )
    return pyodbc.connect(conn_str)


def fetch_purview_domains():
    """
    Attempt to scrape Microsoft Purview AI sites page for wildcard domain patterns.
    Falls back to FALLBACK_DOMAINS if the page structure changes or is unreachable.
    Returns list of raw domain strings (e.g. '*.chatgpt.com').
    """
    print(f"[INFO] Fetching Purview AI sites from: {PURVIEW_URL}")
    try:
        resp = requests.get(PURVIEW_URL, timeout=15, headers={
            "User-Agent": "Mozilla/5.0 (compatible; CompassRegistryImporter/1.0)"
        })
        resp.raise_for_status()

        soup = BeautifulSoup(resp.text, "html.parser")
        domains = set()

        # Look for wildcard domain patterns in the page text
        text = soup.get_text(separator="\n")
        for line in text.splitlines():
            line = line.strip()
            # Match patterns like *.example.com or example.com
            matches = re.findall(r'\*?\.[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}', line)
            for m in matches:
                if len(m) > 4 and len(m) < 100:
                    domains.add(m.lower())

        if len(domains) >= 5:
            print(f"[INFO] Scraped {len(domains)} domain patterns from Purview page.")
            return sorted(domains)
        else:
            print("[WARN] Scrape returned fewer than 5 domains. Using fallback list.")
            return sorted(FALLBACK_DOMAINS)

    except Exception as e:
        print(f"[WARN] Could not fetch Purview page: {e}")
        print("[WARN] Using fallback domain list.")
        return sorted(FALLBACK_DOMAINS)


def normalize_domain(raw_domain):
    """
    Remove wildcard prefix and lowercase.
    '*.chatgpt.com' -> 'chatgpt.com'
    'chatgpt.com'   -> 'chatgpt.com'
    """
    return raw_domain.lstrip("*.").lower()


def suggest_risk(normalized):
    """Return suggested risk level based on keyword match."""
    for keyword, risk in RISK_HINTS.items():
        if keyword in normalized:
            return risk
    return "Medium"


def suggest_category(normalized):
    """Return suggested category based on keyword match."""
    for keyword, cat in CATEGORY_HINTS.items():
        if keyword in normalized:
            return cat
    return "Generative AI"


def suggest_tool_name(normalized):
    """Derive a human-readable tool name from the domain."""
    parts = normalized.split(".")
    # Use the second-to-last part (e.g. 'chatgpt' from 'chatgpt.com')
    if len(parts) >= 2:
        name = parts[-2].replace("-", " ").title()
        return name
    return normalized.title()


def calculate_hash(domains):
    """SHA-256 of the sorted, newline-joined domain list."""
    content = "\n".join(sorted(domains))
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def get_existing_domains(cursor):
    """Return sets of normalized domains already in approved and pending tables."""
    cursor.execute(
        "SELECT normalized_domain FROM compass.approved_ai_registry WHERE active = 1"
    )
    approved = {row[0].lower() for row in cursor.fetchall()}

    cursor.execute(
        "SELECT normalized_domain FROM compass.pending_ai_registry WHERE review_status = 'Pending'"
    )
    pending = {row[0].lower() for row in cursor.fetchall()}

    return approved, pending


def run_import(dry_run=False):
    print("=" * 60)
    print("  COMPASS Registry Importer")
    print(f"  Source: Microsoft Purview")
    print(f"  Mode:   {'DRY RUN (no DB writes)' if dry_run else 'LIVE'}")
    print(f"  Time:   {datetime.now(timezone.utc).isoformat()}")
    print("=" * 60)

    # Step 1: Fetch domains from Purview
    raw_domains = fetch_purview_domains()
    source_hash = calculate_hash(raw_domains)

    print(f"[INFO] Total domains from source: {len(raw_domains)}")
    print(f"[INFO] Source hash (SHA-256): {source_hash}")

    if dry_run:
        print("\n[DRY RUN] Domains that would be evaluated:")
        for d in raw_domains:
            nd = normalize_domain(d)
            print(f"  {d:40s}  normalized: {nd}  risk: {suggest_risk(nd)}")
        print("\n[DRY RUN] No database changes made.")
        return

    # Step 2: Connect to Azure SQL
    print("[INFO] Connecting to Azure SQL Database...")
    conn = get_connection()
    cursor = conn.cursor()
    print("[INFO] Connected.")

    # Step 3: Load existing domains from DB
    approved_domains, pending_domains = get_existing_domains(cursor)
    print(f"[INFO] Approved registry: {len(approved_domains)} active domains")
    print(f"[INFO] Pending queue:     {len(pending_domains)} pending domains")

    # Step 4: Determine which domains to stage (count first, then INSERT import run)
    # Cannot UPDATE an append-only ledger table, so all counts must be known upfront.
    to_stage = []
    skipped_approved = 0
    skipped_pending = 0

    for raw in raw_domains:
        nd = normalize_domain(raw)
        if nd in approved_domains:
            skipped_approved += 1
        elif nd in pending_domains:
            skipped_pending += 1
        else:
            to_stage.append((raw, nd))

    staged = len(to_stage)

    # Step 5: Insert import run record with final counts (append-only - no UPDATE allowed)
    cursor.execute(
        """
        INSERT INTO compass.registry_import_run
            (source_name, source_url, source_hash, domains_found,
             domains_staged, domains_skipped, imported_by, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        "Microsoft Purview",
        PURVIEW_URL,
        source_hash,
        len(raw_domains),
        staged,
        skipped_approved + skipped_pending,
        "import_script",
        f"Automated import run at {datetime.now(timezone.utc).isoformat()}"
    )
    conn.commit()

    cursor.execute("SELECT @@IDENTITY")
    import_run_id = int(cursor.fetchone()[0])
    print(f"[INFO] Import run recorded. ID: {import_run_id}")
    print(f"[INFO] {staged} new domains to stage, {skipped_approved + skipped_pending} to skip")

    # Step 6: Stage new domains in pending table
    for raw, nd in to_stage:
        cursor.execute(
            """
            INSERT INTO compass.pending_ai_registry (
                domain_pattern, normalized_domain, source_name, change_type,
                suggested_tool_name, suggested_category, suggested_risk_level,
                review_status, import_run_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            raw,
            nd,
            "Microsoft Purview",
            "ADD",
            suggest_tool_name(nd),
            suggest_category(nd),
            suggest_risk(nd),
            "Pending",
            import_run_id
        )
        print(f"  [STAGED]  {raw:40s}  risk: {suggest_risk(nd)}")

    conn.commit()

    cursor.close()
    conn.close()

    print("\n" + "=" * 60)
    print(f"  Import complete.")
    print(f"  Staged for review:        {staged}")
    print(f"  Skipped (already approved): {skipped_approved}")
    print(f"  Skipped (already pending):  {skipped_pending}")
    print(f"\n  Next step: Review pending items in the Compass admin")
    print(f"  or run: EXEC compass.usp_GetPendingItems")
    print("=" * 60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Compass - Purview Registry Importer")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview domains without writing to database"
    )
    args = parser.parse_args()
    run_import(dry_run=args.dry_run)
