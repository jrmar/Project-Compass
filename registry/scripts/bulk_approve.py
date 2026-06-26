"""
bulk_approve.py
---------------
Bulk-approves pending registry entries sourced from Microsoft Purview.

Approves all but a small set of curated items left in pending to
demonstrate the human review workflow. Generates a reviewer report
summarizing what was approved and what needs attention.

Enterprise note: In production this script would be triggered automatically
when the import script detects new domains from the Purview list. For this
project it is run manually by the security reviewer.

Usage:
    python bulk_approve.py              # live run
    python bulk_approve.py --dry-run    # preview without DB writes
    python bulk_approve.py --stats      # classification breakdown only
"""

import os
import sys
import argparse
from datetime import datetime, timezone

import pyodbc
from dotenv import load_dotenv
from classify_domain import classify

load_dotenv()

REGISTRY_VERSION  = "v1.0-purview-bulk"
APPROVER_NAME     = "system-auto"
REPORT_OUTPUT     = "compass_registry_review_report.txt"

# Number of domains to leave in pending for human review (demo purposes)
LEAVE_IN_PENDING  = 10

# Map classifier risk levels to the 3 values the DB constraint allows
RISK_MAP = {
    "Low":          "Low",
    "Medium":       "Medium",
    "Medium-High":  "High",
    "High":         "High",
}


def get_connection():
    server   = os.getenv("AZURE_SQL_SERVER")
    database = os.getenv("AZURE_SQL_DATABASE")
    username = os.getenv("AZURE_SQL_USERNAME")
    password = os.getenv("AZURE_SQL_PASSWORD")
    driver   = os.getenv("AZURE_SQL_DRIVER", "{ODBC Driver 18 for SQL Server}")

    if not all([server, database, username, password]):
        print("[ERROR] Missing environment variables. Check your .env file.")
        sys.exit(1)

    conn_str = (
        f"DRIVER={driver};SERVER={server};DATABASE={database};"
        f"UID={username};PWD={password};"
        f"Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;"
    )
    return pyodbc.connect(conn_str)


def get_pending_items(cursor, source_filter="Microsoft Purview"):
    cursor.execute(
        """
        SELECT id, domain_pattern, normalized_domain, source_name
        FROM compass.pending_ai_registry
        WHERE review_status = 'Pending'
        AND source_name = ?
        ORDER BY id ASC
        """,
        source_filter
    )
    return cursor.fetchall()


def select_pending_demo_set(classified_items, count=10):
    """
    Select a diverse set of items to leave in pending for demo review.
    Prioritizes: unclassified > pattern-matched > high-risk > variety.
    """
    reserved = []

    # 4 fully unclassified (default confidence) - best for showing review workflow
    defaults = [e for e in classified_items if e["cl"]["confidence"] == "default"]
    reserved.extend(defaults[:4])

    # 3 pattern-matched (.ai / gpt / bot domains) - interesting edge cases
    patterns = [e for e in classified_items
                if e["cl"]["confidence"] == "pattern"
                and e not in reserved]
    reserved.extend(patterns[:3])

    # 3 high-risk with high confidence - show that even known tools need oversight
    high_risk = [e for e in classified_items
                 if e["cl"]["risk"] in ("High", "Medium-High")
                 and e["cl"]["confidence"] == "high"
                 and e not in reserved]
    reserved.extend(high_risk[:3])

    # If we couldn't fill the set, pad with whatever's left
    remaining = [e for e in classified_items if e not in reserved]
    while len(reserved) < count and remaining:
        reserved.append(remaining.pop(0))

    return reserved[:count]


def approve_entry(cursor, pending_id, cl, dry_run=False):
    db_risk = RISK_MAP.get(cl["risk"], "Medium")
    notes   = f"[AUTO-APPROVED] Source: Microsoft Purview. {cl['reason']}"

    if dry_run:
        return True
    try:
        cursor.execute(
            "EXEC compass.usp_ApproveRegistryEntry ?, ?, ?, ?, ?, ?, ?, ?",
            pending_id,
            cl["tool_name"],
            cl["category"],
            db_risk,
            "Approved",
            APPROVER_NAME,
            notes[:2000],
            REGISTRY_VERSION
        )
        return True
    except Exception as e:
        print(f"  [ERROR] ID {pending_id}: {e}")
        return False


def update_pending_notes(cursor, pending_id, cl, dry_run=False):
    note = (
        f"[PENDING FOR REVIEW] Confidence: {cl['confidence'].upper()}. "
        f"Suggested risk: {cl['risk']}. {cl['reason']}"
    )
    if dry_run:
        return
    cursor.execute(
        """
        UPDATE compass.pending_ai_registry
        SET reviewer_notes = ?
        WHERE id = ? AND review_status = 'Pending'
        """,
        note[:2000],
        pending_id
    )


def generate_report(classified_items, approved, pending_set, dry_run, timestamp):
    """Generate a plain-text reviewer report and save to file."""

    # Build category and risk breakdowns
    cat_counts  = {}
    risk_counts = {"Low": 0, "Medium": 0, "Medium-High": 0, "High": 0}

    for e in classified_items:
        cat  = e["cl"]["category"]
        risk = e["cl"]["risk"]
        cat_counts[cat]   = cat_counts.get(cat, 0) + 1
        if risk in risk_counts:
            risk_counts[risk] += 1

    lines = []
    lines.append("=" * 70)
    lines.append("  PROJECT COMPASS - Registry Bulk Approval Report")
    lines.append(f"  Registry Version : {REGISTRY_VERSION}")
    lines.append(f"  Source           : Microsoft Purview Supported AI Sites")
    lines.append(f"  Generated        : {timestamp}")
    lines.append(f"  Mode             : {'DRY RUN - no DB changes' if dry_run else 'LIVE'}")
    lines.append("=" * 70)

    lines.append("")
    lines.append("SUMMARY")
    lines.append("-" * 40)
    lines.append(f"  Total domains processed : {len(classified_items)}")
    lines.append(f"  Auto-approved           : {len(approved)}")
    lines.append(f"  Left in pending         : {len(pending_set)}")
    lines.append(f"  Approver                : {APPROVER_NAME}")
    lines.append("")

    lines.append("APPROVED REGISTRY - CATEGORY BREAKDOWN")
    lines.append("-" * 40)
    for cat, cnt in sorted(cat_counts.items(), key=lambda x: -x[1]):
        lines.append(f"  {cat:<38s}  {cnt:>4}")
    lines.append("")

    lines.append("APPROVED REGISTRY - DEFAULT RISK DISTRIBUTION")
    lines.append("-" * 40)
    lines.append("  (Risk is a baseline starting point. DNS log analysis")
    lines.append("   and NIST scoring determine operational risk level.)")
    lines.append("")
    for risk, cnt in risk_counts.items():
        bar = "█" * min(cnt // 10, 40)
        lines.append(f"  {risk:<15s}  {cnt:>4}  {bar}")
    lines.append("")

    lines.append("PENDING REVIEW QUEUE")
    lines.append("-" * 40)
    lines.append(f"  {len(pending_set)} domains require manual security review.")
    lines.append("  These were selected to represent a variety of classification")
    lines.append("  scenarios. Use usp_ApproveRegistryEntry or usp_RejectRegistryEntry")
    lines.append("  to action each item.")
    lines.append("")
    lines.append(f"  {'ID':<6}  {'Domain':<42}  {'Risk':<12}  {'Confidence'}")
    lines.append(f"  {'-'*6}  {'-'*42}  {'-'*12}  {'-'*20}")

    for e in pending_set:
        cl = e["cl"]
        lines.append(
            f"  {e['id']:<6}  {e['normalized_domain']:<42}  "
            f"{cl['risk']:<12}  {cl['confidence'].upper()}"
        )

    lines.append("")
    lines.append("  To view all pending items in Azure:")
    lines.append("    EXEC compass.usp_GetPendingItems")
    lines.append("")

    lines.append("REVIEW GUIDANCE FOR PENDING ITEMS")
    lines.append("-" * 40)
    lines.append("  For each pending domain, the security reviewer should confirm:")
    lines.append("  1. Is the vendor legitimate with a clear privacy policy?")
    lines.append("  2. Can submitted data be used for model training?")
    lines.append("  3. Does the tool support enterprise controls (SSO, DPA)?")
    lines.append("  4. Is there a confirmed business need within the organization?")
    lines.append("  5. What is the appropriate final risk level and approval status?")
    lines.append("")
    lines.append("  Approval status options:")
    lines.append("    Approved             - Permitted for organizational use")
    lines.append("    Approved_Restricted  - Permitted with usage restrictions")
    lines.append("    Monitor              - Permitted but flagged for monitoring")
    lines.append("    Blocked              - Not permitted; send to enforcement")
    lines.append("")

    lines.append("ENTERPRISE AUTOMATION NOTE")
    lines.append("-" * 40)
    lines.append("  In a production deployment, the Purview import script")
    lines.append("  (import_purview_domains.py) would run on a scheduled basis")
    lines.append("  (e.g., weekly cron) to detect new AI sites added to the")
    lines.append("  Microsoft Purview list. Only net-new domains would be staged")
    lines.append("  in pending - already approved or already pending domains")
    lines.append("  are skipped automatically. This keeps the registry current")
    lines.append("  without re-reviewing domains already actioned.")
    lines.append("")
    lines.append("=" * 70)

    report_text = "\n".join(lines)

    # Save to file
    try:
        with open(REPORT_OUTPUT, "w", encoding="utf-8") as f:
            f.write(report_text)
        print(f"\n[REPORT] Saved to: {REPORT_OUTPUT}")
    except Exception as e:
        print(f"\n[WARN] Could not save report file: {e}")

    return report_text


def run(dry_run=False, stats_only=False):
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    print("=" * 65)
    print("  COMPASS Bulk Approval")
    print(f"  Registry Version : {REGISTRY_VERSION}")
    print(f"  Mode             : {'STATS ONLY' if stats_only else 'DRY RUN' if dry_run else 'LIVE'}")
    print(f"  Time             : {timestamp}")
    print("=" * 65)

    print("[INFO] Connecting to Azure SQL...")
    conn   = get_connection()
    cursor = conn.cursor()
    print("[INFO] Connected.")

    rows = get_pending_items(cursor)
    print(f"[INFO] Found {len(rows)} pending Purview domains.\n")

    # Classify all
    classified_items = []
    for row in rows:
        pid, pattern, nd, source = row
        cl = classify(nd)
        classified_items.append({
            "id":       pid,
            "domain_pattern":    pattern,
            "normalized_domain": nd,
            "source_name":       source,
            "cl":       cl
        })

    # Select items to leave in pending
    pending_set  = select_pending_demo_set(classified_items, count=LEAVE_IN_PENDING)
    pending_ids  = {e["id"] for e in pending_set}
    approve_list = [e for e in classified_items if e["id"] not in pending_ids]

    # Print breakdown
    cat_counts = {}
    for e in classified_items:
        cat = e["cl"]["category"]
        cat_counts[cat] = cat_counts.get(cat, 0) + 1

    print("── Classification Breakdown ─────────────────────────────────")
    print(f"  Will auto-approve  : {len(approve_list)}")
    print(f"  Will leave pending : {len(pending_set)}")
    print()
    for cat, cnt in sorted(cat_counts.items(), key=lambda x: -x[1]):
        print(f"  {cat:<38s}  {cnt}")
    print()

    if stats_only:
        generate_report(classified_items, approve_list, pending_set, dry_run, timestamp)
        cursor.close()
        conn.close()
        return

    # ---- Approve ----
    print("── Auto-Approving ───────────────────────────────────────────")
    approved_count = 0
    failed_count   = 0
    batch_size     = 50

    for i, entry in enumerate(approve_list):
        ok = approve_entry(cursor, entry["id"], entry["cl"], dry_run=dry_run)
        if ok:
            approved_count += 1
        else:
            failed_count += 1

        if not dry_run and (i + 1) % batch_size == 0:
            conn.commit()
            print(f"  [BATCH] {i + 1}/{len(approve_list)} committed...")

    if not dry_run:
        conn.commit()
    print(f"  Approved: {approved_count}   Failed: {failed_count}")
    print()

    # ---- Update notes on pending items ----
    print("── Pending Items (left for human review) ────────────────────")
    for entry in pending_set:
        cl = entry["cl"]
        update_pending_notes(cursor, entry["id"], cl, dry_run=dry_run)
        print(
            f"  [PENDING]  {entry['normalized_domain']:<40s}  "
            f"{cl['risk']:<12s}  confidence: {cl['confidence'].upper()}"
        )

    if not dry_run:
        conn.commit()

    cursor.close()
    conn.close()

    # ---- Generate report ----
    report = generate_report(
        classified_items, approve_list, pending_set, dry_run, timestamp
    )
    print()
    print(report)

    print("=" * 65)
    print(f"  Done.  Approved: {approved_count}  |  Pending: {len(pending_set)}")
    print("=" * 65)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Compass - Bulk Registry Approver")
    parser.add_argument("--dry-run", action="store_true", help="Preview without DB writes")
    parser.add_argument("--stats",   action="store_true", help="Classification stats only")
    args = parser.parse_args()
    run(dry_run=args.dry_run, stats_only=args.stats)
