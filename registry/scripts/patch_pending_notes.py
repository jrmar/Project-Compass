"""
patch_pending_notes.py
----------------------
One-time patch to write reviewer_notes on the 10 pending demo items
that were left without notes after bulk_approve.py hit an UPDATE
permission error (before the GRANT UPDATE was added to compass_reviewer).

Run once after granting UPDATE on compass.pending_ai_registry to compass_reviewer.
Safe to re-run - only touches rows where review_status = 'Pending'.
"""

import os
import sys
import pyodbc
from dotenv import load_dotenv
from classify_domain import classify

load_dotenv()


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


def run():
    print("[INFO] Connecting...")
    conn   = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT id, normalized_domain
        FROM compass.pending_ai_registry
        WHERE review_status = 'Pending'
        AND source_name = 'Microsoft Purview'
        ORDER BY id ASC
        """
    )
    rows = cursor.fetchall()
    print(f"[INFO] Found {len(rows)} pending items to patch.\n")

    updated = 0
    for pid, nd in rows:
        cl   = classify(nd)
        note = (
            f"[PENDING FOR REVIEW] Confidence: {cl['confidence'].upper()}. "
            f"Suggested risk: {cl['risk']}. {cl['reason']}"
        )
        cursor.execute(
            """
            UPDATE compass.pending_ai_registry
            SET reviewer_notes = ?
            WHERE id = ? AND review_status = 'Pending'
            """,
            note[:2000],
            pid
        )
        print(f"  [UPDATED] {nd:<42s}  {cl['risk']:<12s}  {cl['confidence'].upper()}")
        updated += 1

    conn.commit()
    cursor.close()
    conn.close()
    print(f"\n[DONE] Updated notes on {updated} pending items.")


if __name__ == "__main__":
    run()
