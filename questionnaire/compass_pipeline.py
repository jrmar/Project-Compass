"""
compass_pipeline.py
====================
Wires Shivali's real log parser (dns_ai_parser.py) into Mena's NIST
scoring/questionnaire/report (compass_questionnaire.py + compass_nist_controlsv4.py),
through the category bridge (compass_category_bridge.py).

This is the real UC-1 -> UC-2 pipeline. compass_questionnaire.py's demo mode
(DEFAULT_DETECTED_TOOLS) is a fixture stand-in for what this script now
actually produces from a real DNS log file.

Run:
    python3 compass_pipeline.py path/to/log.csv
    python3 compass_pipeline.py path/to/log.csv --min-risk medium
"""

import sys
import os
import argparse
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from dns_ai_parser import parse_log, build_ruleset
from compass_category_bridge import normalize_flagged_entries
from compass_questionnaire import show_inventory, run_questionnaire, generate_report


def build_detected_tools(flagged_normalized: list[dict]) -> tuple[list[dict], list[dict]]:
    """
    Aggregate normalized flagged entries (one row per DNS query) into the
    per-domain tool records that run_questionnaire()/generate_report() expect:
        {"tool_name", "domain", "category", "risk", "queries"}

    Splits out shadow AI (schema_category == "unknown") into a separate list,
    matching the SHADOW_AI / DETECTED_TOOLS split in the original demo fixture.

    Returns:
        (detected_tools, shadow_ai)
    """
    by_domain = defaultdict(lambda: {"category": None, "risk": "low", "queries": 0})
    risk_order = {"low": 0, "medium": 1, "high": 2, "unknown": 3}

    for entry in flagged_normalized:
        domain = entry["query"]
        rec = by_domain[domain]
        rec["category"] = entry["schema_category"]
        rec["queries"] += 1
        if risk_order.get(entry["risk_level"], 0) > risk_order.get(rec["risk"], 0):
            rec["risk"] = entry["risk_level"]

    detected_tools = []
    shadow_ai = []
    for domain, rec in sorted(by_domain.items(), key=lambda x: -x[1]["queries"]):
        if rec["category"] == "unknown":
            shadow_ai.append({"domain": domain, "queries": rec["queries"]})
        else:
            detected_tools.append({
                "tool_name": domain,   # parser doesn't carry a friendly display name yet
                "domain": domain,
                "category": rec["category"],
                "risk": rec["risk"],
                "queries": rec["queries"],
            })

    return detected_tools, shadow_ai


def main():
    parser = argparse.ArgumentParser(description="Run the full Compass UC-1 -> UC-2 pipeline on a real DNS log.")
    parser.add_argument("log_file", help="Path to the DNS log CSV file")
    parser.add_argument("--min-risk", choices=["low", "medium", "high", "unknown"], default="low")
    parser.add_argument("--custom-domains", help="Path to a text file of additional domains to detect")
    args = parser.parse_args()

    if not os.path.isfile(args.log_file):
        print(f"ERROR: Log file not found: {args.log_file}", file=sys.stderr)
        sys.exit(1)

    custom = []
    if args.custom_domains:
        from dns_ai_parser import load_custom_domains
        custom = load_custom_domains(args.custom_domains)

    ruleset = build_ruleset(custom)

    print(f"Parsing {args.log_file} ...")
    flagged, skipped, errors = parse_log(args.log_file, ruleset, args.min_risk)

    if errors:
        print(f"WARNING: {len(errors)} log line(s) failed to parse. First few:")
        for lineno, raw, msg in errors[:5]:
            print(f"  Line {lineno}: {msg}")

    # -- Bridge: map parser categories onto the NIST/schema category vocabulary --
    flagged_normalized, unmapped_categories = normalize_flagged_entries(flagged)
    if unmapped_categories:
        print(f"\nWARNING: {len(unmapped_categories)} category string(s) had no NIST mapping "
              f"and were scored as 'unknown' (zero applicable controls):")
        for cat in unmapped_categories:
            print(f"  - {cat!r}")
        print("  -> Add these to CATEGORY_MAP in compass_category_bridge.py.\n")

    detected_tools, shadow_ai = build_detected_tools(flagged_normalized)

    if not detected_tools and not shadow_ai:
        print("\nNo AI-related DNS activity detected in this log.")
        return

    # -- Feed into the existing NIST questionnaire + three-audience report --
    show_inventory(detected_tools=detected_tools, shadow_ai=shadow_ai)
    answers, org_score, org_max = run_questionnaire(detected_tools=detected_tools)
    generate_report(answers, org_score, org_max, detected_tools=detected_tools)


if __name__ == "__main__":
    main()
