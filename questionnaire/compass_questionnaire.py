"""
compass_questionnaire.py
=========================
Standalone demo of UC-2: Governance Questionnaire + NIST Report.

Does NOT need the log file or dns_ai_parser.py.
Uses a pre-built inventory (what the log parser would have found)
and walks through the governance questionnaire against your NIST
controls file, then produces the three-audience report.

Run:
    python3 compass_questionnaire.py
"""

import sys
import os
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from compass_nist_controlsv4 import (
    query_controls, get_controls_for_question,
    QUESTIONS, GENAI_RISKS, SEVERITY_WEIGHT
)

ASSESSMENT_DATE = datetime.now(timezone.utc).strftime("%B %d, %Y")

# Pre-built inventory (what the log parser found in UC-1)
DETECTED_TOOLS = [
    {"tool_name": "ChatGPT API",   "domain": "api.openai.com",     "category": "generative_ai",    "risk": "high",   "queries": 74},
    {"tool_name": "Claude",         "domain": "claude.ai",           "category": "generative_ai",    "risk": "high",   "queries": 46},
    {"tool_name": "GitHub Copilot", "domain": "copilot.github.com", "category": "code_assistant",   "risk": "high",   "queries": 52},
    {"tool_name": "Google Gemini",  "domain": "gemini.google.com",  "category": "generative_ai",    "risk": "medium", "queries": 27},
    {"tool_name": "HuggingFace",    "domain": "huggingface.co",     "category": "open_source_model","risk": "medium", "queries": 27},
    {"tool_name": "Grammarly AI",   "domain": "grammarly.com",      "category": "writing_assistant","risk": "medium", "queries": 30},
    {"tool_name": "Midjourney",     "domain": "midjourney.com",     "category": "image_generation", "risk": "medium", "queries": 23},
    {"tool_name": "Perplexity",     "domain": "perplexity.ai",      "category": "generative_ai",    "risk": "medium", "queries": 21},
    {"tool_name": "Character.AI",   "domain": "character.ai",       "category": "generative_ai",    "risk": "high",   "queries": 56},
    {"tool_name": "Otter.ai",       "domain": "otter.ai",           "category": "voice_ai",         "risk": "low",    "queries": 8},
    {"tool_name": "Notion AI",      "domain": "notion.so",          "category": "writing_assistant","risk": "low",    "queries": 5},
]

SHADOW_AI = [
    {"domain": "api.runway.ml",  "queries": 7},
    {"domain": "writesonic.com", "queries": 5},
    {"domain": "ai.jasper.ai",   "queries": 10},
]

# Set to True to use pre-loaded answers (demo mode)
# Set to False to answer questions yourself interactively
DEMO_MODE = False

# Pre-loaded answers used only when DEMO_MODE = True
DEMO_ANSWERS = {
    "G-01": "No", "G-02": "No", "G-03": "Yes", "G-04": "No",
    "M-01": "No", "M-02": "Yes", "M-03": "No",
    "MS-01": "No", "MS-02": "Yes", "MS-03": "No",
    "MG-01": "No", "MG-02": "No", "MG-03": "Yes",
}

SEV_ICON = {"HIGH": "!", "MEDIUM": "~", "LOW": "i"}
FN_LABEL = {
    "GOVERN":  "GOVERN -- Policies & Accountability",
    "MAP":     "MAP -- Risk Identification",
    "MEASURE": "MEASURE -- Monitoring & Analysis",
    "MANAGE":  "MANAGE -- Response & Remediation",
}


def show_inventory():
    print("\n" + "=" * 72)
    print("  UC-1 RESULT -- AI TOOLS DETECTED IN LOG SCAN")
    print("=" * 72)
    risk_counts = {"high": 0, "medium": 0, "low": 0}
    for t in DETECTED_TOOLS:
        risk_counts[t["risk"]] += 1
    print()
    print(f"  High:   {risk_counts['high']} tools")
    print(f"  Medium: {risk_counts['medium']} tools")
    print(f"  Low:    {risk_counts['low']} tools")
    print()
    print(f"  {'Tool':<18} {'Domain':<25} {'Category':<18} {'Risk':<8} {'Queries'}")
    print("  " + "-" * 78)
    for t in DETECTED_TOOLS:
        print(f"  {t['tool_name']:<18} {t['domain']:<25} {t['category']:<18} {t['risk']:<8} {t['queries']}")
    if SHADOW_AI:
        print()
        print(f"  Shadow AI -- {len(SHADOW_AI)} unrecognized domains flagged for review:")
        for s in SHADOW_AI:
            print(f"      {s['domain']:<25} {s['queries']} queries")


def run_questionnaire():
    answers = {}
    detected_categories = set(t["category"] for t in DETECTED_TOOLS)
    has_genai = bool({"generative_ai", "internal_llm"} & detected_categories)

    print("\n" + "=" * 72)
    print("  UC-2 -- GOVERNANCE QUESTIONNAIRE")
    print("  13 yes/no questions mapped to NIST AI RMF controls.")
    print("  Each No answer confirms specific controls as unmet.")
    print("=" * 72)

    running_score = 0

    for fn in ["GOVERN", "MAP", "MEASURE", "MANAGE"]:
        qs = QUESTIONS.get(fn, [])
        analyst_qs = []
        for q in qs:
            q_type = getattr(q, "question_type", "standard")
            if q_type in ("vendor", "conditional"):
                continue
            if q_type == "genai_specific" and not has_genai:
                continue
            analyst_qs.append(q)

        if not analyst_qs:
            continue

        print(f"\n  -- {FN_LABEL[fn]} --")

        for q in analyst_qs:
            icon = SEV_ICON.get(q.severity_if_no, " ")
            print(f"\n  [{icon}] [{q.q_id}] {q.question}")
            print(f"      Severity if No: {q.severity_if_no}")

            if DEMO_MODE:
                answer = DEMO_ANSWERS.get(q.q_id, "Yes")
                print(f"      Answer: {answer}  (demo)")
            else:
                while True:
                    raw = input("      Your answer (Yes / No / Unsure): ").strip().lower()
                    if raw in ("yes", "no", "unsure"):
                        answer = "no" if raw == "unsure" else raw
                        break
                    print("      Please type Yes, No, or Unsure.")

            if answer.lower() == "no":
                confirmed = get_controls_for_question(q.q_id)
                if confirmed:
                    pts = sum(c.severity_weight for c in confirmed)
                    running_score += pts
                    ctrl_ids = ", ".join(c.control_id for c in confirmed)
                    print(f"      -> Confirms UNMET: {ctrl_ids}  (+{pts} pts)  [Running: {running_score}]")

            answers[q.q_id] = answer.lower()

            for cq in QUESTIONS.get("CONDITIONAL", []):
                if getattr(cq, "parent_q_id", None) == q.q_id and answer.lower() == "no":
                    print(f"\n      -> [{cq.q_id}] {cq.question}")
                    if DEMO_MODE:
                        followup = DEMO_ANSWERS.get(cq.q_id, "No")
                        print(f"         Answer: {followup}  (informational -- no gap score)")
                    else:
                        followup = input("         Your answer (Yes / No): ").strip()
                        print(f"         (informational -- no gap score)")

    print(f"\n  {'─' * 70}")
    print(f"  Questionnaire complete. Confirmed gap score: {running_score} pts")
    print(f"  {'─' * 70}")
    return answers


def generate_report(answers):
    tool_scores = []
    for t in DETECTED_TOOLS:
        applicable = query_controls(t["category"])
        potential = sum(c.severity_weight for c in applicable)
        unmet = [c for c in applicable if answers.get(c.questionnaire_question_id) == "no"]
        confirmed = sum(c.severity_weight for c in unmet)
        tool_scores.append((t, applicable, unmet, confirmed, potential))

    total_confirmed = sum(s[3] for s in tool_scores)
    total_potential = sum(s[4] for s in tool_scores)
    pct = round(100 * total_confirmed / total_potential) if total_potential else 0

    print("\n\n" + "=" * 72)
    print("  COMPASS GOVERNANCE GAP ASSESSMENT REPORT")
    print(f"  {ASSESSMENT_DATE}  |  NIST AI RMF 1.0 + NIST-AI-600-1 GenAI Profile")
    print("=" * 72)

    # EXECUTIVE VIEW
    print(f"""
{'#' * 72}
  EXECUTIVE VIEW
  Business risk | Plain language | Top 3 actions
{'#' * 72}

  {len(DETECTED_TOOLS)} AI tools detected -- none are formally governed.
  Confirmed governance gap: {total_confirmed} of {total_potential} possible points ({pct}%).

  What this means:
  Employees are using AI tools that send data to external vendors
  without a formal policy, a named owner, or monitoring in place.
  This creates real risk of sensitive data leaving the organization.

  Top 3 priority actions:""")

    seen = set()
    top3 = []
    for t, _, unmet, _, _ in sorted(tool_scores, key=lambda x: -x[3]):
        for c in unmet:
            if c.control_id not in seen:
                top3.append((t, c))
                seen.add(c.control_id)
            if len(top3) >= 3:
                break
        if len(top3) >= 3:
            break

    for i, (t, c) in enumerate(top3, 1):
        print(f"\n  {i}. {c.remediation}")

    # SECURITY TEAM VIEW
    print(f"""
{'#' * 72}
  SECURITY TEAM VIEW
  NIST controls | Gap scores | Remediation
{'#' * 72}

  {'Tool':<18} {'Queries':<9} {'Potential':<11} {'Confirmed':<11} {'%':>4}
  {'-' * 56}""")

    for t, _, unmet, confirmed, potential in sorted(tool_scores, key=lambda x: -x[3]):
        pct_t = round(100 * confirmed / potential) if potential else 0
        print(f"  {t['tool_name']:<18} {t['queries']:<9} {potential:<11} {confirmed:<11} {pct_t:>3}%")

    print(f"\n  Top unmet controls:")
    seen2 = set()
    count = 0
    for t, _, unmet, _, _ in sorted(tool_scores, key=lambda x: -x[3]):
        for c in sorted(unmet, key=lambda x: -x.severity_weight):
            if c.control_id not in seen2:
                print(f"\n  [{c.control_id}] {c.severity_level} -- {c.description}")
                print(f"    Fix: {c.remediation}")
                seen2.add(c.control_id)
                count += 1
            if count >= 6:
                break
        if count >= 6:
            break

    # AUDITOR VIEW
    total_findings = sum(len(s[2]) for s in tool_scores)
    print(f"""
{'#' * 72}
  AUDITOR VIEW
  Structured findings | Evidence | NIST reference | Control status
{'#' * 72}

  Framework:       NIST AI RMF 1.0 (January 2023)
  GenAI Profile:   NIST-AI-600-1 (July 2024)
  Assessment Date: {ASSESSMENT_DATE}
  Total Findings:  {total_findings}
""")

    finding_num = 1
    for t, _, unmet, confirmed, potential in sorted(tool_scores, key=lambda x: -x[3])[:3]:
        for c in unmet[:3]:
            q_text = next(
                (q.question for qs in QUESTIONS.values()
                 for q in qs if q.q_id == c.questionnaire_question_id), "N/A"
            )
            print(f"  Finding {finding_num:03d}")
            print(f"  {'─' * 60}")
            print(f"  Tool              : {t['tool_name']} ({t['domain']})")
            print(f"  NIST Reference    : {c.control_id} ({c.function})")
            print(f"  Description       : {c.description}")
            print(f"  Control Status    : UNMET")
            print(f"  Severity          : {c.severity_level} ({c.severity_weight} points)")
            print(f"  Evidence          : {t['queries']} DNS queries to {t['domain']} in log scan")
            print(f"  Question          : {c.questionnaire_question_id} -- {q_text}")
            print(f"  Answer            : No")
            print(f"  Recommendation    : {c.remediation}")
            print()
            finding_num += 1

    print(f"  ... {total_findings - (finding_num - 1)} additional findings in full report.")
    print(f"\n{'=' * 72}")


def main():
    show_inventory()
    answers = run_questionnaire()
    generate_report(answers)


if __name__ == "__main__":
    main()
