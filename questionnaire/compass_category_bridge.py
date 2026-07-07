"""
compass_category_bridge.py
===========================
Maps Shivali's dns_ai_parser.py `detected_category` strings (free-text,
e.g. "LLM API", "AI Code Tool") onto the AgentCategory enum used by
compass_agent_schemav3.py and compass_nist_controlsv4.py
(e.g. "generative_ai", "code_assistant").

Why this exists:
    Without this mapping, query_controls(detected_category) in the NIST
    controls file returns an EMPTY list for every tool the parser finds,
    because the two files use completely different category vocabularies.
    That failure is silent — no exception, just zero applicable controls
    and a $0 exposure score for every real tool. This bridge closes that gap.

Owner: Mena Li — Security + NIST Framework
Depends on: AgentCategory enum in compass_agent_schemav3.py (kept as
plain strings here to avoid a hard import dependency; values must match).

Usage:
    from compass_category_bridge import normalize_category

    schema_category, was_mapped = normalize_category("LLM API")
    # schema_category == "generative_ai", was_mapped == True
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# All 15 distinct detected_category strings currently produced by
# dns_ai_parser.py's AI_DOMAINS ruleset, mapped to the AgentCategory enum.
#
# Mapping decisions worth double-checking with Shivali/team:
#   - "AI Search" / "AI Dev Search" -> generative_ai
#         (Perplexity, You.com, Phind are AI-answer engines, not just search)
#   - "Video Generation" -> image_generation
#         (no dedicated video category exists yet in AgentCategory —
#          this is a placeholder decision, not a perfect fit. If video-gen
#          tools become a bigger share of detections, consider adding a
#          real VIDEO_GEN value to AgentCategory instead.)
#   - "AI-Powered Tool" -> writing_assistant
#         (currently only matches notion.so; matches how the demo fixture
#          already categorized Notion AI)
#   - "ML Platform" -> open_source_model
#         (huggingface.co, replicate.com — treated as open-source model
#          hosting/serving platforms)
# ---------------------------------------------------------------------------

CATEGORY_MAP: dict[str, str] = {
    "LLM API":          "generative_ai",
    "LLM Platform":     "generative_ai",
    "LLM Assistant":    "generative_ai",
    "AI Chatbot":       "generative_ai",
    "AI Assistant":     "generative_ai",
    "AI Search":        "generative_ai",
    "AI Dev Search":    "generative_ai",
    "AI Code Editor":   "code_assistant",
    "AI Code Tool":     "code_assistant",
    "AI Writing":       "writing_assistant",
    "AI-Powered Tool":  "writing_assistant",
    "Image Generation": "image_generation",
    "Image Gen API":    "image_generation",
    "Video Generation": "image_generation",   # placeholder — see note above
    "Audio Generation": "voice_ai",
    "Audio Gen API":    "voice_ai",
    "ML Platform":      "open_source_model",
    "Custom":           "unknown",            # user-supplied custom domains — no category info
}


def normalize_category(detected_category: str) -> tuple[str, bool]:
    """
    Convert a parser-reported category string into an AgentCategory value.

    Args:
        detected_category: The `detected_category` field from a flagged
                            entry produced by dns_ai_parser.py.

    Returns:
        (schema_category, was_mapped)
            schema_category: the AgentCategory-compatible string.
                              Falls back to "unknown" if no mapping exists.
            was_mapped: False if this category string wasn't found in
                        CATEGORY_MAP — signals a NEW category was added
                        to dns_ai_parser.py's AI_DOMAINS that this bridge
                        doesn't know about yet. Surface these, don't
                        silently drop them.
    """
    if detected_category in CATEGORY_MAP:
        return CATEGORY_MAP[detected_category], True
    return "unknown", False


def normalize_flagged_entries(flagged: list[dict]) -> tuple[list[dict], list[str]]:
    """
    Bulk-normalize a list of flagged entries from dns_ai_parser.parse_log().

    Args:
        flagged: list of dicts as returned by dns_ai_parser.parse_log(),
                 each with a "detected_category" key.

    Returns:
        (normalized_entries, unmapped_categories)
            normalized_entries: same dicts, each with an added
                                 "schema_category" key.
            unmapped_categories: sorted list of any detected_category
                                  values with no mapping — surface these
                                  to whoever maintains CATEGORY_MAP so
                                  they get added, rather than silently
                                  scoring those tools as "unknown"
                                  (which means zero NIST controls applied).
    """
    unmapped = set()
    normalized = []
    for entry in flagged:
        raw_cat = entry.get("detected_category", "")
        schema_cat, was_mapped = normalize_category(raw_cat)
        if not was_mapped:
            unmapped.add(raw_cat)
        new_entry = dict(entry)
        new_entry["schema_category"] = schema_cat
        normalized.append(new_entry)
    return normalized, sorted(unmapped)


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=== Mapping coverage check ===")
    for raw_cat, schema_cat in CATEGORY_MAP.items():
        print(f"  {raw_cat:<18} -> {schema_cat}")

    print("\n=== Unmapped category test ===")
    cat, mapped = normalize_category("Something New")
    print(f"  'Something New' -> {cat}  (was_mapped={mapped})")

    print("\n=== Bulk normalize test ===")
    fake_flagged = [
        {"query": "api.openai.com", "detected_category": "LLM API", "risk_level": "high"},
        {"query": "midjourney.com", "detected_category": "Image Generation", "risk_level": "high"},
        {"query": "mystery.ai", "detected_category": "Mystery Category", "risk_level": "medium"},
    ]
    normalized, unmapped = normalize_flagged_entries(fake_flagged)
    for e in normalized:
        print(f"  {e['query']:<20} {e['detected_category']:<20} -> {e['schema_category']}")
    print(f"\n  Unmapped categories found: {unmapped}")
