"""
classify_domain.py
------------------
Shared domain classification module for Project Compass.

Provides category, default risk level, and reviewer reasoning
for AI tool domains based on keyword and pattern matching.

The risk_level here is a BASELINE STARTING POINT for the security
reviewer and downstream NIST scoring - not a final computed risk.
Actual risk is determined by the DNS parser and NIST scoring engine
based on real usage patterns in network logs.
"""

# ============================================================
# CATEGORY RULES
# Evaluated in order - first match wins.
# Each rule defines keywords that, if found in the normalized
# domain, assign the category, risk, and reasoning.
# ============================================================

CATEGORY_RULES = [

    # ---- Microsoft Enterprise AI ----
    {
        "keywords": ["microsoft", "copilot", "azure", "bing", "office365",
                     "sharepoint", "teams", "outlook", "msn", "windows"],
        "category":    "Enterprise AI Platform",
        "risk":        "Low",
        "tool_hint":   "Microsoft AI Services",
        "reason": (
            "Microsoft enterprise tool. Typically covered by existing organizational "
            "license and data processing agreement (DPA). Enterprise controls, SSO, "
            "and data residency options are available. Verify enterprise plan is active."
        )
    },

    # ---- Google Enterprise AI ----
    {
        "keywords": ["google", "googleapis", "gcp", "googlecloud",
                     "workspace", "gmail", "gdrive", "docs.google"],
        "category":    "Enterprise AI Platform",
        "risk":        "Low",
        "tool_hint":   "Google AI Services",
        "reason": (
            "Google Workspace-integrated AI. Typically covered by existing Google "
            "Workspace agreement. Enterprise data protection applies when using "
            "licensed Workspace accounts. Verify enterprise tier is in use."
        )
    },

    # ---- Google Consumer AI (separate from Workspace) ----
    {
        "keywords": ["gemini", "bard", "makersuite", "aistudio"],
        "category":    "Generative AI",
        "risk":        "Medium",
        "tool_hint":   "Google Generative AI",
        "reason": (
            "Google consumer-facing generative AI product. Data handling depends on "
            "account type - personal Google accounts do not carry Workspace DPA. "
            "Confirm employees are using organizational accounts with admin controls."
        )
    },

    # ---- OpenAI / ChatGPT ----
    {
        "keywords": ["openai", "chatgpt"],
        "category":    "Generative AI",
        "risk":        "High",
        "tool_hint":   "OpenAI / ChatGPT",
        "reason": (
            "Consumer-grade generative AI. By default, prompts and outputs may be "
            "used for model training. No enterprise data isolation unless ChatGPT "
            "Enterprise or API with zero-retention agreement is active. High data "
            "leakage potential for sensitive organizational content."
        )
    },

    # ---- Anthropic / Claude ----
    {
        "keywords": ["anthropic", "claude"],
        "category":    "Generative AI",
        "risk":        "Medium",
        "tool_hint":   "Anthropic Claude",
        "reason": (
            "Generative AI assistant. Claude.ai consumer product does not provide "
            "enterprise data controls. API usage with zero-retention settings offers "
            "stronger privacy. Verify whether organizational use is via API or consumer "
            "product and whether a DPA is in place."
        )
    },

    # ---- AI Image Generation ----
    {
        "keywords": ["midjourney", "stability", "stablediffusion", "runway",
                     "pika", "adobe", "firefly", "dall-e", "ideogram",
                     "leonardo", "imagine", "artbreeder", "nightcafe"],
        "category":    "AI Image / Video Generation",
        "risk":        "High",
        "tool_hint":   "AI Creative Generation Tool",
        "reason": (
            "AI creative generation tool. High intellectual property and copyright "
            "exposure risk. User prompts and generated outputs may be logged and "
            "used for model improvement. No enterprise controls by default. "
            "Generated content ownership is legally ambiguous in most jurisdictions."
        )
    },

    # ---- AI Audio / Voice Synthesis ----
    {
        "keywords": ["elevenlabs", "murf", "speechify", "resemble",
                     "descript", "voicemod", "replica", "wellsaid"],
        "category":    "AI Audio / Voice Generation",
        "risk":        "High",
        "tool_hint":   "AI Voice Synthesis Tool",
        "reason": (
            "AI voice synthesis and cloning tool. Voice cloning capability presents "
            "impersonation and deepfake risk. Audio samples and synthesized output "
            "may be retained by the vendor. High risk for social engineering misuse."
        )
    },

    # ---- AI Video Generation ----
    {
        "keywords": ["sora", "synthesia", "heygen", "colossyan",
                     "invideo", "lumen5", "pictory"],
        "category":    "AI Video Generation",
        "risk":        "High",
        "tool_hint":   "AI Video Generation Tool",
        "reason": (
            "AI video generation tool. Video content and scripts submitted may be "
            "retained. Deepfake risk if used with real likeness. No enterprise "
            "controls by default. Review vendor terms for training data usage."
        )
    },

    # ---- GitHub / Enterprise Code Platforms ----
    {
        "keywords": ["github", "gitlab"],
        "category":    "AI Code Assistant",
        "risk":        "Low",
        "tool_hint":   "AI-Assisted Code Platform",
        "reason": (
            "Developer platform with integrated AI features (Copilot, Duo). "
            "Enterprise controls available including IP indemnification and private "
            "model options. Source code exposure risk mitigated by existing repository "
            "security policies. Verify GitHub Copilot Enterprise vs. individual plan."
        )
    },

    # ---- AI Code Assistants (consumer) ----
    {
        "keywords": ["cursor", "tabnine", "codeium", "replit",
                     "codex", "blackbox", "sourcegraph", "cody"],
        "category":    "AI Code Assistant",
        "risk":        "Medium",
        "tool_hint":   "AI Code Completion Tool",
        "reason": (
            "AI code completion or pair-programming tool. Source code snippets are "
            "transmitted to external servers for completion suggestions. Review "
            "vendor data retention policy. Enterprise plans may offer private "
            "deployment or zero-retention options."
        )
    },

    # ---- AI Search ----
    {
        "keywords": ["perplexity", "you.com", "phind", "kagi",
                     "metaphor", "exa", "brave"],
        "category":    "AI Search",
        "risk":        "Medium",
        "tool_hint":   "AI Search Engine",
        "reason": (
            "AI-powered search engine. Search queries are transmitted to external "
            "service and may be logged. Sensitive search terms could expose "
            "organizational research or strategic intent. No enterprise data controls."
        )
    },

    # ---- AI Productivity / Writing ----
    {
        "keywords": ["notion", "grammarly", "jasper", "copy.ai", "writesonic",
                     "quillbot", "wordtune", "otter", "fireflies", "mem",
                     "craft", "coda", "roam"],
        "category":    "AI Productivity",
        "risk":        "Low",
        "tool_hint":   "AI Productivity Tool",
        "reason": (
            "AI-enhanced productivity or writing tool. Document content is processed "
            "by external AI service. Review vendor's enterprise plan for data privacy "
            "controls and retention policies before handling sensitive content."
        )
    },

    # ---- AI Meeting / Transcription ----
    {
        "keywords": ["otter", "fireflies", "fathom", "gong", "chorus",
                     "avoma", "trint", "rev", "zoom"],
        "category":    "AI Meeting Intelligence",
        "risk":        "Medium",
        "tool_hint":   "AI Meeting / Transcription Tool",
        "reason": (
            "AI meeting recording and transcription tool. Full meeting audio and "
            "video may be stored by vendor. Participants may not be aware of "
            "recording. Review consent requirements and data retention policies. "
            "High risk if used in privileged or confidential meetings."
        )
    },

    # ---- AI Developer Platforms / APIs ----
    {
        "keywords": ["huggingface", "replicate", "together", "groq",
                     "mistral", "cohere", "aleph", "inflection",
                     "ai21", "forefront", "nlpcloud"],
        "category":    "AI Developer Platform",
        "risk":        "Medium",
        "tool_hint":   "AI API / Developer Platform",
        "reason": (
            "AI model hosting or API platform used for programmatic access to "
            "language models. Data submitted via API may be used for model training "
            "unless zero-retention agreement is in place. Review API terms and "
            "confirm organizational use cases are approved."
        )
    },

    # ---- AI Customer Service / Chatbots ----
    {
        "keywords": ["intercom", "drift", "zendesk", "freshdesk",
                     "ada", "kore", "boost.ai", "ultimate"],
        "category":    "AI Customer Service",
        "risk":        "Low",
        "tool_hint":   "AI Customer Service Platform",
        "reason": (
            "AI-powered customer service or chatbot platform. Customer interaction "
            "data is processed externally. Verify data residency and retention "
            "policies comply with organizational data handling requirements."
        )
    },

    # ---- AI Security Tools ----
    {
        "keywords": ["darktrace", "vectra", "cylance", "crowdstrike",
                     "sentinelone", "secureworks"],
        "category":    "AI Security Tool",
        "risk":        "Low",
        "tool_hint":   "AI Security Platform",
        "reason": (
            "AI-enhanced cybersecurity platform. Security telemetry may be shared "
            "with vendor for threat intelligence. Typically governed by enterprise "
            "security agreements. Review data sharing and threat intel telemetry terms."
        )
    },

]

# ============================================================
# PATTERN-BASED FALLBACK RULES
# Applied when no keyword rule matches.
# ============================================================

FALLBACK_PATTERNS = [
    {
        "pattern":  lambda nd: nd.endswith(".ai") or ".ai." in nd,
        "category": "Unknown AI Tool",
        "risk":     "Medium-High",
        "reason": (
            "Domain uses .ai TLD or contains AI-related suffix, suggesting an AI "
            "product or service. No specific tool classification available. "
            "Elevated default risk until the tool is reviewed and categorized."
        )
    },
    {
        "pattern":  lambda nd: any(kw in nd for kw in ["gpt", "llm", "neural", "ml.", "bot.", "chat"]),
        "category": "Unclassified AI Tool",
        "risk":     "Medium-High",
        "reason": (
            "Domain contains AI-related keyword (gpt, llm, neural, ml, bot, chat). "
            "Likely an AI tool or service. Classification and risk level should be "
            "confirmed by security reviewer before approving for monitoring."
        )
    },
]

# Default when nothing matches
DEFAULT_CLASSIFICATION = {
    "category": "Unclassified",
    "risk":     "Medium",
    "tool_hint": None,
    "reason": (
        "Domain sourced from Microsoft Purview supported AI sites list. "
        "No specific category rule matched. Default Medium risk assigned as "
        "starting point. Security reviewer should verify tool type, vendor "
        "privacy policy, data retention terms, and organizational need before "
        "confirming risk level."
    )
}


# ============================================================
# PUBLIC API
# ============================================================

def classify(normalized_domain: str) -> dict:
    """
    Classify a normalized domain and return:
      category, risk, tool_name, reason, confidence

    confidence: 'high' = keyword matched a specific rule
                'pattern' = matched a pattern fallback
                'default' = nothing matched
    """
    nd = normalized_domain.lower()

    # Check category rules
    for rule in CATEGORY_RULES:
        if any(kw in nd for kw in rule["keywords"]):
            tool_name = rule.get("tool_hint") or _derive_tool_name(nd)
            return {
                "category":   rule["category"],
                "risk":       rule["risk"],
                "tool_name":  tool_name,
                "reason":     rule["reason"],
                "confidence": "high"
            }

    # Check pattern fallbacks
    for fp in FALLBACK_PATTERNS:
        if fp["pattern"](nd):
            return {
                "category":   fp["category"],
                "risk":       fp["risk"],
                "tool_name":  _derive_tool_name(nd),
                "reason":     fp["reason"],
                "confidence": "pattern"
            }

    # Default
    return {
        "category":   DEFAULT_CLASSIFICATION["category"],
        "risk":       DEFAULT_CLASSIFICATION["risk"],
        "tool_name":  _derive_tool_name(nd),
        "reason":     DEFAULT_CLASSIFICATION["reason"],
        "confidence": "default"
    }


def is_auto_approvable(classification: dict, source_name: str) -> bool:
    """
    Returns True if a domain should be auto-approved.
    Criteria:
      - Source must be Microsoft Purview (trusted seed)
      - Classification confidence must be 'high' (matched a specific rule)
      - Risk level is not Medium-High or higher for unknown tools
    """
    if source_name != "Microsoft Purview":
        return False
    if classification["confidence"] != "high":
        return False
    if classification["risk"] == "Medium-High":
        return False
    return True


def _derive_tool_name(normalized_domain: str) -> str:
    """Derive a human-readable tool name from a normalized domain."""
    parts = normalized_domain.split(".")
    if len(parts) >= 2:
        return parts[-2].replace("-", " ").title()
    return normalized_domain.title()
