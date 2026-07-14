"""
compass_nist_controls.py
========================
NIST AI RMF control mapping for the Compass gap scoring engine.

Frameworks:
    - NIST AI RMF 1.0 (January 2023)
    - NIST-AI-600-1 GenAI Profile (July 2024)


Version: 2.0

Usage (Shivali scoring engine):
    from compass_nist_controls import query_controls, QUESTIONS, GENAI_RISKS

    # Get all controls that apply to a detected tool category
    controls = query_controls("generative_ai")

    # Get the questionnaire questions for a NIST function
    govern_questions = QUESTIONS["GOVERN"]

    # Get plain-English description of a GenAI risk
    desc = GENAI_RISKS["data_privacy"]["plain_english"]
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Severity weights — used by Shivali's gap scoring algorithm
# total_gap_score = sum of severity_weight for each unmet control
# Same 100 / 50 / 0 scale as ANSWER_SCORE (compass_questionnaire.py) and
# VENDOR_CREDIT below, so every score in the pipeline speaks the same units.
# ---------------------------------------------------------------------------

SEVERITY_WEIGHT = {
    "HIGH":   100,
    "MEDIUM":  50,
    "LOW":      0,
}

# Credit scale for vendor auto-scoring (score_vendor_gaps below) -- mirrors
# the 0 / 50 / 100 scale used for Yes / Unsure / No answers in
# compass_questionnaire.py's ANSWER_SCORE.
VENDOR_CREDIT = {"pass": 100, "partial": 50, "fail": 0}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class NistControl:
    """
    A single NIST AI RMF control node in the knowledge graph.

    Shivali's scoring engine queries these by tool category.
    A No answer to the linked questionnaire question confirms the gap
    and adds severity_weight to the tool's total gap score.
    """
    control_id: str
    function: str                        # GOVERN | MAP | MEASURE | MANAGE
    subcategory: str                     # e.g. GV.PO
    description: str
    severity_level: str                  # HIGH | MEDIUM | LOW
    severity_weight: int                 # 100 | 50 | 0
    applies_to_categories: list[str]     # tool categories that trigger this control
    questionnaire_question_id: str       # which question confirms this gap
    questionnaire_confirms: bool         # True = questionnaire confirms a pre-flagged gap
    genai_risks_linked: list[str]        # GenAI risk IDs from NIST-AI-600-1
    remediation: str                     # what goes in the report recommendation
    log_triggered: bool = False          # True = also triggered by log scan patterns


@dataclass
class QuestionnaireQuestion:
    """
    A single governance questionnaire question for UC-2.

    question_type controls how Mario's frontend handles this question:

        standard      — show to all orgs, analyst answers Yes / No
        genai_specific — only show when generative_ai or internal_llm tools
                         were detected in the log scan
        vendor        — NOT shown to analyst. Auto-scored by Compass from
                         RegistryAttributes after the log scan. auto_score_from
                         names the RegistryAttributes field to check.
        conditional   — only show when parent_q_id was answered with trigger_answer.
                         Used for follow-up questions after a No answer.
    """
    q_id: str
    nist_function: str                   # GOVERN | MAP | MEASURE | MANAGE | VENDOR
    question: str
    answer_type: str                     # yes_no | auto (for vendor type)
    controls_if_no: list[str]            # control IDs flagged on a No / fail answer
    severity_if_no: str                  # HIGH | MEDIUM | LOW
    question_type: str = "standard"      # standard | genai_specific | vendor | conditional
    auto_score_from: Optional[str] = None  # vendor only: RegistryAttributes field name
    parent_q_id: Optional[str] = None   # conditional only: which question triggers this
    trigger_answer: Optional[str] = None # conditional only: "no" or "yes"
    adapts_for_categories: list[str] = field(default_factory=list)
    follow_up_if_no: Optional[str] = None
    note: Optional[str] = None


@dataclass
class GenAIRiskProfile:
    """One of the 12 GenAI-specific risks from NIST-AI-600-1 (July 2024)."""
    risk_id: str
    plain_english: str
    highest_risk_categories: list[str]


# ---------------------------------------------------------------------------
# All 19 NIST AI RMF controls
# ---------------------------------------------------------------------------

ALL_CONTROLS: list[NistControl] = [

    # ── GOVERN / GV.OV ──────────────────────────────────────────────────────
    NistControl(
        control_id="GV.OV-1",
        function="GOVERN", subcategory="GV.OV",
        description="Organization has designated AI governance roles and accountability structures.",
        severity_level="HIGH", severity_weight=100,
        applies_to_categories=["generative_ai", "code_assistant", "writing_assistant",
                               "image_generation", "open_source_model", "internal_llm"],
        questionnaire_question_id="G-02", questionnaire_confirms=True,
        genai_risks_linked=["human_ai_config", "societal_impacts"],
        remediation="Assign a named AI governance owner. Document accountability for each AI tool in use."
    ),
    NistControl(
        control_id="GV.OV-2",
        function="GOVERN", subcategory="GV.OV",
        description="Organization has established oversight processes for AI tool approvals.",
        severity_level="HIGH", severity_weight=100,
        applies_to_categories=["generative_ai", "code_assistant", "writing_assistant",
                               "image_generation", "voice_ai", "data_ai",
                               "open_source_model", "internal_llm"],
        questionnaire_question_id="G-02", questionnaire_confirms=True,
        genai_risks_linked=["ip_exposure", "info_security", "human_ai_config"],
        remediation="Implement an AI tool approval process. No tool used without prior review and sign-off."
    ),
    NistControl(
        control_id="GV.OV-3",
        function="GOVERN", subcategory="GV.OV",
        description="AI risks are included in organizational risk reporting and board-level visibility.",
        severity_level="MEDIUM", severity_weight=50,
        applies_to_categories=["generative_ai", "internal_llm", "data_ai"],
        questionnaire_question_id="G-03", questionnaire_confirms=True,
        genai_risks_linked=["societal_impacts", "info_integrity"],
        remediation="Add AI risk as a standing agenda item in risk committee meetings."
    ),

    # ── GOVERN / GV.PO ──────────────────────────────────────────────────────
    NistControl(
        control_id="GV.PO-1",
        function="GOVERN", subcategory="GV.PO",
        description="Organization has a written AI acceptable use policy covering approved tools and prohibited uses.",
        severity_level="HIGH", severity_weight=100,
        applies_to_categories=["generative_ai", "code_assistant", "writing_assistant",
                               "image_generation", "voice_ai", "data_ai",
                               "open_source_model", "internal_llm"],
        questionnaire_question_id="G-01", questionnaire_confirms=True,
        genai_risks_linked=["data_privacy", "ip_exposure", "harmful_content"],
        remediation="Draft and publish an AI acceptable use policy. Communicate to all staff. Review annually."
    ),
    NistControl(
        control_id="GV.PO-2",
        function="GOVERN", subcategory="GV.PO",
        description="AI policy includes specific provisions for generative AI and LLM tools.",
        severity_level="HIGH", severity_weight=100,
        applies_to_categories=["generative_ai", "internal_llm"],
        questionnaire_question_id="G-01", questionnaire_confirms=True,
        genai_risks_linked=["data_privacy", "prompt_injection", "confabulation", "ip_exposure"],
        remediation="Extend AI policy to include GenAI-specific rules: no PII input, no confidential data, prompt review guidelines."
    ),

    # ── GOVERN / GV.AT ──────────────────────────────────────────────────────
    NistControl(
        control_id="GV.AT-1",
        function="GOVERN", subcategory="GV.AT",
        description="Staff who use AI tools have received training on responsible use and associated risks.",
        severity_level="MEDIUM", severity_weight=50,
        applies_to_categories=["generative_ai", "code_assistant", "writing_assistant",
                               "open_source_model", "internal_llm"],
        questionnaire_question_id="G-04", questionnaire_confirms=True,
        genai_risks_linked=["confabulation", "info_integrity", "human_ai_config"],
        remediation="Deliver AI literacy training covering hallucination risks, data handling, and acceptable use."
    ),
    NistControl(
        control_id="GV.AT-2",
        function="GOVERN", subcategory="GV.AT",
        description="AI governance accountability is documented and assigned to specific individuals.",
        severity_level="MEDIUM", severity_weight=50,
        applies_to_categories=["generative_ai", "internal_llm", "data_ai"],
        questionnaire_question_id="G-02", questionnaire_confirms=True,
        genai_risks_linked=["human_ai_config", "societal_impacts"],
        remediation="Name a responsible owner for each AI tool in the organization's tool registry."
    ),

    # ── MAP / MP.AC ─────────────────────────────────────────────────────────
    NistControl(
        control_id="MP.AC-1",
        function="MAP", subcategory="MP.AC",
        description="Organization has mapped all AI tools in use, including shadow AI detected in network logs.",
        severity_level="HIGH", severity_weight=100,
        applies_to_categories=["generative_ai", "code_assistant", "writing_assistant",
                               "image_generation", "voice_ai", "data_ai",
                               "open_source_model", "internal_llm", "unknown"],
        questionnaire_question_id="M-01", questionnaire_confirms=False,
        log_triggered=True,
        genai_risks_linked=["info_security", "data_privacy"],
        remediation="Maintain a live AI tool inventory. Compass provides this via log scan — review monthly."
    ),
    NistControl(
        control_id="MP.AC-2",
        function="MAP", subcategory="MP.AC",
        description="Each AI tool's intended use case and business purpose is documented.",
        severity_level="MEDIUM", severity_weight=50,
        applies_to_categories=["generative_ai", "internal_llm", "data_ai"],
        questionnaire_question_id="M-02", questionnaire_confirms=True,
        genai_risks_linked=["human_ai_config", "info_integrity"],
        remediation="Document the approved use case for each AI tool. Include in the tool registry."
    ),

    # ── MAP / MP.AI ─────────────────────────────────────────────────────────
    NistControl(
        control_id="MP.AI-1",
        function="MAP", subcategory="MP.AI",
        description="AI-specific risks have been identified and documented for each tool in use.",
        severity_level="HIGH", severity_weight=100,
        applies_to_categories=["generative_ai", "code_assistant", "open_source_model", "internal_llm"],
        questionnaire_question_id="M-03", questionnaire_confirms=True,
        genai_risks_linked=["confabulation", "data_privacy", "prompt_injection", "data_poisoning"],
        remediation="Conduct a risk assessment for each detected AI tool. Document risks and mitigations."
    ),

    # ── MAP / MP.RD ─────────────────────────────────────────────────────────
    NistControl(
        control_id="MP.RD-1",
        function="MAP", subcategory="MP.RD",
        description="AI risk documentation is maintained and accessible to relevant stakeholders.",
        severity_level="MEDIUM", severity_weight=50,
        applies_to_categories=["generative_ai", "open_source_model", "internal_llm", "data_ai"],
        questionnaire_question_id="M-03", questionnaire_confirms=True,
        genai_risks_linked=["info_integrity", "human_ai_config"],
        remediation="Store risk documentation in a shared location. Review at least annually."
    ),

    # ── MEASURE / MS.AN ─────────────────────────────────────────────────────
    NistControl(
        control_id="MS.AN-1",
        function="MEASURE", subcategory="MS.AN",
        description="Organization actively monitors AI tool usage — logs reviewed, anomalies flagged.",
        severity_level="HIGH", severity_weight=100,
        applies_to_categories=["generative_ai", "code_assistant", "internal_llm",
                               "data_ai", "open_source_model"],
        questionnaire_question_id="MS-01", questionnaire_confirms=True,
        log_triggered=True,
        genai_risks_linked=["info_security", "human_ai_config", "data_poisoning"],
        remediation="Set up DNS/firewall log monitoring for AI domains. Run Compass scans monthly."
    ),
    NistControl(
        control_id="MS.AN-2",
        function="MEASURE", subcategory="MS.AN",
        description="AI tool outputs are reviewed for accuracy and potential harm before use in decisions.",
        severity_level="MEDIUM", severity_weight=50,
        applies_to_categories=["generative_ai", "internal_llm"],
        questionnaire_question_id="MS-02", questionnaire_confirms=True,
        genai_risks_linked=["confabulation", "info_integrity", "human_replication"],
        remediation="Establish a human review step for AI-generated outputs used in decisions."
    ),

    # ── MEASURE / MS.DW ─────────────────────────────────────────────────────
    NistControl(
        control_id="MS.DW-1",
        function="MEASURE", subcategory="MS.DW",
        description="Data inputs to AI tools are reviewed to prevent sensitive or confidential data exposure.",
        severity_level="HIGH", severity_weight=100,
        applies_to_categories=["generative_ai", "code_assistant", "writing_assistant", "internal_llm"],
        questionnaire_question_id="MS-03", questionnaire_confirms=True,
        genai_risks_linked=["data_privacy", "ip_exposure", "info_security"],
        remediation="Implement data classification. Train staff not to input PII or confidential data into AI tools."
    ),

    # ── MEASURE / MS.MC ─────────────────────────────────────────────────────
    NistControl(
        control_id="MS.MC-1",
        function="MEASURE", subcategory="MS.MC",
        description="AI risk metrics are tracked over time and reviewed at defined intervals.",
        severity_level="LOW", severity_weight=0,
        applies_to_categories=["generative_ai", "internal_llm", "data_ai"],
        questionnaire_question_id="MS-01", questionnaire_confirms=True,
        genai_risks_linked=["societal_impacts"],
        remediation="Define and track 2-3 AI risk KPIs quarterly. Include in risk reporting."
    ),

    # ── MANAGE / MG.AN ──────────────────────────────────────────────────────
    NistControl(
        control_id="MG.AN-1",
        function="MANAGE", subcategory="MG.AN",
        description="Organization has a defined process to respond to AI-related incidents or policy violations.",
        severity_level="MEDIUM", severity_weight=50,
        applies_to_categories=["generative_ai", "code_assistant", "internal_llm", "open_source_model"],
        questionnaire_question_id="MG-01", questionnaire_confirms=True,
        genai_risks_linked=["info_security", "harmful_content", "data_privacy"],
        remediation="Document an AI incident response procedure. Include escalation path and communication plan."
    ),

    # ── MANAGE / MG.DM ──────────────────────────────────────────────────────
    NistControl(
        control_id="MG.DM-1",
        function="MANAGE", subcategory="MG.DM",
        description="Decisions to approve, restrict, or block AI tools are documented and revisited regularly.",
        severity_level="MEDIUM", severity_weight=50,
        applies_to_categories=["generative_ai", "code_assistant", "writing_assistant",
                               "image_generation", "open_source_model"],
        questionnaire_question_id="MG-02", questionnaire_confirms=True,
        genai_risks_linked=["human_ai_config", "ip_exposure"],
        remediation="Maintain a tool decision log. Review at least quarterly."
    ),

    # ── MANAGE / MG.PO ──────────────────────────────────────────────────────
    NistControl(
        control_id="MG.PO-1",
        function="MANAGE", subcategory="MG.PO",
        description="Organization has a process to block or restrict AI tools that violate policy.",
        severity_level="HIGH", severity_weight=100,
        applies_to_categories=["generative_ai", "code_assistant", "writing_assistant",
                               "image_generation", "voice_ai", "data_ai",
                               "open_source_model", "internal_llm"],
        questionnaire_question_id="MG-02", questionnaire_confirms=True,
        genai_risks_linked=["data_privacy", "ip_exposure", "info_security"],
        remediation="Configure DNS/firewall to block high-risk AI domains. Implement an allowlist for approved tools."
    ),
    NistControl(
        control_id="MG.RR-1",
        function="MANAGE", subcategory="MG.RR",
        description="AI governance policies are reviewed and updated when new tools are detected or risks change.",
        severity_level="LOW", severity_weight=0,
        applies_to_categories=["generative_ai", "internal_llm"],
        questionnaire_question_id="MG-03", questionnaire_confirms=True,
        genai_risks_linked=["info_integrity", "societal_impacts"],
        remediation="Schedule a quarterly AI policy review. Trigger ad-hoc review when a new high-risk tool is detected."
    ),
]


# ---------------------------------------------------------------------------
# Questionnaire questions — 13 total across 4 NIST functions
# ---------------------------------------------------------------------------

QUESTIONS: dict[str, list[QuestionnaireQuestion]] = {

    "GOVERN": [
        QuestionnaireQuestion(
            q_id="G-01", nist_function="GOVERN",
            question="Does your organization have a written AI acceptable use policy?",
            answer_type="yes_no", question_type="standard",
            controls_if_no=["GV.PO-1", "GV.PO-2"],
            severity_if_no="HIGH",
            adapts_for_categories=["generative_ai", "internal_llm"],
            follow_up_if_no="Do you plan to create one in the next 90 days?"
        ),
        QuestionnaireQuestion(
            q_id="G-02", nist_function="GOVERN",
            question="Does your organization have a named person accountable for AI governance decisions?",
            answer_type="yes_no", question_type="standard",
            controls_if_no=["GV.OV-1", "GV.OV-2", "GV.AT-2"],
            severity_if_no="HIGH",
            adapts_for_categories=["generative_ai", "internal_llm", "data_ai"]
        ),
        QuestionnaireQuestion(
            q_id="G-03", nist_function="GOVERN",
            question="Are AI risks included in your organization's formal risk reporting?",
            answer_type="yes_no", question_type="standard",
            controls_if_no=["GV.OV-3"],
            severity_if_no="MEDIUM",
            adapts_for_categories=["generative_ai", "internal_llm"]
        ),
        QuestionnaireQuestion(
            q_id="G-04", nist_function="GOVERN",
            question="Have staff who use AI tools received training on responsible use and associated risks?",
            answer_type="yes_no", question_type="standard",
            controls_if_no=["GV.AT-1"],
            severity_if_no="MEDIUM",
            adapts_for_categories=["generative_ai", "code_assistant", "writing_assistant"]
        ),
    ],

    "MAP": [
        QuestionnaireQuestion(
            q_id="M-01", nist_function="MAP",
            question="Has your organization formally inventoried all AI tools currently in use?",
            answer_type="yes_no", question_type="standard",
            controls_if_no=["MP.AC-1"],
            severity_if_no="HIGH",
            note="Compass log scan partially answers this — confirms whether a formal process exists beyond the scan."
        ),
        QuestionnaireQuestion(
            q_id="M-02", nist_function="MAP",
            question="Is the intended business purpose documented for each AI tool your organization uses?",
            answer_type="yes_no", question_type="standard",
            controls_if_no=["MP.AC-2"],
            severity_if_no="MEDIUM",
            adapts_for_categories=["generative_ai", "internal_llm", "data_ai"]
        ),
        QuestionnaireQuestion(
            q_id="M-03", nist_function="MAP",
            question="Has your organization conducted a risk assessment for the AI tools detected in this scan?",
            answer_type="yes_no", question_type="standard",
            controls_if_no=["MP.AI-1", "MP.RD-1"],
            severity_if_no="HIGH",
            adapts_for_categories=["generative_ai", "open_source_model", "internal_llm"]
        ),
    ],

    "MEASURE": [
        QuestionnaireQuestion(
            q_id="MS-01", nist_function="MEASURE",
            question="Does your organization actively monitor AI tool usage through logs, alerts, or SIEM?",
            answer_type="yes_no", question_type="standard",
            controls_if_no=["MS.AN-1", "MS.MC-1"],
            severity_if_no="HIGH",
            note="Compass is a one-time scan — this asks whether continuous monitoring exists beyond Compass."
        ),
        QuestionnaireQuestion(
            q_id="MS-02", nist_function="MEASURE",
            question="Are AI-generated outputs reviewed by a human before being used in business decisions?",
            answer_type="yes_no", question_type="genai_specific",
            controls_if_no=["MS.AN-2"],
            severity_if_no="MEDIUM",
            adapts_for_categories=["generative_ai", "internal_llm"],
            note="GenAI specific — only show when generative_ai or internal_llm tools detected."
        ),
        QuestionnaireQuestion(
            q_id="MS-03", nist_function="MEASURE",
            question="Does your organization have controls preventing sensitive data from being entered into AI tools?",
            answer_type="yes_no", question_type="standard",
            controls_if_no=["MS.DW-1"],
            severity_if_no="HIGH",
            adapts_for_categories=["generative_ai", "code_assistant", "writing_assistant", "internal_llm"]
        ),
    ],

    "MANAGE": [
        QuestionnaireQuestion(
            q_id="MG-01", nist_function="MANAGE",
            question="Does your organization have a documented process for responding to AI-related incidents?",
            answer_type="yes_no", question_type="standard",
            controls_if_no=["MG.AN-1"],
            severity_if_no="MEDIUM",
            adapts_for_categories=["generative_ai", "internal_llm", "open_source_model"]
        ),
        QuestionnaireQuestion(
            q_id="MG-02", nist_function="MANAGE",
            question="Does your organization have a process to block or restrict AI tools that violate policy?",
            answer_type="yes_no", question_type="standard",
            controls_if_no=["MG.PO-1", "MG.DM-1"],
            severity_if_no="HIGH",
            adapts_for_categories=["generative_ai", "code_assistant", "writing_assistant",
                                   "image_generation", "open_source_model"]
        ),
        QuestionnaireQuestion(
            q_id="MG-03", nist_function="MANAGE",
            question="Are your AI governance policies reviewed and updated on a regular schedule?",
            answer_type="yes_no", question_type="standard",
            controls_if_no=["MG.RR-1"],
            severity_if_no="LOW",
            adapts_for_categories=["generative_ai", "internal_llm"]
        ),
    ],

    # ── VENDOR — auto-scored from RegistryAttributes, NOT shown to analyst ──
    # Shivali: call score_vendor_gaps(agent) to compute these automatically.
    # Mario: do NOT render these as UI questions — they score silently.
    "VENDOR": [
        QuestionnaireQuestion(
            q_id="V-01", nist_function="VENDOR",
            question="Vendor has a current SOC 2 Type II certification.",
            answer_type="auto", question_type="vendor",
            controls_if_no=["GV.OV-2"],
            severity_if_no="HIGH",
            auto_score_from="soc2_certified",
            note="Auto-scored: if soc2_certified is False, GV.OV-2 is flagged."
        ),
        QuestionnaireQuestion(
            q_id="V-02", nist_function="VENDOR",
            question="Vendor offers a Data Processing Agreement for enterprise customers.",
            answer_type="auto", question_type="vendor",
            controls_if_no=["MG.PO-1"],
            severity_if_no="HIGH",
            auto_score_from="data_processing_agreement_available",
            note="Auto-scored: if data_processing_agreement_available is False, MG.PO-1 is flagged."
        ),
        QuestionnaireQuestion(
            q_id="V-03", nist_function="VENDOR",
            question="Vendor does NOT train models on user inputs by default.",
            answer_type="auto", question_type="vendor",
            controls_if_no=["MS.DW-1"],
            severity_if_no="HIGH",
            auto_score_from="trains_on_inputs",
            note="Auto-scored (inverted): if trains_on_inputs is True, MS.DW-1 is flagged."
        ),
        QuestionnaireQuestion(
            q_id="V-04", nist_function="VENDOR",
            question="Vendor privacy policy is rated A or B.",
            answer_type="auto", question_type="vendor",
            controls_if_no=["GV.PO-1"],
            severity_if_no="MEDIUM",
            auto_score_from="privacy_policy_grade",
            note="Auto-scored: if privacy_policy_grade is C or D, GV.PO-1 is flagged."
        ),
    ],

    # ── CONDITIONAL — only shown when parent question answered a certain way ──
    # Mario: render these only when parent_q_id answer matches trigger_answer.
    "CONDITIONAL": [
        QuestionnaireQuestion(
            q_id="G-01-C", nist_function="GOVERN",
            question="Do you plan to create an AI acceptable use policy in the next 90 days?",
            answer_type="yes_no", question_type="conditional",
            controls_if_no=[], severity_if_no="LOW",
            parent_q_id="G-01", trigger_answer="no",
            note="Informational only — no gap score. Flags remediation urgency."
        ),
        QuestionnaireQuestion(
            q_id="G-02-C", nist_function="GOVERN",
            question="Is assigning an AI governance owner on your near-term roadmap (next 90 days)?",
            answer_type="yes_no", question_type="conditional",
            controls_if_no=[], severity_if_no="LOW",
            parent_q_id="G-02", trigger_answer="no",
            note="Informational only — no gap score. Flags remediation urgency."
        ),
        QuestionnaireQuestion(
            q_id="MS-01-C", nist_function="MEASURE",
            question="Do you have any other manual review process for AI tool usage (e.g. periodic audits)?",
            answer_type="yes_no", question_type="conditional",
            controls_if_no=[], severity_if_no="LOW",
            parent_q_id="MS-01", trigger_answer="no",
            note="Informational — distinguishes no monitoring at all from informal monitoring."
        ),
    ],
}


# ---------------------------------------------------------------------------
# All 12 GenAI risks from NIST-AI-600-1 (July 2024)
# ---------------------------------------------------------------------------

GENAI_RISKS: dict[str, GenAIRiskProfile] = {
    r.risk_id: r for r in [
        GenAIRiskProfile("confabulation",     "The AI produces false or fabricated information presented as fact.",                           ["generative_ai", "internal_llm"]),
        GenAIRiskProfile("data_privacy",      "User inputs contain or expose personal or sensitive data sent to the AI vendor.",             ["generative_ai", "code_assistant", "writing_assistant"]),
        GenAIRiskProfile("prompt_injection",  "Malicious instructions embedded in inputs manipulate the AI's behavior.",                    ["generative_ai", "internal_llm"]),
        GenAIRiskProfile("ip_exposure",       "Proprietary or confidential business information is shared with the AI vendor.",             ["generative_ai", "code_assistant", "writing_assistant"]),
        GenAIRiskProfile("info_security",     "The AI system introduces new attack vectors or is used to assist cyberattacks.",             ["generative_ai", "code_assistant", "open_source_model"]),
        GenAIRiskProfile("human_ai_config",   "Humans over-rely on AI outputs or misunderstand the AI's role in decisions.",               ["generative_ai", "internal_llm", "data_ai"]),
        GenAIRiskProfile("info_integrity",    "AI-generated content spreads misinformation or degrades information quality.",               ["generative_ai", "writing_assistant"]),
        GenAIRiskProfile("cbrn",              "AI is used to assist in creating chemical, biological, radiological, or nuclear threats.",   ["generative_ai", "open_source_model"]),
        GenAIRiskProfile("harmful_content",   "AI generates violent, abusive, or otherwise harmful content.",                              ["generative_ai", "image_generation"]),
        GenAIRiskProfile("human_replication", "AI is used to impersonate humans or create deceptive synthetic media.",                     ["generative_ai", "voice_ai", "image_generation"]),
        GenAIRiskProfile("societal_impacts",  "AI use at scale creates broader social harms such as bias, discrimination, or inequity.",   ["generative_ai", "data_ai", "internal_llm"]),
        GenAIRiskProfile("data_poisoning",    "Malicious data is introduced into AI training or input pipelines to corrupt outputs.",      ["open_source_model", "internal_llm", "data_ai"]),
    ]
}


# ---------------------------------------------------------------------------
# Primary query function — Shivali calls this in the scoring engine
# ---------------------------------------------------------------------------

def query_controls(tool_category: str) -> list[NistControl]:
    """
    Returns all NIST controls that apply to a given tool category.
    Call this once per detected agent type after log parsing.

    Args:
        tool_category: The agent's category string from AgentRecord.category
                       e.g. "generative_ai", "code_assistant", "unknown"

    Returns:
        List of NistControl objects, sorted HIGH → MEDIUM → LOW severity.

    Example:
        controls = query_controls("generative_ai")
        for ctrl in controls:
            print(ctrl.control_id, ctrl.severity_weight, ctrl.questionnaire_question_id)
    """
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    matched = [c for c in ALL_CONTROLS if tool_category in c.applies_to_categories]
    return sorted(matched, key=lambda c: order[c.severity_level])


def get_controls_for_question(q_id: str) -> list[NistControl]:
    """
    Returns all controls linked to a specific questionnaire question ID.
    Useful for confirming gaps after an answer is submitted.

    Example:
        controls = get_controls_for_question("G-01")
        # returns GV.PO-1 and GV.PO-2
    """
    return [c for c in ALL_CONTROLS if c.questionnaire_question_id == q_id]


def get_question(q_id: str) -> Optional[QuestionnaireQuestion]:
    """Returns a single question by ID across all functions."""
    for questions in QUESTIONS.values():
        for q in questions:
            if q.q_id == q_id:
                return q
    return None


def score_vendor_gaps(registry_attributes) -> tuple[float, list[str]]:
    """
    Auto-scores vendor-based gaps from RegistryAttributes.
    Called by the scoring engine after log parse — no analyst input needed.

    Uses the same 0 / 50 / 100 credit scale as compass_questionnaire.py's
    Yes / Unsure / No answers:
        100 (pass)    -> field fully satisfies the control -- no gap
         50 (partial)  -> field is missing / unclear -- counted as half a gap
          0 (fail)     -> field fails the control -- full gap

    Args:
        registry_attributes: An AgentRecord.registry_attributes object.
                             Pass None for shadow AI candidates.

    Returns:
        (vendor_gap_score, unmet_control_ids). Score can be fractional now
        that a "partial" (unknown/unclear) field contributes half of a
        control's severity_weight instead of the full amount.
    """
    if registry_attributes is None:
        return 0, []

    score = 0
    unmet = []

    for q in QUESTIONS.get("VENDOR", []):
        field = q.auto_score_from
        val = getattr(registry_attributes, field, None)

        # Determine credit level: pass (100) / partial (50) / fail (0)
        if field == "trains_on_inputs":
            if val is True:
                credit = "fail"          # trains_on_inputs=True is the bad outcome
            elif val is False:
                credit = "pass"
            else:
                credit = "partial"       # unknown -- half credit
        elif field == "privacy_policy_grade":
            if val in ("A", "B"):
                credit = "pass"
            elif val == "C":
                credit = "partial"       # C grade -- half credit
            elif val == "D":
                credit = "fail"
            else:
                credit = "partial"       # ungraded/unknown -- half credit
        else:
            if val is True:
                credit = "pass"
            elif val is False:
                credit = "fail"
            else:
                credit = "partial"       # unknown -- half credit

        gap_frac = (100 - VENDOR_CREDIT[credit]) / 100
        if gap_frac > 0:
            score += SEVERITY_WEIGHT[q.severity_if_no] * gap_frac
            unmet.extend(q.controls_if_no)

    return score, unmet


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=== query_controls('generative_ai') ===")
    controls = query_controls("generative_ai")
    for c in controls:
        print(f"  {c.control_id:<12} {c.severity_level:<8} weight={c.severity_weight}  q={c.questionnaire_question_id}")

    print(f"\nTotal controls for generative_ai: {len(controls)}")
    print(f"Max possible gap score:           {sum(c.severity_weight for c in controls)}")

    print("\n=== get_controls_for_question('G-01') ===")
    for c in get_controls_for_question("G-01"):
        print(f"  {c.control_id} — {c.description[:60]}...")

    print("\n=== Questions by type ===")
    for fn, qs in QUESTIONS.items():
        for q in qs:
            print(f"  [{q.question_type:<14}] {q.q_id:<8} {q.question[:55]}...")

    print("\n=== GENAI_RISKS sample ===")
    print(f"  data_privacy: {GENAI_RISKS['data_privacy'].plain_english}")

    print(f"\nTotal controls:  {len(ALL_CONTROLS)}")
    total_q = sum(len(v) for v in QUESTIONS.values())
    standard = sum(1 for qs in QUESTIONS.values() for q in qs if q.question_type == "standard")
    genai    = sum(1 for qs in QUESTIONS.values() for q in qs if q.question_type == "genai_specific")
    vendor   = sum(1 for qs in QUESTIONS.values() for q in qs if q.question_type == "vendor")
    cond     = sum(1 for qs in QUESTIONS.values() for q in qs if q.question_type == "conditional")
    print(f"Total questions: {total_q}  (standard={standard}, genai_specific={genai}, vendor={vendor}, conditional={cond})")
    print(f"Total GenAI risks: {len(GENAI_RISKS)}")
