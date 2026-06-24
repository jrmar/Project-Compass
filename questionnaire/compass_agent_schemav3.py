"""
compass_agent_schema.py
=======================
Defines the structure of a detected AI agent/tool in the Compass system.

An agent record is built by the log parser (Layer 1) and enriched by the
AI Tool Registry lookup. Raw log data (IP addresses, device identifiers,
raw domain traffic) is NEVER persisted — only the fields defined here are saved.

Usage (FastAPI / Flask):
    from compass_agent_schema import AgentRecord, RegistryAttributes, RiskLevel

Compatible with Python 3.9+. Requires: pip install pydantic
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class RiskLevel(str, Enum):
    HIGH    = "high"
    MEDIUM  = "medium"
    LOW     = "low"
    UNKNOWN = "unknown"      # domain had no registry match


class AgentCategory(str, Enum):
    GENERATIVE_AI   = "generative_ai"
    CODE_ASSISTANT  = "code_assistant"
    WRITING_ASSIST  = "writing_assistant"
    IMAGE_GEN       = "image_generation"
    VOICE_AI        = "voice_ai"
    DATA_AI         = "data_ai"
    OPEN_SOURCE_LLM = "open_source_model"
    INTERNAL_LLM    = "internal_llm"
    UNKNOWN         = "unknown"


class ReviewStatus(str, Enum):
    UNREVIEWED = "unreviewed"   # default at parse time
    APPROVED   = "approved"
    FLAGGED    = "flagged"
    BLOCKED    = "blocked"


class PrivacyPolicyGrade(str, Enum):
    A = "A"   # strong
    B = "B"
    C = "C"
    D = "D"   # weak or absent


class GenAIRisk(str, Enum):
    """
    12 GenAI-specific risks from NIST-AI-600-1 (July 2024).
    Pre-flagged per tool type from the registry — not final gap scores.
    """
    CONFABULATION     = "confabulation"
    DATA_PRIVACY      = "data_privacy"
    PROMPT_INJECTION  = "prompt_injection"
    IP_EXPOSURE       = "ip_exposure"
    INFO_SECURITY     = "info_security"
    HUMAN_AI_CONFIG   = "human_ai_config"
    INFO_INTEGRITY    = "info_integrity"
    CBRN              = "cbrn"
    HARMFUL_CONTENT   = "harmful_content"
    HUMAN_REPLICATION = "human_replication"
    SOCIETAL_IMPACTS  = "societal_impacts"
    DATA_POISONING    = "data_poisoning"


# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------

class RegistryAttributes(BaseModel):
    """
    Metadata sourced from the AI Tool Registry JSON file.
    None for shadow AI candidates with no registry match.
    """
    soc2_certified: bool = Field(
        description="Whether the vendor has a current SOC 2 Type II certification."
    )
    privacy_policy_grade: PrivacyPolicyGrade = Field(
        description="Internal risk grade assigned to the vendor privacy policy. A=strong, D=weak or absent."
    )
    data_processing_agreement_available: bool = Field(
        description="Whether the vendor offers a Data Processing Agreement (DPA) for enterprise customers."
    )
    trains_on_inputs: bool = Field(
        description="Whether the vendor uses user inputs to train or fine-tune models by default."
    )
    data_retention_policy: str = Field(
        description="Vendor stated data retention period for user inputs."
    )
    vendor_notes: Optional[str] = Field(
        default=None,
        description="Free-text notes from the registry about this vendor's governance posture."
    )


class ParseError(BaseModel):
    """
    Captures any log line that could not be fully parsed.
    Zero silent failures — all errors are recorded here.
    """
    line_number: int  = Field(description="1-indexed line number in the uploaded log file.")
    raw_line: str     = Field(description="The raw log line that failed to parse.")
    error_reason: str = Field(description="Human-readable reason the line could not be parsed.")


# ---------------------------------------------------------------------------
# Main agent record
# ---------------------------------------------------------------------------

class AgentRecord(BaseModel):
    """
    A single detected AI agent/tool record produced by the Compass log parser.

    Lifecycle:
        1. Log parser extracts raw hits → creates AgentRecord with parse-time fields
        2. AI Tool Registry lookup → populates tool_name, vendor, category,
           risk_level, registry_attributes, nist_risk_flags
        3. Analyst reviews in inventory UI → updates review_status
        4. Scoring engine consumes agent_id + nist_risk_flags → gap score

    Data minimization:
        Fields NOT stored: raw log lines, client_ip, device hostnames, query payloads.
        Only the fields in this schema are persisted after session close.
    """

    model_config = ConfigDict(use_enum_values=True)

    # -- Identity --
    agent_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier generated at parse time for this agent within the session."
    )

    # -- Tool identification (from registry lookup) --
    tool_name: str = Field(
        description="Human-readable name from the AI Tool Registry. 'UNKNOWN' if no registry match."
    )
    vendor: Optional[str] = Field(
        default=None,
        description="Organization that owns or operates the tool. None if unknown."
    )
    category: AgentCategory = Field(
        default=AgentCategory.UNKNOWN,
        description="Classification of the AI tool type."
    )

    # -- Domain (normalized) --
    domain: str = Field(
        description=(
            "Normalized root domain after subdomain stripping. "
            "Example: us-east.api.openai.com → api.openai.com."
        )
    )
    raw_domains_seen: List[str] = Field(
        default_factory=list,
        description="All raw subdomain variants observed before normalization. Audit trail only."
    )

    # -- Risk --
    risk_level: RiskLevel = Field(
        description="Risk classification from the AI Tool Registry. 'unknown' when no registry match."
    )
    shadow_ai_candidate: bool = Field(
        default=False,
        description="True when the domain did not match any registry entry. Requires manual analyst review."
    )

    # -- Timing and volume --
    first_seen: datetime = Field(
        description="Timestamp of the earliest log entry for this domain in the uploaded file."
    )
    last_seen: datetime = Field(
        description="Timestamp of the most recent log entry for this domain in the uploaded file."
    )
    frequency: int = Field(
        ge=1,
        description="Total number of DNS queries to this domain in the uploaded log."
    )
    data_volume_bytes: int = Field(
        ge=0,
        default=0,
        description="Sum of bytes_out across all matching log entries."
    )

    # -- Analyst workflow --
    review_status: ReviewStatus = Field(
        default=ReviewStatus.UNREVIEWED,
        description="Analyst review state. Set to 'unreviewed' at parse time."
    )

    # -- Registry enrichment --
    registry_attributes: Optional[RegistryAttributes] = Field(
        default=None,
        description="Vendor metadata from the AI Tool Registry. None for shadow AI candidates."
    )

    # -- NIST pre-flags --
    nist_risk_flags: List[GenAIRisk] = Field(
        default_factory=list,
        description=(
            "GenAI risk categories from NIST-AI-600-1 pre-flagged for this tool type. "
            "These seed the questionnaire — not final gap scores."
        )
    )

    # -- NIST scoring (UC-1: potential exposure, set at detection time) --
    applicable_control_ids: List[str] = Field(
        default_factory=list,
        description=(
            "IDs of all NIST AI RMF controls that apply to this tool's category. "
            "Populated by query_controls(category) immediately after detection. "
            "Example: ['GV.PO-1', 'GV.OV-2', 'MS.AN-1', ...]"
        )
    )
    potential_exposure: int = Field(
        default=0,
        description=(
            "Sum of severity weights for all applicable controls. "
            "This is the INHERENT risk — worst case if none of the controls are met. "
            "Available immediately from detection, no questionnaire needed. "
            "HIGH=15, MEDIUM=7, LOW=2."
        )
    )

    # -- NIST scoring (UC-2: confirmed gaps, set after questionnaire) --
    confirmed_gap_score: Optional[int] = Field(
        default=None,
        description=(
            "Sum of severity weights for controls confirmed as UNMET by questionnaire answers. "
            "None until the analyst completes the governance questionnaire. "
            "Always <= potential_exposure."
        )
    )
    confirmed_unmet_control_ids: List[str] = Field(
        default_factory=list,
        description=(
            "Control IDs confirmed as unmet by No answers in the questionnaire. "
            "Empty until UC-2 completes. "
            "Example: ['GV.PO-1', 'GV.PO-2', 'MS.DW-1']"
        )
    )
    questionnaire_complete: bool = Field(
        default=False,
        description="True once the analyst has submitted all applicable questionnaire answers for this tool."
    )

    # -- NIST scoring (vendor gaps: auto-scored from RegistryAttributes) --
    vendor_gap_score: Optional[int] = Field(
        default=None,
        description=(
            "Sum of severity weights for controls flagged by vendor registry data. "
            "Auto-scored by score_vendor_gaps(registry_attributes) — no analyst input needed. "
            "None for shadow AI candidates with no registry match."
        )
    )
    vendor_unmet_control_ids: List[str] = Field(
        default_factory=list,
        description=(
            "Control IDs flagged by vendor registry checks (SOC2, DPA, trains_on_inputs, privacy grade). "
            "Populated automatically from RegistryAttributes — not from questionnaire answers. "
            "Example: ['GV.OV-2', 'MG.PO-1'] if vendor has no SOC2 and no DPA."
        )
    )

    # -- Parse quality --
    parse_errors: List[ParseError] = Field(
        default_factory=list,
        description="Log lines for this domain that could not be parsed. Zero silent failures."
    )

    # -- Validators --
    @field_validator("domain")
    @classmethod
    def domain_must_be_normalized(cls, v: str) -> str:
        parts = v.split(".")
        if len(parts) > 3:
            raise ValueError(
                f"Domain '{v}' looks un-normalized. "
                f"Strip subdomains before setting domain field. "
                f"Store the original in raw_domains_seen."
            )
        return v.lower()

    @model_validator(mode="after")
    def last_seen_after_first(self) -> AgentRecord:
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen must be >= first_seen")
        return self


# ---------------------------------------------------------------------------
# Parser output wrapper
# ---------------------------------------------------------------------------

class ParseResult(BaseModel):
    """
    Top-level output of a single log file parse run.
    Returned by the log parser to the frontend after UC-1 completes.
    """
    session_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique ID for this parse session. Ties the inventory to the UC-2 gap assessment."
    )
    log_filename: str = Field(
        description="Original filename of the uploaded log. Not stored — display only."
    )
    parsed_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="UTC timestamp when the parse completed."
    )
    total_lines: int   = Field(description="Total number of lines in the uploaded log file.")
    parsed_lines: int  = Field(description="Number of lines successfully parsed.")
    skipped_lines: int = Field(description="Number of lines skipped due to parse errors.")
    agents: List[AgentRecord] = Field(
        description="All detected AI agents/tools, including shadow AI candidates."
    )

    @property
    def known_agents(self) -> List[AgentRecord]:
        """Registry-matched agents only."""
        return [a for a in self.agents if not a.shadow_ai_candidate]

    @property
    def shadow_ai_candidates(self) -> List[AgentRecord]:
        """Unrecognized domains flagged for manual review."""
        return [a for a in self.agents if a.shadow_ai_candidate]

    @property
    def high_risk_agents(self) -> List[AgentRecord]:
        return [a for a in self.agents if a.risk_level == RiskLevel.HIGH]


# ---------------------------------------------------------------------------
# Example / smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from datetime import timezone

    chatgpt = AgentRecord(
        tool_name="ChatGPT",
        vendor="OpenAI",
        domain="api.openai.com",
        raw_domains_seen=["api.openai.com", "chat.openai.com", "us-east.api.openai.com"],
        category=AgentCategory.GENERATIVE_AI,
        risk_level=RiskLevel.HIGH,
        shadow_ai_candidate=False,
        first_seen=datetime(2026, 6, 10, 8, 23, 14, tzinfo=timezone.utc),
        last_seen=datetime(2026, 6, 10, 17, 45, 22, tzinfo=timezone.utc),
        frequency=47,
        data_volume_bytes=892340,
        registry_attributes=RegistryAttributes(
            soc2_certified=False,
            privacy_policy_grade=PrivacyPolicyGrade.C,
            data_processing_agreement_available=False,
            trains_on_inputs=True,
            data_retention_policy="30_days",
            vendor_notes="Default API logs inputs 30 days. Enterprise zero-retention available."
        ),
        nist_risk_flags=[GenAIRisk.DATA_PRIVACY, GenAIRisk.PROMPT_INJECTION, GenAIRisk.IP_EXPOSURE],
    )

    shadow = AgentRecord(
        tool_name="UNKNOWN",
        domain="runway.ml",
        raw_domains_seen=["api.runway.ml"],
        risk_level=RiskLevel.UNKNOWN,
        shadow_ai_candidate=True,
        first_seen=datetime(2026, 6, 10, 10, 14, 7, tzinfo=timezone.utc),
        last_seen=datetime(2026, 6, 10, 14, 52, 33, tzinfo=timezone.utc),
        frequency=8,
        data_volume_bytes=54200,
    )

    result = ParseResult(
        log_filename="compass_synthetic_dns.log",
        total_lines=1316,
        parsed_lines=1310,
        skipped_lines=6,
        agents=[chatgpt, shadow],
    )

    print(f"Session:              {result.session_id}")
    print(f"Known agents:         {len(result.known_agents)}")
    print(f"Shadow AI candidates: {len(result.shadow_ai_candidates)}")
    print(f"High risk agents:     {len(result.high_risk_agents)}")
    print()
    print(result.agents[0].model_dump_json(indent=2))
