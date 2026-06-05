from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RelayAuditConfigError(ValueError):
    pass


class RelayAuditProfile(str, Enum):
    GENERAL = "general"
    STREAMING = "streaming"
    SCHEMA = "schema"
    PRIVACY = "privacy"
    SECURITY = "security"
    CONTEXT = "context"
    FULL = "full"


class RelayVerdict(str, Enum):
    PASS = "pass"
    SUSPICIOUS = "suspicious"
    FAIL = "fail"
    INCONCLUSIVE = "inconclusive"


class RelayRiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    UNKNOWN = "unknown"


class RelayAuditMode(str, Enum):
    FAKE = "fake"
    LIVE = "live"


class RelayRuntimeCategory(str, Enum):
    AUTH_ERROR = "auth_error"
    QUOTA_OR_RATE_LIMIT = "quota_or_rate_limit"
    TIMEOUT = "timeout"
    DISCONNECT = "disconnect"
    NETWORK_ERROR = "network_error"
    UNSUPPORTED_LIVE_TARGET = "unsupported_live_target"
    UNKNOWN_RUNTIME_ERROR = "unknown_runtime_error"


class RelayRiskCategory(str, Enum):
    PROMPT_INSTRUCTION_LEAKAGE = "prompt_instruction_leakage"
    MESSAGE_REWRITE = "message_rewrite"
    CONTEXT_TRUNCATION = "context_truncation"
    MODEL_SUBSTITUTION = "model_substitution"
    STREAMING_INTEGRITY = "streaming_integrity"
    SCHEMA_TOOL_REWRITE = "schema_tool_rewrite"
    UPSTREAM_ERROR_LEAKAGE = "upstream_error_leakage"
    LATENCY_OR_INSTABILITY = "latency_or_instability"
    INFRASTRUCTURE_FINGERPRINT = "infrastructure_fingerprint"


@dataclass(frozen=True)
class RelayEvidence:
    key: str
    category: RelayRiskCategory
    status: str
    summary: str
    metrics: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RelayPackSummary:
    label: str
    pack_hash: str | None
    pack_id: str | None = None
    version: str | None = None
    basename: str | None = None
    profiles: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    challenge_count: int = 0
    public_intents: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class RelayResult:
    run_id: str
    profile: RelayAuditProfile
    scenario: RelayVerdict
    mode: RelayAuditMode
    model: str
    endpoint_host: str
    endpoint_hash: str
    pack_summary: RelayPackSummary
    verdict: RelayVerdict
    risk_level: RelayRiskLevel
    risk_categories: list[RelayRiskCategory]
    evidence: list[RelayEvidence]
    retest_guidance: str
    inconclusive_reason: str | None = None
    runtime_category: RelayRuntimeCategory | None = None


def parse_relay_profile(value: str) -> RelayAuditProfile:
    normalized = value.strip().lower()
    try:
        return RelayAuditProfile(normalized)
    except ValueError as exc:
        accepted = ", ".join(item.value for item in RelayAuditProfile)
        raise RelayAuditConfigError(f"Unknown relay audit profile. Accepted values: {accepted}.") from exc


def parse_relay_scenario(value: str) -> RelayVerdict:
    normalized = value.strip().lower()
    try:
        return RelayVerdict(normalized)
    except ValueError as exc:
        accepted = ", ".join(item.value for item in RelayVerdict)
        raise RelayAuditConfigError(f"Unknown relay fake-run scenario. Accepted values: {accepted}.") from exc
