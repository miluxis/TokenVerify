from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Rating(str, Enum):
    HIGH_TRUST = "High Trust"
    MEDIUM_TRUST = "Medium Trust"
    LOW_TRUST = "Low Trust"
    INCONCLUSIVE = "Inconclusive"


class ProbeCategory(str, Enum):
    PROTOCOL = "protocol"
    CAPABILITY = "capability"
    STREAM = "stream"
    ERROR = "error"
    REPEATABILITY = "repeatability"
    CHANNEL_RISK = "channel_risk"


class EvidenceTag(str, Enum):
    ANTHROPIC_NATIVE_SHAPE_MATCH = "ANTHROPIC_NATIVE_SHAPE_MATCH"
    ANTHROPIC_NATIVE_SHAPE_MISMATCH = "ANTHROPIC_NATIVE_SHAPE_MISMATCH"
    OPENAI_COMPATIBLE_SHAPE_DETECTED = "OPENAI_COMPATIBLE_SHAPE_DETECTED"
    OPENAI_COMPATIBLE_SHAPE_MATCH = "OPENAI_COMPATIBLE_SHAPE_MATCH"
    ANTHROPIC_NATIVE_SHAPE_DETECTED = "ANTHROPIC_NATIVE_SHAPE_DETECTED"
    GENERIC_PROXY_ERROR_DETECTED = "GENERIC_PROXY_ERROR_DETECTED"
    ERROR_SCHEMA_MATCH = "ERROR_SCHEMA_MATCH"
    ERROR_SCHEMA_MISMATCH = "ERROR_SCHEMA_MISMATCH"
    STREAM_EVENT_SEQUENCE_MATCH = "STREAM_EVENT_SEQUENCE_MATCH"
    STREAM_EVENT_SEQUENCE_MISMATCH = "STREAM_EVENT_SEQUENCE_MISMATCH"
    EXTENDED_THINKING_MATCH = "EXTENDED_THINKING_MATCH"
    EXTENDED_THINKING_MISSING = "EXTENDED_THINKING_MISSING"
    EXTENDED_THINKING_REJECTED = "EXTENDED_THINKING_REJECTED"
    EXTENDED_THINKING_IGNORED = "EXTENDED_THINKING_IGNORED"
    MODEL_CAPABILITY_MATCH = "MODEL_CAPABILITY_MATCH"
    MODEL_CAPABILITY_MISMATCH = "MODEL_CAPABILITY_MISMATCH"
    CLAUDE_MODEL_CLAIM_MATCH = "CLAUDE_MODEL_CLAIM_MATCH"
    CLAUDE_MODEL_CLAIM_MISMATCH = "CLAUDE_MODEL_CLAIM_MISMATCH"
    MIXED_PROVIDER_INCONSISTENCY_DETECTED = "MIXED_PROVIDER_INCONSISTENCY_DETECTED"
    CLAUDE_VERSION_FIELD_LEAKED = "CLAUDE_VERSION_FIELD_LEAKED"
    CLAUDE_THINKING_CAPABILITY_MATCH = "CLAUDE_THINKING_CAPABILITY_MATCH"
    CLAUDE_THINKING_CAPABILITY_MISMATCH = "CLAUDE_THINKING_CAPABILITY_MISMATCH"
    OPENAI_STREAM_SEQUENCE_MATCH = "OPENAI_STREAM_SEQUENCE_MATCH"
    OPENAI_CHAT_COMPLETION_SHAPE_MATCH = "OPENAI_CHAT_COMPLETION_SHAPE_MATCH"
    OPENAI_CHAT_COMPLETION_SHAPE_MISMATCH = "OPENAI_CHAT_COMPLETION_SHAPE_MISMATCH"
    NON_OPENAI_PROVIDER_SHAPE_DETECTED = "NON_OPENAI_PROVIDER_SHAPE_DETECTED"
    OPENAI_MODEL_CLAIM_MATCH = "OPENAI_MODEL_CLAIM_MATCH"
    OPENAI_MODEL_CLAIM_MISMATCH = "OPENAI_MODEL_CLAIM_MISMATCH"
    CROSS_PROVIDER_MODEL_LEAKED = "CROSS_PROVIDER_MODEL_LEAKED"
    OPENAI_STREAM_SEQUENCE_MISMATCH = "OPENAI_STREAM_SEQUENCE_MISMATCH"
    OPENAI_REASONING_CAPABILITY_MATCH = "OPENAI_REASONING_CAPABILITY_MATCH"
    OPENAI_REASONING_CAPABILITY_MISMATCH = "OPENAI_REASONING_CAPABILITY_MISMATCH"
    OPENAI_OFFICIAL_CHANNEL_MATCH = "OPENAI_OFFICIAL_CHANNEL_MATCH"
    OPENAI_OFFICIAL_CHANNEL_MISMATCH = "OPENAI_OFFICIAL_CHANNEL_MISMATCH"
    CROSS_PROVIDER_REASONING_LEAKED = "CROSS_PROVIDER_REASONING_LEAKED"
    DEEPSEEK_CHAT_COMPLETION_SHAPE_MATCH = "DEEPSEEK_CHAT_COMPLETION_SHAPE_MATCH"
    DEEPSEEK_CHAT_COMPLETION_SHAPE_MISMATCH = "DEEPSEEK_CHAT_COMPLETION_SHAPE_MISMATCH"
    NON_DEEPSEEK_PROVIDER_SHAPE_DETECTED = "NON_DEEPSEEK_PROVIDER_SHAPE_DETECTED"
    DEEPSEEK_MODEL_CLAIM_MATCH = "DEEPSEEK_MODEL_CLAIM_MATCH"
    DEEPSEEK_MODEL_CLAIM_MISMATCH = "DEEPSEEK_MODEL_CLAIM_MISMATCH"
    DEEPSEEK_REASONING_CONTENT_MATCH = "DEEPSEEK_REASONING_CONTENT_MATCH"
    DEEPSEEK_REASONING_CONTENT_MISSING = "DEEPSEEK_REASONING_CONTENT_MISSING"
    DEEPSEEK_STREAM_SEQUENCE_MATCH = "DEEPSEEK_STREAM_SEQUENCE_MATCH"
    DEEPSEEK_STREAM_SEQUENCE_MISMATCH = "DEEPSEEK_STREAM_SEQUENCE_MISMATCH"
    DEEPSEEK_STREAM_REASONING_MATCH = "DEEPSEEK_STREAM_REASONING_MATCH"
    DEEPSEEK_STREAM_REASONING_MISSING = "DEEPSEEK_STREAM_REASONING_MISSING"
    DEEPSEEK_OFFICIAL_CHANNEL_MATCH = "DEEPSEEK_OFFICIAL_CHANNEL_MATCH"
    DEEPSEEK_OFFICIAL_CHANNEL_MISMATCH = "DEEPSEEK_OFFICIAL_CHANNEL_MISMATCH"


class RiskTag(str, Enum):
    STREAM_UNIFORMITY_SUSPECT = "STREAM_UNIFORMITY_SUSPECT"
    SYNTHETIC_STREAM_SUSPECT = "SYNTHETIC_STREAM_SUSPECT"
    TTFT_VARIANCE_HIGH = "TTFT_VARIANCE_HIGH"
    THROUGHPUT_ANOMALY = "THROUGHPUT_ANOMALY"
    CONCURRENT_POOL_SUSPECT = "CONCURRENT_POOL_SUSPECT"
    WEB_REVERSE_SUSPECT = "WEB_REVERSE_SUSPECT"
    UNSTABLE_RELAY_SUSPECT = "UNSTABLE_RELAY_SUSPECT"
    HOSTED_BY_AWS = "HOSTED_BY_AWS"
    HOSTED_BY_AZURE = "HOSTED_BY_AZURE"
    HOSTED_BY_UNKNOWN_PROXY = "HOSTED_BY_UNKNOWN_PROXY"
    CROSS_PROVIDER_FINISH_REASON_SUSPECT = "CROSS_PROVIDER_FINISH_REASON_SUSPECT"
    SELF_RELAY_LOOP_DETECTED = "SELF_RELAY_LOOP_DETECTED"
    SYNTHETIC_THINKING_SUSPECT = "SYNTHETIC_THINKING_SUSPECT"
    RELAY_HEADER_SUSPECT = "RELAY_HEADER_SUSPECT"
    RATE_LIMIT_RELAY_SUSPECT = "RATE_LIMIT_RELAY_SUSPECT"
    REGION_LATENCY_INCONSISTENT = "REGION_LATENCY_INCONSISTENT"
    MODEL_DRIFT_SUSPECT = "MODEL_DRIFT_SUSPECT"


@dataclass(frozen=True)
class Claim:
    model: str
    provider: str = "anthropic"
    api_shape: str = "native"
    channel_claim: str = "unknown"
    region_claim: str | None = None


@dataclass(frozen=True)
class Verdict:
    rating: Rating
    authenticity_score: int
    risk_score: int
    tags: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class EndpointConfig:
    name: str
    base_url: str
    model: str
    api_key: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    claim: Claim | None = None


@dataclass(frozen=True)
class RuntimeConfig:
    endpoint: EndpointConfig
    output_path: Path
    raw_logs_enabled: bool = False
    raw_log_path: Path | None = None
    extension_probes: list[dict[str, Any]] = field(default_factory=list)
    redacted_config: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ProviderEvent:
    timestamp: float
    event_type: str
    text_length: int | None = None
    data: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class EvidenceItem:
    key: str
    weight: str
    passed: bool | None
    message: str
    details: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ProbeResult:
    name: str
    status: str
    evidence: list[EvidenceItem] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    metrics: Any | None = None


@dataclass(frozen=True)
class StreamingMetrics:
    ttft_seconds: float | None
    total_latency_seconds: float
    chunk_intervals: list[float]
    chunk_size_distribution: list[int]
    estimated_tps: float | None
    is_synthetic_stream: bool


@dataclass(frozen=True)
class AuditResult:
    target_summary: dict[str, Any]
    probe_results: list[ProbeResult]
    rating: Rating
    score_breakdown: dict[str, int]
    verdict: Verdict | None = None
    claim: Claim | None = None
    report_warnings: list[str] = field(default_factory=list)
    raw_log_path: Path | None = None
    redacted_config: dict[str, Any] = field(default_factory=dict)
    extension_probe_results: list[ProbeResult] = field(default_factory=list)
