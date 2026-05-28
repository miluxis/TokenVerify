from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Rating(str, Enum):
    HIGH_TRUST = "高可信"
    MEDIUM_TRUST = "中可信"
    LOW_TRUST = "低可信"
    INCONCLUSIVE = "无法判定"


@dataclass(frozen=True)
class EndpointConfig:
    name: str
    base_url: str
    model: str
    api_key: str | None = None
    headers: dict[str, str] = field(default_factory=dict)


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
    report_warnings: list[str] = field(default_factory=list)
    raw_log_path: Path | None = None
    redacted_config: dict[str, Any] = field(default_factory=dict)
    extension_probe_results: list[ProbeResult] = field(default_factory=list)
