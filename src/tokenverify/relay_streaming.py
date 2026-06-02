from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Iterable, Protocol

from tokenverify.relay_live import NormalizedRelayRuntimeError, normalize_live_runtime_error
from tokenverify.relay_models import (
    RelayAuditMode,
    RelayAuditProfile,
    RelayEvidence,
    RelayPackSummary,
    RelayResult,
    RelayRiskCategory,
    RelayRiskLevel,
    RelayRuntimeCategory,
    RelayVerdict,
)
from tokenverify.relay_safety import RelayLiveAuthorization, hash_relay_endpoint, sanitize_public_relay_text, sanitize_to_fqdn


class RelayStreamingTransport(Protocol):
    def __call__(self, payload: dict[str, Any]) -> Iterable["RelayStreamEvent"]:
        ...


@dataclass(frozen=True)
class RelayStreamEvent:
    event_type: str
    index: int
    has_content_delta: bool
    text_length: int
    has_finish_reason: bool
    finish_reason: str | None = None


class RelayStreamingRuntimeError(RuntimeError):
    def __init__(self, category: RelayRuntimeCategory, public_message: str):
        self.category = category
        self.public_message = sanitize_public_relay_text(public_message)
        super().__init__(self.public_message)


@dataclass(frozen=True)
class NormalizedRelayStreamingRuntimeError:
    category: RelayRuntimeCategory
    public_message: str

    def raise_for_public_handling(self) -> None:
        raise RelayStreamingRuntimeError(self.category, self.public_message) from None


def build_minimal_streaming_payload(model: str) -> dict[str, Any]:
    return {
        "model": sanitize_public_relay_text(model),
        "messages": [{"role": "user", "content": "Return only: ok"}],
        "max_tokens": 16,
        "stream": True,
    }


def normalize_stream_event(raw_event: object, *, index: int) -> RelayStreamEvent:
    if not isinstance(raw_event, dict):
        return RelayStreamEvent(
            event_type="unknown",
            index=index,
            has_content_delta=False,
            text_length=0,
            has_finish_reason=False,
            finish_reason=None,
        )
    choices = raw_event.get("choices")
    first_choice = choices[0] if isinstance(choices, list) and choices and isinstance(choices[0], dict) else {}
    delta = first_choice.get("delta") if isinstance(first_choice, dict) else {}
    content = delta.get("content") if isinstance(delta, dict) else None
    finish_reason = first_choice.get("finish_reason") if isinstance(first_choice, dict) else None
    object_type = raw_event.get("object") or raw_event.get("event_type") or "unknown"
    return RelayStreamEvent(
        event_type=sanitize_public_relay_text(object_type),
        index=index,
        has_content_delta=isinstance(content, str) and bool(content),
        text_length=len(content) if isinstance(content, str) else 0,
        has_finish_reason=finish_reason is not None,
        finish_reason=sanitize_public_relay_text(finish_reason) if finish_reason is not None else None,
    )


def normalize_stream_runtime_error(exc: BaseException) -> NormalizedRelayStreamingRuntimeError:
    normalized = normalize_live_runtime_error(RuntimeError(_classification_text(exc)))
    return NormalizedRelayStreamingRuntimeError(
        category=normalized.category,
        public_message=_stream_public_message(normalized),
    )


def _classification_text(exc: BaseException) -> str:
    text = str(exc)
    text = text.replace("Authorization: Bearer", "redacted header")
    text = text.replace("authorization: bearer", "redacted header")
    return text


def _stream_public_message(normalized: NormalizedRelayRuntimeError) -> str:
    messages = {
        RelayRuntimeCategory.AUTH_ERROR: "Provider authentication or authorization error during streaming.",
        RelayRuntimeCategory.QUOTA_OR_RATE_LIMIT: "Provider quota or rate-limit error during streaming.",
        RelayRuntimeCategory.TIMEOUT: "Provider timeout before a conclusive streaming result.",
        RelayRuntimeCategory.DISCONNECT: "Provider disconnect before a conclusive streaming result.",
        RelayRuntimeCategory.NETWORK_ERROR: "Provider network error before a conclusive streaming result.",
        RelayRuntimeCategory.UNSUPPORTED_LIVE_TARGET: "Relay streaming live transport is not configured for this execution path.",
        RelayRuntimeCategory.UNKNOWN_RUNTIME_ERROR: "Provider streaming runtime error before a conclusive relay result.",
    }
    return messages[normalized.category]


def run_minimal_streaming_live_check(
    *,
    authorization: RelayLiveAuthorization,
    endpoint: str,
    model: str,
    api_key: str | None,
    pack_summary: RelayPackSummary,
    transport: RelayStreamingTransport | None,
) -> RelayResult:
    endpoint_host = sanitize_to_fqdn(endpoint)
    endpoint_hash = hash_relay_endpoint(endpoint)
    if transport is None:
        normalized = NormalizedRelayStreamingRuntimeError(
            RelayRuntimeCategory.UNSUPPORTED_LIVE_TARGET,
            "Relay streaming live transport is not configured for this execution path.",
        )
        return _inconclusive_streaming_result(
            endpoint_host=endpoint_host,
            endpoint_hash=endpoint_hash,
            model=model,
            pack_summary=pack_summary,
            normalized=normalized,
        )
    try:
        events = list(transport(build_minimal_streaming_payload(model)))
    except BaseException as exc:
        normalized = normalize_stream_runtime_error(exc)
        return _inconclusive_streaming_result(
            endpoint_host=endpoint_host,
            endpoint_hash=endpoint_hash,
            model=model,
            pack_summary=pack_summary,
            normalized=normalized,
        )
    if not events:
        normalized = NormalizedRelayStreamingRuntimeError(
            RelayRuntimeCategory.UNKNOWN_RUNTIME_ERROR,
            "Provider streaming runtime error before a conclusive relay result.",
        )
        return _inconclusive_streaming_result(
            endpoint_host=endpoint_host,
            endpoint_hash=endpoint_hash,
            model=model,
            pack_summary=pack_summary,
            normalized=normalized,
        )

    event_count = len(events)
    content_events = [event for event in events if event.has_content_delta and event.text_length > 0]
    terminal_events = [event for event in events if event.has_finish_reason]
    incompatible_events = [
        event for event in events if event.event_type not in {"chat.completion.chunk", "unknown"}
    ]
    if incompatible_events and not content_events and not terminal_events:
        return _streaming_result(
            endpoint_host=endpoint_host,
            endpoint_hash=endpoint_hash,
            model=model,
            pack_summary=pack_summary,
            verdict=RelayVerdict.FAIL,
            risk_level=RelayRiskLevel.HIGH,
            evidence=[
                RelayEvidence(
                    key="stream_contract_violation",
                    category=RelayRiskCategory.STREAMING_INTEGRITY,
                    status="fail",
                    summary="Streaming profile received an incompatible non-streaming response envelope.",
                    metrics={"event_count": event_count},
                )
            ],
            retest_guidance="Rerun with --profile streaming after confirming the relay endpoint supports SSE streaming.",
        )
    if not content_events:
        normalized = NormalizedRelayStreamingRuntimeError(
            RelayRuntimeCategory.UNKNOWN_RUNTIME_ERROR,
            "Provider streaming runtime error before a conclusive relay result.",
        )
        return _inconclusive_streaming_result(
            endpoint_host=endpoint_host,
            endpoint_hash=endpoint_hash,
            model=model,
            pack_summary=pack_summary,
            normalized=normalized,
        )

    evidence = [
        RelayEvidence(
            key="stream_event_sequence",
            category=RelayRiskCategory.STREAMING_INTEGRITY,
            status="pass",
            summary="Streaming response yielded a bounded public event sequence.",
            metrics={"event_count": event_count},
        ),
        RelayEvidence(
            key="stream_content_delta",
            category=RelayRiskCategory.STREAMING_INTEGRITY,
            status="pass",
            summary="At least one streaming content delta was observed as sanitized metadata.",
            metrics={"content_delta_count": len(content_events)},
        ),
        RelayEvidence(
            key="stream_terminal_finish",
            category=RelayRiskCategory.STREAMING_INTEGRITY,
            status="pass" if terminal_events else "suspicious",
            summary=(
                "A terminal finish signal was observed in the streaming envelope."
                if terminal_events
                else "Streaming content arrived without a terminal finish signal."
            ),
            metrics={
                "terminal_finish_observed": bool(terminal_events),
                "finish_reason": terminal_events[-1].finish_reason if terminal_events else None,
            },
        ),
    ]

    uniform_chunk_size_detected = _has_uniform_chunk_sizes(content_events)
    if uniform_chunk_size_detected:
        evidence.append(
            RelayEvidence(
                key="synthetic_stream_heuristic",
                category=RelayRiskCategory.STREAMING_INTEGRITY,
                status="suspicious",
                summary=(
                    "Uniform stream chunks are a heuristic risk indicator, not proof of provider forgery. "
                    "This finding is based only on static text-length uniformity across public chunk metadata."
                ),
                metrics={
                    "uniform_chunk_size_detected": True,
                    "chunk_count": len(content_events),
                },
            )
        )

    verdict = RelayVerdict.PASS
    risk_level = RelayRiskLevel.LOW
    retest_guidance = "Run deeper profile-specific probes only after their approved milestones."
    if uniform_chunk_size_detected or not terminal_events:
        verdict = RelayVerdict.SUSPICIOUS
        risk_level = RelayRiskLevel.MEDIUM
        retest_guidance = "Rerun streaming checks and compare with schema/privacy milestones when approved."

    return _streaming_result(
        endpoint_host=endpoint_host,
        endpoint_hash=endpoint_hash,
        model=model,
        pack_summary=pack_summary,
        verdict=verdict,
        risk_level=risk_level,
        evidence=evidence,
        retest_guidance=retest_guidance,
    )


def _has_uniform_chunk_sizes(content_events: list[RelayStreamEvent]) -> bool:
    if len(content_events) < 5:
        return False
    lengths = [event.text_length for event in content_events]
    return max(lengths) - min(lengths) <= 1


def _streaming_result(
    *,
    endpoint_host: str,
    endpoint_hash: str,
    model: str,
    pack_summary: RelayPackSummary,
    verdict: RelayVerdict,
    risk_level: RelayRiskLevel,
    evidence: list[RelayEvidence],
    retest_guidance: str,
) -> RelayResult:
    return RelayResult(
        run_id=_streaming_run_id(endpoint_hash, model, verdict.value),
        profile=RelayAuditProfile.STREAMING,
        scenario=verdict,
        mode=RelayAuditMode.LIVE,
        model=sanitize_public_relay_text(model),
        endpoint_host=endpoint_host,
        endpoint_hash=endpoint_hash,
        pack_summary=pack_summary,
        verdict=verdict,
        risk_level=risk_level,
        risk_categories=[RelayRiskCategory.STREAMING_INTEGRITY],
        evidence=evidence,
        retest_guidance=retest_guidance,
    )


def _inconclusive_streaming_result(
    *,
    endpoint_host: str,
    endpoint_hash: str,
    model: str,
    pack_summary: RelayPackSummary,
    normalized: NormalizedRelayStreamingRuntimeError,
) -> RelayResult:
    return RelayResult(
        run_id=_streaming_run_id(endpoint_hash, model, normalized.category.value),
        profile=RelayAuditProfile.STREAMING,
        scenario=RelayVerdict.INCONCLUSIVE,
        mode=RelayAuditMode.LIVE,
        model=sanitize_public_relay_text(model),
        endpoint_host=endpoint_host,
        endpoint_hash=endpoint_hash,
        pack_summary=pack_summary,
        verdict=RelayVerdict.INCONCLUSIVE,
        risk_level=RelayRiskLevel.UNKNOWN,
        risk_categories=[RelayRiskCategory.UPSTREAM_ERROR_LEAKAGE],
        evidence=[
            RelayEvidence(
                key=normalized.category.value,
                category=RelayRiskCategory.UPSTREAM_ERROR_LEAKAGE,
                status="inconclusive",
                summary=normalized.public_message,
            )
        ],
        retest_guidance="Resolve the streaming runtime condition, then rerun with explicit --live.",
        inconclusive_reason=normalized.public_message,
        runtime_category=normalized.category,
    )


def _streaming_run_id(endpoint_hash: str, model: str, suffix: str) -> str:
    material = "|".join(["streaming-live", endpoint_hash, model, suffix])
    return "relay-stream-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
