from __future__ import annotations

from tokenverify.models import EvidenceItem, EvidenceTag, ProbeResult, ProviderEvent, RiskTag, StreamingMetrics


def evaluate_streaming_features(events: list[ProviderEvent]) -> ProbeResult:
    metrics = calculate_streaming_metrics(events)
    evidence: list[EvidenceItem] = []
    sequence_evidence = _native_stream_sequence_evidence(events)
    if sequence_evidence is not None:
        evidence.append(sequence_evidence)
        if sequence_evidence.passed is False:
            return ProbeResult(
                name="streaming_features",
                status="failed",
                evidence=evidence,
                metrics=metrics,
            )
    if metrics.is_synthetic_stream:
        evidence.append(
            EvidenceItem(
                key="synthetic_stream_heuristic",
                weight="weak",
                passed=False,
                message="Stream chunks were uniformly sized and emitted in a short burst; this is a heuristic risk indicator, not proof of provider forgery.",
                tags=[RiskTag.SYNTHETIC_STREAM_SUSPECT.value, RiskTag.STREAM_UNIFORMITY_SUSPECT.value],
            )
        )
    return ProbeResult(
        name="streaming_features",
        status="warning" if metrics.is_synthetic_stream else "passed",
        evidence=evidence,
        metrics=metrics,
    )


def _native_stream_sequence_evidence(events: list[ProviderEvent]) -> EvidenceItem | None:
    event_types = [event.event_type for event in events]
    if not event_types:
        return None
    if any(event_type.startswith("chat.completion") for event_type in event_types):
        return EvidenceItem(
            key="anthropic_stream_event_sequence",
            weight="strong",
            passed=False,
            message="Stream emitted OpenAI-compatible chunk events during a native Anthropic stream probe.",
            details={"event_types": event_types},
            tags=[EvidenceTag.STREAM_EVENT_SEQUENCE_MISMATCH.value],
        )
    has_native_start = event_types[0] == "message_start"
    has_text_delta = "content_block_delta" in event_types
    has_terminal = "message_stop" in event_types or any(
        event.event_type == "message_delta" and event.data.get("stop_reason") for event in events
    )
    if has_native_start and has_text_delta and has_terminal:
        return EvidenceItem(
            key="anthropic_stream_event_sequence",
            weight="strong",
            passed=True,
            message="Stream follows Anthropic native message/content delta event sequence.",
            details={"event_types": event_types},
            tags=[EvidenceTag.STREAM_EVENT_SEQUENCE_MATCH.value],
        )
    return None


def calculate_streaming_metrics(events: list[ProviderEvent]) -> StreamingMetrics:
    if not events:
        return StreamingMetrics(
            ttft_seconds=None,
            total_latency_seconds=0.0,
            chunk_intervals=[],
            chunk_size_distribution=[],
            estimated_tps=None,
            is_synthetic_stream=False,
        )
    start = events[0].timestamp
    text_events = [event for event in events if event.event_type == "content_block_delta" and event.text_length is not None]
    chunk_sizes = [int(event.text_length or 0) for event in text_events]
    ttft = round(text_events[0].timestamp - start, 6) if text_events else None
    intervals = [
        round(text_events[index].timestamp - text_events[index - 1].timestamp, 6)
        for index in range(1, len(text_events))
    ]
    total_latency = round(events[-1].timestamp - start, 6)
    total_chars = sum(chunk_sizes)
    estimated_tps = round(total_chars / total_latency, 6) if total_latency > 0 and total_chars else None
    return StreamingMetrics(
        ttft_seconds=ttft,
        total_latency_seconds=total_latency,
        chunk_intervals=intervals,
        chunk_size_distribution=chunk_sizes,
        estimated_tps=estimated_tps,
        is_synthetic_stream=_looks_synthetic(text_events, chunk_sizes, total_latency),
    )


def _looks_synthetic(text_events: list[ProviderEvent], chunk_sizes: list[int], total_latency: float) -> bool:
    if len(chunk_sizes) < 5:
        return False
    uniform_nontrivial_chunks = len(set(chunk_sizes)) == 1 and chunk_sizes[0] >= 10
    short_burst = total_latency <= 0.05
    return uniform_nontrivial_chunks and short_burst
