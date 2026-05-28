from __future__ import annotations

from tokenverify.models import EvidenceItem, ProbeResult, ProviderEvent, RiskTag, StreamingMetrics


def evaluate_streaming_features(events: list[ProviderEvent]) -> ProbeResult:
    metrics = calculate_streaming_metrics(events)
    evidence: list[EvidenceItem] = []
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
