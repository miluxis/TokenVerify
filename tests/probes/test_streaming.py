from tokenverify.models import ProviderEvent
from tokenverify.probes.streaming import calculate_streaming_metrics, evaluate_streaming_features


def test_chunk_size_distribution_is_recorded():
    metrics = calculate_streaming_metrics(
        [
            ProviderEvent(timestamp=1.0, event_type="message_start"),
            ProviderEvent(timestamp=1.2, event_type="content_block_delta", text_length=3),
            ProviderEvent(timestamp=1.5, event_type="content_block_delta", text_length=7),
        ]
    )

    assert metrics.ttft_seconds == 0.2
    assert metrics.chunk_size_distribution == [3, 7]
    assert metrics.is_synthetic_stream is False


def test_fixed_size_burst_sets_synthetic_stream_true():
    events = [ProviderEvent(timestamp=1.0, event_type="message_start")]
    events.extend(
        ProviderEvent(timestamp=1.01 + index * 0.001, event_type="content_block_delta", text_length=20)
        for index in range(6)
    )

    metrics = calculate_streaming_metrics(events)

    assert metrics.chunk_size_distribution == [20, 20, 20, 20, 20, 20]
    assert metrics.is_synthetic_stream is True


def test_synthetic_stream_probe_emits_risk_tags():
    events = [
        ProviderEvent(0.0, "message_start"),
        ProviderEvent(0.01, "content_block_delta", text_length=20),
        ProviderEvent(0.02, "content_block_delta", text_length=20),
        ProviderEvent(0.03, "content_block_delta", text_length=20),
        ProviderEvent(0.04, "content_block_delta", text_length=20),
        ProviderEvent(0.05, "content_block_delta", text_length=20),
    ]

    result = evaluate_streaming_features(events)

    assert result.status == "warning"
    assert result.evidence[0].weight == "weak"
    assert result.evidence[0].passed is False
    assert "SYNTHETIC_STREAM_SUSPECT" in result.evidence[0].tags
    assert "STREAM_UNIFORMITY_SUSPECT" in result.evidence[0].tags


def test_native_stream_event_sequence_emits_strong_match_evidence():
    result = evaluate_streaming_features(
        [
            ProviderEvent(0.0, "message_start"),
            ProviderEvent(0.1, "content_block_start"),
            ProviderEvent(0.2, "content_block_delta", text_length=2),
            ProviderEvent(0.3, "content_block_stop"),
            ProviderEvent(0.4, "message_delta", data={"stop_reason": "end_turn"}),
            ProviderEvent(0.5, "message_stop"),
        ]
    )

    assert result.status == "passed"
    assert result.evidence[0].weight == "strong"
    assert result.evidence[0].passed is True
    assert "STREAM_EVENT_SEQUENCE_MATCH" in result.evidence[0].tags


def test_openai_stream_event_in_native_stream_emits_strong_mismatch_evidence():
    result = evaluate_streaming_features(
        [
            ProviderEvent(0.0, "message_start"),
            ProviderEvent(0.1, "chat.completion.chunk", text_length=2),
        ]
    )

    assert result.status == "failed"
    assert result.evidence[0].passed is False
    assert "STREAM_EVENT_SEQUENCE_MISMATCH" in result.evidence[0].tags
