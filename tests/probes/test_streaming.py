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
