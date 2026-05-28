from tokenverify.models import ProviderEvent
from tokenverify.probes.streaming import calculate_streaming_metrics


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
