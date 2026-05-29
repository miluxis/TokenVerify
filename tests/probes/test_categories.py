from tokenverify.models import ProbeCategory
from tokenverify.probes.categories import categorize_probe


def test_probe_names_map_to_stable_categories():
    assert categorize_probe("messages_protocol") == ProbeCategory.PROTOCOL
    assert categorize_probe("chat_completions_shape") == ProbeCategory.PROTOCOL
    assert categorize_probe("extended_thinking") == ProbeCategory.CAPABILITY
    assert categorize_probe("thinking_parameter_compatibility") == ProbeCategory.CAPABILITY
    assert categorize_probe("streaming_features") == ProbeCategory.STREAM
    assert categorize_probe("openai_compatible_streaming") == ProbeCategory.STREAM
    assert categorize_probe("messages_error_schema") == ProbeCategory.ERROR
    assert categorize_probe("mixed_provider_consistency") == ProbeCategory.REPEATABILITY
    assert categorize_probe("repeated_run_variance") == ProbeCategory.REPEATABILITY
    assert categorize_probe("channel_risk_observations") == ProbeCategory.CHANNEL_RISK


def test_unknown_probe_category_is_none_not_failure():
    assert categorize_probe("extension_probe") is None


def test_openai_probe_names_map_to_categories():
    assert categorize_probe("openai_chat_completions_shape") == ProbeCategory.PROTOCOL
    assert categorize_probe("openai_reasoning_capability") == ProbeCategory.CAPABILITY
    assert categorize_probe("openai_compatible_streaming") == ProbeCategory.STREAM
    assert categorize_probe("openai_channel_risk") == ProbeCategory.CHANNEL_RISK


def test_deepseek_probe_names_map_to_categories():
    assert categorize_probe("deepseek_chat_completions_shape") == ProbeCategory.PROTOCOL
    assert categorize_probe("deepseek_model_claim_consistency") == ProbeCategory.PROTOCOL
    assert categorize_probe("deepseek_reasoning_content") == ProbeCategory.CAPABILITY
    assert categorize_probe("deepseek_compatible_streaming") == ProbeCategory.STREAM
    assert categorize_probe("deepseek_channel_risk") == ProbeCategory.CHANNEL_RISK
