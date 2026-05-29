from __future__ import annotations

from tokenverify.models import ProbeCategory


_CATEGORY_BY_PROBE_NAME = {
    "messages_protocol": ProbeCategory.PROTOCOL,
    "chat_completions_shape": ProbeCategory.PROTOCOL,
    "claude_claim_consistency": ProbeCategory.PROTOCOL,
    "reasoning_leakage": ProbeCategory.PROTOCOL,
    "extended_thinking": ProbeCategory.CAPABILITY,
    "claude_version_thinking_capability": ProbeCategory.CAPABILITY,
    "thinking_parameter_compatibility": ProbeCategory.CAPABILITY,
    "streaming_features": ProbeCategory.STREAM,
    "openai_compatible_streaming": ProbeCategory.STREAM,
    "messages_error_schema": ProbeCategory.ERROR,
    "mixed_provider_consistency": ProbeCategory.REPEATABILITY,
    "repeated_run_variance": ProbeCategory.REPEATABILITY,
    "channel_risk_observations": ProbeCategory.CHANNEL_RISK,
}


def categorize_probe(name: str) -> ProbeCategory | None:
    return _CATEGORY_BY_PROBE_NAME.get(name)
