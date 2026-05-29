from tokenverify.model_capabilities import ThinkingMode, lookup_model_capability


def test_known_thinking_model_requires_thinking_probe():
    capability = lookup_model_capability("claude-sonnet-4-5")

    assert capability.is_known is True
    assert capability.supports_extended_thinking is True
    assert capability.preferred_thinking_mode == ThinkingMode.MANUAL_BUDGET


def test_unknown_model_is_not_forced_to_low_trust():
    capability = lookup_model_capability("claude-future-unknown")

    assert capability.is_known is False
    assert capability.supports_extended_thinking is None
    assert capability.preferred_thinking_mode == ThinkingMode.UNKNOWN


def test_relay_model_name_with_thinking_suffix_expects_thinking_probe():
    capability = lookup_model_capability("claude-haiku-4-5-20251001-thinking")

    assert capability.is_known is False
    assert capability.supports_extended_thinking is True
    assert capability.preferred_thinking_mode == ThinkingMode.MANUAL_BUDGET


def test_dot_version_aliases_map_to_known_thinking_models():
    capability = lookup_model_capability("anthropic/claude-sonnet-4.5-20250929")

    assert capability.is_known is True
    assert capability.model == "claude-sonnet-4-5"
    assert capability.supports_extended_thinking is True
    assert capability.preferred_thinking_mode == ThinkingMode.MANUAL_BUDGET


def test_non_claude_model_is_known_not_claude():
    capability = lookup_model_capability("openai/gpt-4o")

    assert capability.is_known is False
    assert capability.supports_extended_thinking is None
    assert capability.preferred_thinking_mode == ThinkingMode.UNKNOWN


def test_expanded_claude_capability_table_covers_current_and_legacy_families():
    haiku_45 = lookup_model_capability("claude-haiku-4.5")
    sonnet_35 = lookup_model_capability("claude-3.5-sonnet")
    haiku_3 = lookup_model_capability("claude-3-haiku")

    assert haiku_45.is_known is True
    assert haiku_45.supports_extended_thinking is True
    assert sonnet_35.is_known is True
    assert sonnet_35.supports_extended_thinking is False
    assert haiku_3.is_known is True
    assert haiku_3.supports_extended_thinking is False


def test_capability_lookup_includes_confidence_language():
    known = lookup_model_capability("claude-sonnet-4.5")
    unknown = lookup_model_capability("claude-future-unknown")

    assert known.confidence == "high"
    assert "known Claude capability table" in known.confidence_reason
    assert unknown.confidence == "low"
    assert "unknown model" in unknown.confidence_reason
