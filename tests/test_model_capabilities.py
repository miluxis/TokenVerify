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
