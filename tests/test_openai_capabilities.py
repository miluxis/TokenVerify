from tokenverify.openai_capabilities import OpenAIModelFamily, lookup_openai_model_capability


def test_gpt_5_family_is_reasoning_capable():
    capability = lookup_openai_model_capability("gpt-5.1")

    assert capability.family == OpenAIModelFamily.GPT_5
    assert capability.is_known is True
    assert capability.supports_reasoning_effort is True
    assert capability.confidence == "high"


def test_gpt_4_family_is_known_without_reasoning_effort():
    capability = lookup_openai_model_capability("openai/gpt-4.1-2025-04-14")

    assert capability.family == OpenAIModelFamily.GPT_4_1
    assert capability.is_known is True
    assert capability.supports_reasoning_effort is False


def test_o_series_is_reasoning_capable_but_conservative():
    capability = lookup_openai_model_capability("o3-mini")

    assert capability.family == OpenAIModelFamily.O_SERIES
    assert capability.supports_reasoning_effort is True
    assert "conservative" in capability.confidence_reason


def test_unknown_openai_looking_model_is_neutral():
    capability = lookup_openai_model_capability("gpt-unknown-future")

    assert capability.family == OpenAIModelFamily.UNKNOWN_OPENAI
    assert capability.is_known is False
    assert capability.supports_reasoning_effort is None
    assert capability.confidence == "low"
