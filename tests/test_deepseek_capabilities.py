from tokenverify.deepseek_capabilities import DeepSeekModelFamily, lookup_deepseek_model_capability


def test_deepseek_r1_family_requires_reasoning_content():
    capability = lookup_deepseek_model_capability("deepseek-r1")

    assert capability.family == DeepSeekModelFamily.R1
    assert capability.is_known is True
    assert capability.expects_reasoning_content is True
    assert capability.confidence == "high"


def test_deepseek_reasoner_alias_maps_to_r1():
    capability = lookup_deepseek_model_capability("deepseek-reasoner")

    assert capability.family == DeepSeekModelFamily.R1
    assert capability.expects_reasoning_content is True


def test_deepseek_chat_family_does_not_require_reasoning_content():
    capability = lookup_deepseek_model_capability("deepseek-chat")

    assert capability.family == DeepSeekModelFamily.CHAT
    assert capability.is_known is True
    assert capability.expects_reasoning_content is False


def test_unknown_deepseek_looking_model_is_neutral():
    capability = lookup_deepseek_model_capability("deepseek-future-9")

    assert capability.family == DeepSeekModelFamily.UNKNOWN_DEEPSEEK
    assert capability.is_known is False
    assert capability.expects_reasoning_content is None


def test_non_deepseek_model_is_classified_as_non_deepseek():
    capability = lookup_deepseek_model_capability("gpt-4o")

    assert capability.family == DeepSeekModelFamily.NON_DEEPSEEK
    assert capability.is_known is False
