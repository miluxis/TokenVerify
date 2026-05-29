from tokenverify.models import EvidenceTag, RiskTag
from tokenverify.tag_taxonomy import TagTaxonomyCategory, classify_tag, tag_taxonomy


def test_tag_taxonomy_groups_stable_authenticity_tags():
    taxonomy = tag_taxonomy()

    assert EvidenceTag.ANTHROPIC_NATIVE_SHAPE_MATCH.value in taxonomy[TagTaxonomyCategory.AUTHENTICITY]
    assert EvidenceTag.CLAUDE_THINKING_CAPABILITY_MATCH.value in taxonomy[TagTaxonomyCategory.AUTHENTICITY]


def test_tag_taxonomy_groups_stable_risk_and_operational_tags():
    taxonomy = tag_taxonomy()

    assert RiskTag.STREAM_UNIFORMITY_SUSPECT.value in taxonomy[TagTaxonomyCategory.RISK]
    assert RiskTag.RELAY_HEADER_SUSPECT.value in taxonomy[TagTaxonomyCategory.RISK]
    assert RiskTag.SELF_RELAY_LOOP_DETECTED.value in taxonomy[TagTaxonomyCategory.OPERATIONAL]


def test_tag_taxonomy_groups_cross_provider_leakage_tags():
    taxonomy = tag_taxonomy()

    assert EvidenceTag.CROSS_PROVIDER_REASONING_LEAKED.value in taxonomy[TagTaxonomyCategory.CROSS_PROVIDER_LEAKAGE]
    assert RiskTag.CROSS_PROVIDER_FINISH_REASON_SUSPECT.value in taxonomy[TagTaxonomyCategory.CROSS_PROVIDER_LEAKAGE]


def test_classify_tag_returns_none_for_unknown_tag():
    assert classify_tag("UNKNOWN_TAG") is None
    assert classify_tag(RiskTag.MODEL_DRIFT_SUSPECT.value) == TagTaxonomyCategory.RISK


def test_openai_tags_are_classified_for_dashboard_taxonomy():
    assert classify_tag(EvidenceTag.OPENAI_CHAT_COMPLETION_SHAPE_MATCH.value) == TagTaxonomyCategory.AUTHENTICITY
    assert classify_tag(EvidenceTag.OPENAI_OFFICIAL_CHANNEL_MISMATCH.value) == TagTaxonomyCategory.RISK
    assert classify_tag(EvidenceTag.CROSS_PROVIDER_MODEL_LEAKED.value) == TagTaxonomyCategory.CROSS_PROVIDER_LEAKAGE


def test_deepseek_tags_are_classified_for_dashboard_taxonomy():
    assert classify_tag(EvidenceTag.DEEPSEEK_CHAT_COMPLETION_SHAPE_MATCH.value) == TagTaxonomyCategory.AUTHENTICITY
    assert classify_tag(EvidenceTag.DEEPSEEK_REASONING_CONTENT_MISSING.value) == TagTaxonomyCategory.AUTHENTICITY
    assert classify_tag(EvidenceTag.DEEPSEEK_OFFICIAL_CHANNEL_MISMATCH.value) == TagTaxonomyCategory.RISK
