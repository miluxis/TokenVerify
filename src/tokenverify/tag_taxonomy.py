from __future__ import annotations

from enum import Enum

from tokenverify.models import EvidenceTag, RiskTag


class TagTaxonomyCategory(str, Enum):
    AUTHENTICITY = "authenticity"
    RISK = "risk"
    OPERATIONAL = "operational"
    CROSS_PROVIDER_LEAKAGE = "cross_provider_leakage"


def tag_taxonomy() -> dict[TagTaxonomyCategory, tuple[str, ...]]:
    cross_provider = (
        EvidenceTag.CROSS_PROVIDER_MODEL_LEAKED.value,
        EvidenceTag.CROSS_PROVIDER_REASONING_LEAKED.value,
        RiskTag.CROSS_PROVIDER_FINISH_REASON_SUSPECT.value,
    )
    evidence_risk = (
        EvidenceTag.OPENAI_OFFICIAL_CHANNEL_MISMATCH.value,
        EvidenceTag.DEEPSEEK_OFFICIAL_CHANNEL_MISMATCH.value,
    )
    operational = (
        RiskTag.SELF_RELAY_LOOP_DETECTED.value,
    )
    risk = (
        *evidence_risk,
        *tuple(
            tag.value
            for tag in RiskTag
            if tag.value not in {*cross_provider, *operational}
        ),
    )
    authenticity = tuple(
        tag.value
        for tag in EvidenceTag
        if tag.value not in {*cross_provider, *evidence_risk}
    )
    return {
        TagTaxonomyCategory.AUTHENTICITY: authenticity,
        TagTaxonomyCategory.RISK: risk,
        TagTaxonomyCategory.OPERATIONAL: operational,
        TagTaxonomyCategory.CROSS_PROVIDER_LEAKAGE: cross_provider,
    }


def classify_tag(tag: str) -> TagTaxonomyCategory | None:
    for category, tags in tag_taxonomy().items():
        if tag in tags:
            return category
    return None
