from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class DeepSeekModelFamily(str, Enum):
    R1 = "r1"
    CHAT = "chat"
    UNKNOWN_DEEPSEEK = "unknown_deepseek"
    NON_DEEPSEEK = "non_deepseek"


@dataclass(frozen=True)
class DeepSeekModelCapability:
    model: str
    family: DeepSeekModelFamily
    is_known: bool
    expects_reasoning_content: bool | None
    confidence: str
    confidence_reason: str


def lookup_deepseek_model_capability(model: str) -> DeepSeekModelCapability:
    normalized = _normalize_model(model)
    if normalized.startswith("deepseek-r1") or normalized == "deepseek-reasoner":
        return DeepSeekModelCapability(
            model,
            DeepSeekModelFamily.R1,
            True,
            True,
            "high",
            "Matched known DeepSeek R1/reasoner family.",
        )
    if normalized.startswith("deepseek-chat") or normalized.startswith("deepseek-v3"):
        return DeepSeekModelCapability(
            model,
            DeepSeekModelFamily.CHAT,
            True,
            False,
            "high",
            "Matched known DeepSeek chat/V3 family.",
        )
    if normalized.startswith("deepseek-"):
        return DeepSeekModelCapability(
            model,
            DeepSeekModelFamily.UNKNOWN_DEEPSEEK,
            False,
            None,
            "low",
            "Unknown DeepSeek-looking model.",
        )
    return DeepSeekModelCapability(
        model,
        DeepSeekModelFamily.NON_DEEPSEEK,
        False,
        None,
        "high",
        "Model name does not look like a DeepSeek model family.",
    )


def _normalize_model(model: str) -> str:
    normalized = model.strip().lower()
    if "/" in normalized:
        normalized = normalized.rsplit("/", 1)[-1]
    return normalized.replace("_", "-")
