from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class OpenAIModelFamily(str, Enum):
    GPT_5 = "gpt_5"
    GPT_4_1 = "gpt_4_1"
    GPT_4O = "gpt_4o"
    O_SERIES = "o_series"
    UNKNOWN_OPENAI = "unknown_openai"
    NON_OPENAI = "non_openai"


@dataclass(frozen=True)
class OpenAIModelCapability:
    model: str
    family: OpenAIModelFamily
    is_known: bool
    supports_reasoning_effort: bool | None
    confidence: str
    confidence_reason: str


def lookup_openai_model_capability(model: str) -> OpenAIModelCapability:
    normalized = _normalize_model(model)
    if normalized.startswith("gpt-5"):
        return OpenAIModelCapability(
            model,
            OpenAIModelFamily.GPT_5,
            True,
            True,
            "high",
            "Matched known OpenAI GPT-5 family.",
        )
    if normalized.startswith("gpt-4-1"):
        return OpenAIModelCapability(
            model,
            OpenAIModelFamily.GPT_4_1,
            True,
            False,
            "high",
            "Matched known OpenAI GPT-4.1 family.",
        )
    if normalized.startswith("gpt-4o"):
        return OpenAIModelCapability(
            model,
            OpenAIModelFamily.GPT_4O,
            True,
            False,
            "high",
            "Matched known OpenAI GPT-4o family.",
        )
    if normalized.startswith(("o1", "o3", "o4")):
        return OpenAIModelCapability(
            model,
            OpenAIModelFamily.O_SERIES,
            True,
            True,
            "medium",
            "Matched o-series reasoning family with conservative Chat Completions assumptions.",
        )
    if normalized.startswith("gpt-"):
        return OpenAIModelCapability(
            model,
            OpenAIModelFamily.UNKNOWN_OPENAI,
            False,
            None,
            "low",
            "Unknown OpenAI-looking model.",
        )
    return OpenAIModelCapability(
        model,
        OpenAIModelFamily.NON_OPENAI,
        False,
        None,
        "high",
        "Model name does not look like an OpenAI model family.",
    )


def _normalize_model(model: str) -> str:
    normalized = model.strip().lower()
    if "/" in normalized:
        normalized = normalized.rsplit("/", 1)[-1]
    return normalized.replace(".", "-")
