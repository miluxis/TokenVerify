from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ThinkingMode(str, Enum):
    MANUAL_BUDGET = "manual_budget"
    ADAPTIVE = "adaptive"
    NONE = "none"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ModelCapability:
    model: str
    is_known: bool
    supports_extended_thinking: bool | None
    preferred_thinking_mode: ThinkingMode
    confidence: str
    confidence_reason: str


_CAPABILITIES = {
    "claude-sonnet-4-5": ModelCapability(
        model="claude-sonnet-4-5",
        is_known=True,
        supports_extended_thinking=True,
        preferred_thinking_mode=ThinkingMode.MANUAL_BUDGET,
        confidence="high",
        confidence_reason="Matched known Claude capability table.",
    ),
    "claude-haiku-4-5": ModelCapability(
        model="claude-haiku-4-5",
        is_known=True,
        supports_extended_thinking=True,
        preferred_thinking_mode=ThinkingMode.MANUAL_BUDGET,
        confidence="high",
        confidence_reason="Matched known Claude capability table.",
    ),
    "claude-opus-4-1": ModelCapability(
        model="claude-opus-4-1",
        is_known=True,
        supports_extended_thinking=True,
        preferred_thinking_mode=ThinkingMode.MANUAL_BUDGET,
        confidence="high",
        confidence_reason="Matched known Claude capability table.",
    ),
    "claude-3-5-sonnet": ModelCapability(
        model="claude-3-5-sonnet",
        is_known=True,
        supports_extended_thinking=False,
        preferred_thinking_mode=ThinkingMode.NONE,
        confidence="high",
        confidence_reason="Matched known Claude capability table.",
    ),
    "claude-3-haiku": ModelCapability(
        model="claude-3-haiku",
        is_known=True,
        supports_extended_thinking=False,
        preferred_thinking_mode=ThinkingMode.NONE,
        confidence="high",
        confidence_reason="Matched known Claude capability table.",
    ),
}


def lookup_model_capability(model: str) -> ModelCapability:
    raw_normalized = model.strip().lower()
    if raw_normalized.endswith("-thinking") or "-thinking-" in raw_normalized:
        return ModelCapability(
            model=model,
            is_known=False,
            supports_extended_thinking=True,
            preferred_thinking_mode=ThinkingMode.MANUAL_BUDGET,
            confidence="medium",
            confidence_reason="Inferred thinking support from model name suffix.",
        )

    normalized = _normalize_model_name(model)
    return _CAPABILITIES.get(
        normalized,
        ModelCapability(
            model=model,
            is_known=False,
            supports_extended_thinking=None,
            preferred_thinking_mode=ThinkingMode.UNKNOWN,
            confidence="low",
            confidence_reason="unknown model; capability class cannot be inferred confidently.",
        ),
    )


def _normalize_model_name(model: str) -> str:
    normalized = model.strip().lower()
    if "/" in normalized:
        normalized = normalized.rsplit("/", 1)[-1]
    normalized = normalized.replace(".", "-")
    for known_model in _CAPABILITIES:
        if normalized == known_model or normalized.startswith(f"{known_model}-"):
            return known_model
    return normalized
