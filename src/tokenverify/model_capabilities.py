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


_CAPABILITIES = {
    "claude-sonnet-4-5": ModelCapability(
        model="claude-sonnet-4-5",
        is_known=True,
        supports_extended_thinking=True,
        preferred_thinking_mode=ThinkingMode.MANUAL_BUDGET,
    ),
    "claude-opus-4-1": ModelCapability(
        model="claude-opus-4-1",
        is_known=True,
        supports_extended_thinking=True,
        preferred_thinking_mode=ThinkingMode.MANUAL_BUDGET,
    ),
    "claude-3-5-sonnet": ModelCapability(
        model="claude-3-5-sonnet",
        is_known=True,
        supports_extended_thinking=False,
        preferred_thinking_mode=ThinkingMode.NONE,
    ),
}


def lookup_model_capability(model: str) -> ModelCapability:
    normalized = model.strip().lower()
    if normalized.endswith("-thinking") or "-thinking-" in normalized:
        return ModelCapability(
            model=model,
            is_known=False,
            supports_extended_thinking=True,
            preferred_thinking_mode=ThinkingMode.MANUAL_BUDGET,
        )
    return _CAPABILITIES.get(
        normalized,
        ModelCapability(
            model=model,
            is_known=False,
            supports_extended_thinking=None,
            preferred_thinking_mode=ThinkingMode.UNKNOWN,
        ),
    )
