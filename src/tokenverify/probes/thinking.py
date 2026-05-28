from __future__ import annotations

from tokenverify.model_capabilities import lookup_model_capability
from tokenverify.models import EvidenceItem, ProbeResult
from tokenverify.providers.anthropic import build_messages_payload


class ProbeConstructionError(ValueError):
    pass


def build_thinking_payload(
    model: str,
    budget_tokens: int = 1024,
    max_tokens: int = 2048,
) -> dict:
    if budget_tokens >= max_tokens:
        raise ProbeConstructionError("thinking budget_tokens must be lower than max_tokens")
    return build_messages_payload(
        model=model,
        messages=[{"role": "user", "content": "Answer with one short sentence."}],
        max_tokens=max_tokens,
        stream=True,
        thinking={"type": "enabled", "budget_tokens": budget_tokens},
    )


def evaluate_thinking_outcome(
    model: str,
    response: dict | None,
    error_message: str | None = None,
) -> ProbeResult:
    capability = lookup_model_capability(model)
    thinking_expected = capability.supports_extended_thinking is True
    if error_message and _is_operational_error(error_message):
        return ProbeResult(
            name="extended_thinking",
            status="error",
            evidence=[
                EvidenceItem(
                    key="extended_thinking_operational_error",
                    weight="strong",
                    passed=None,
                    message=f"Extended Thinking probe hit an operational error, not authenticity evidence: {error_message}",
                )
            ],
            errors=[error_message],
        )
    if error_message and thinking_expected:
        return ProbeResult(
            name="extended_thinking",
            status="failed",
            evidence=[
                EvidenceItem(
                    key="extended_thinking_expected",
                    weight="strong",
                    passed=False,
                    message=f"Model is expected to support Extended Thinking but endpoint rejected it: {error_message}",
                )
            ],
            errors=[error_message],
        )
    if response and _contains_thinking_block(response):
        return ProbeResult(
            name="extended_thinking",
            status="passed",
            evidence=[
                EvidenceItem(
                    key="extended_thinking_expected",
                    weight="strong",
                    passed=True,
                    message="Endpoint returned a thinking content block for a thinking-capable model.",
                )
            ],
        )
    return ProbeResult(
        name="extended_thinking",
        status="skipped" if not thinking_expected else "warning",
        evidence=[
            EvidenceItem(
                key="extended_thinking_expected",
                weight="strong",
                passed=None if not thinking_expected else False,
                message="Extended Thinking is not expected for this model." if not thinking_expected else "No thinking evidence was observed.",
            )
        ],
    )


def _contains_thinking_block(response: dict) -> bool:
    content = response.get("content")
    return isinstance(content, list) and any(block.get("type") == "thinking" for block in content if isinstance(block, dict))


def _is_operational_error(message: str) -> bool:
    lower = message.lower()
    markers = (
        "rate limit",
        "quota",
        "too many requests",
        "authentication",
        "authorization",
        "invalid x-api-key",
        "service unavailable",
        "try again later",
    )
    return any(marker in lower for marker in markers)
