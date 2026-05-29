from __future__ import annotations

from tokenverify.model_capabilities import lookup_model_capability
from tokenverify.models import EvidenceItem, EvidenceTag, ProbeResult
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
    if response and _contains_cross_provider_reasoning(response):
        return ProbeResult(
            name="extended_thinking",
            status="failed",
            evidence=[
                EvidenceItem(
                    key="cross_provider_reasoning_leaked",
                    weight="strong",
                    passed=False,
                    message="Response exposed provider-specific reasoning content that contradicts the claimed Claude boundary.",
                    tags=[EvidenceTag.CROSS_PROVIDER_REASONING_LEAKED.value],
                )
            ],
        )
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
                    tags=[EvidenceTag.EXTENDED_THINKING_REJECTED.value],
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
                    tags=[EvidenceTag.EXTENDED_THINKING_MATCH.value],
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
                tags=[] if not thinking_expected else [EvidenceTag.EXTENDED_THINKING_MISSING.value],
            )
        ],
    )


def evaluate_thinking_parameter_compatibility(
    model: str,
    accepted_parameters: list[str],
    rejected_parameters: list[str],
) -> ProbeResult:
    capability = lookup_model_capability(model)
    thinking_expected = capability.supports_extended_thinking is True
    if not thinking_expected:
        return ProbeResult(
            name="thinking_parameter_compatibility",
            status="skipped",
            evidence=[
                EvidenceItem(
                    key="thinking_parameter_compatibility",
                    weight="strong",
                    passed=None,
                    message=f"Thinking parameters are not expected for this capability tier ({capability.confidence} confidence: {capability.confidence_reason}).",
                )
            ],
        )

    accepted = any(parameter.startswith("thinking") for parameter in accepted_parameters)
    rejected = any(parameter.startswith("thinking") for parameter in rejected_parameters)
    passed = accepted and not rejected
    return ProbeResult(
        name="thinking_parameter_compatibility",
        status="passed" if passed else "failed",
        evidence=[
            EvidenceItem(
                key="thinking_parameter_compatibility",
                weight="strong",
                passed=passed,
                message=(
                    f"Thinking parameter behavior matches the expected Claude capability tier "
                    f"({capability.confidence} confidence: {capability.confidence_reason})."
                    if passed
                    else f"Thinking parameter behavior contradicts the expected Claude capability tier ({capability.confidence} confidence)."
                ),
                details={"accepted_parameters": accepted_parameters, "rejected_parameters": rejected_parameters},
                tags=[
                    EvidenceTag.CLAUDE_THINKING_CAPABILITY_MATCH.value
                    if passed
                    else EvidenceTag.CLAUDE_THINKING_CAPABILITY_MISMATCH.value
                ],
            )
        ],
    )


def _contains_thinking_block(response: dict) -> bool:
    content = response.get("content")
    return isinstance(content, list) and any(block.get("type") == "thinking" for block in content if isinstance(block, dict))


def _contains_cross_provider_reasoning(response: dict) -> bool:
    choices = response.get("choices")
    if isinstance(choices, list):
        for choice in choices:
            if not isinstance(choice, dict):
                continue
            delta = choice.get("delta")
            message = choice.get("message")
            if isinstance(delta, dict) and "reasoning_content" in delta:
                return True
            if isinstance(message, dict) and "reasoning_content" in message:
                return True
    return False


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
