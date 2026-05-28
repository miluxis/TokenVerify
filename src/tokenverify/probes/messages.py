from __future__ import annotations

from tokenverify.models import EvidenceItem, ProbeResult


def evaluate_messages_response(response: dict) -> ProbeResult:
    content = response.get("content")
    is_native = (
        response.get("type") == "message"
        and response.get("role") == "assistant"
        and isinstance(content, list)
        and all(isinstance(block, dict) and "type" in block for block in content)
    )
    if is_native:
        return ProbeResult(
            name="messages_protocol",
            status="passed",
            evidence=[
                EvidenceItem(
                    key="anthropic_messages_shape",
                    weight="strong",
                    passed=True,
                    message="Response matches Anthropic Messages content block shape.",
                )
            ],
        )
    looks_openai = "choices" in response
    message = (
        "Response resembles an OpenAI-compatible chat completion shape."
        if looks_openai
        else "Response does not match Anthropic Messages content block shape."
    )
    return ProbeResult(
        name="messages_protocol",
        status="failed",
        evidence=[
            EvidenceItem(
                key="anthropic_messages_shape",
                weight="strong",
                passed=False,
                message=message,
            )
        ],
    )
