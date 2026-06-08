from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from tokenverify.relay_safety import sanitize_public_relay_text


@dataclass(frozen=True)
class RelayResponseEnvelope:
    status_code: int
    response_id_pattern: str | None
    observed_model: str | None
    observed_model_family: str
    response_shape_family: str
    object_type_family: str | None
    finish_reason_family: str | None
    usage_observed: bool
    reasoning_usage_observed: bool
    system_fingerprint_observed: bool
    reasoning_content_observed: bool
    thinking_block_observed: bool
    provider_marker_detected: bool
    provider_marker_family: str | None
    header_marker_families: tuple[str, ...]


def extract_relay_response_envelope(
    *,
    status_code: int,
    body: dict[str, Any] | object,
    headers: dict[str, str] | None,
) -> RelayResponseEnvelope:
    body_dict = body if isinstance(body, dict) else {}
    headers = headers or {}
    response_id = body_dict.get("id")
    observed_model = sanitize_public_relay_text(body_dict.get("model")) if body_dict.get("model") is not None else None
    header_families = _header_marker_families(headers)
    body_marker = _provider_marker_family_from_body(body_dict)
    provider_family = body_marker or (header_families[0] if header_families else None)
    return RelayResponseEnvelope(
        status_code=status_code,
        response_id_pattern=public_response_id_pattern(response_id),
        observed_model=observed_model,
        observed_model_family=observed_model_family(observed_model),
        response_shape_family=response_shape_family(body_dict),
        object_type_family=_object_type_family(body_dict),
        finish_reason_family=_finish_reason_family(body_dict),
        usage_observed=isinstance(body_dict.get("usage"), dict),
        reasoning_usage_observed=_reasoning_usage_observed(body_dict),
        system_fingerprint_observed="system_fingerprint" in body_dict,
        reasoning_content_observed=_contains_key(body_dict, "reasoning_content"),
        thinking_block_observed=_thinking_block_observed(body_dict),
        provider_marker_detected=provider_family is not None,
        provider_marker_family=provider_family,
        header_marker_families=tuple(header_families),
    )


def claimed_model_family(model: str) -> str:
    text = model.strip().lower()
    if "claude" in text or "anthropic" in text:
        return "claude"
    if "deepseek" in text or "r1" in text and "deepseek" in text:
        return "deepseek"
    if "gpt" in text or text.startswith(("o1", "o3", "o4")) or "openai" in text:
        return "openai"
    if "qwen" in text:
        return "qwen_like"
    if "glm" in text:
        return "glm_like"
    if "gemini" in text or "google" in text:
        return "gemini_like"
    return "unknown"


def observed_model_family(value: str | None) -> str:
    if not value:
        return "unknown"
    text = value.strip().lower()
    if "bedrock" in text or text.startswith(("anthropic.", "us.anthropic", "eu.anthropic")):
        return "claude"
    return claimed_model_family(text)


def response_shape_family(body: dict[str, Any]) -> str:
    if body.get("type") == "message" and "content" in body:
        return "anthropic_messages"
    choices = body.get("choices")
    if isinstance(choices, list) and choices and isinstance(choices[0], dict):
        message = choices[0].get("message")
        if isinstance(message, dict) and "reasoning_content" in message:
            return "deepseek_compatible"
        if isinstance(message, dict):
            return "openai_chat_completions"
    return "unknown"


def public_response_id_pattern(value: object) -> str | None:
    text = sanitize_public_relay_text(value).strip()
    if not text or text == "None":
        return None
    if text.startswith("msg_bdrk"):
        return "msg_bdrk..."
    if text.startswith("msg_"):
        return "msg_..."
    if text.startswith("chatcmpl-"):
        return "chatcmpl-..."
    return text[:12] + "..." if len(text) > 12 else text


def family_from_self_report(value: str | None) -> str:
    text = sanitize_public_relay_text(value or "").lower()
    if "qwen" in text:
        return "qwen_like"
    if "glm" in text:
        return "glm_like"
    if "deepseek" in text:
        return "deepseek"
    if "gpt" in text or "openai" in text:
        return "openai"
    if "claude" in text or "anthropic" in text:
        return "claude"
    if "gemini" in text:
        return "gemini_like"
    return "unknown"


def _header_marker_families(headers: dict[str, str]) -> list[str]:
    families: list[str] = []
    for key in headers:
        lowered = key.lower()
        family = None
        if lowered.startswith("x-amzn") or "bedrock" in lowered:
            family = "bedrock"
        elif lowered.startswith("x-ms") or "azure" in lowered:
            family = "azure"
        elif lowered.startswith("x-openrouter"):
            family = "openrouter"
        elif lowered.startswith(("x-upstream", "x-relay")):
            family = "proxy"
        elif lowered in {"server", "via"}:
            value = headers.get(key, "").lower()
            if "nginx" in value:
                family = "nginx"
            elif "cloudflare" in value:
                family = "cloudflare"
        if family and family not in families:
            families.append(family)
    return families


def _provider_marker_family_from_body(body: dict[str, Any]) -> str | None:
    text = sanitize_public_relay_text(_safe_marker_view(body)).lower()
    if "msg_bdrk" in text or "bedrock" in text or "x-amzn" in text:
        return "bedrock"
    if "azure" in text or "x-ms-" in text:
        return "azure"
    if "openrouter" in text:
        return "openrouter"
    if "one-api" in text or "oneapi" in text:
        return "oneapi"
    if "new-api" in text or "newapi" in text:
        return "newapi"
    return None


def _safe_marker_view(body: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": body.get("id"),
        "model": body.get("model"),
        "object": body.get("object"),
        "type": body.get("type"),
        "error": _error_marker(body.get("error")),
    }


def _error_marker(value: object) -> object:
    if isinstance(value, dict):
        return {key: value.get(key) for key in ("type", "code", "param")}
    return None


def _object_type_family(body: dict[str, Any]) -> str | None:
    value = body.get("object") or body.get("type")
    return sanitize_public_relay_text(value) if value is not None else None


def _finish_reason_family(body: dict[str, Any]) -> str | None:
    if "stop_reason" in body:
        return sanitize_public_relay_text(body.get("stop_reason"))
    choices = body.get("choices")
    if isinstance(choices, list) and choices and isinstance(choices[0], dict):
        choice = choices[0]
        value = choice.get("finish_reason")
        return sanitize_public_relay_text(value) if value is not None else None
    return None


def _reasoning_usage_observed(body: dict[str, Any]) -> bool:
    usage = body.get("usage")
    if not isinstance(usage, dict):
        return False
    details = usage.get("output_tokens_details") or usage.get("completion_tokens_details")
    return isinstance(details, dict) and bool(details.get("reasoning_tokens"))


def _contains_key(value: object, key: str) -> bool:
    if isinstance(value, dict):
        return key in value or any(_contains_key(item, key) for item in value.values())
    if isinstance(value, list):
        return any(_contains_key(item, key) for item in value)
    return False


def _thinking_block_observed(body: dict[str, Any]) -> bool:
    content = body.get("content")
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict) and sanitize_public_relay_text(item.get("type")).lower() in {
                "thinking",
                "redacted_thinking",
            }:
                return True
    return _contains_key(body, "thinking") or _contains_key(body, "signature_delta")
