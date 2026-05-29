from __future__ import annotations

from tokenverify.model_capabilities import lookup_model_capability
from tokenverify.models import EvidenceItem, EvidenceTag, ProbeResult, ProviderEvent, RiskTag
from tokenverify.probes.streaming import calculate_streaming_metrics


def evaluate_chat_completions_response(response: dict) -> ProbeResult:
    choices = response.get("choices")
    is_openai_shape = isinstance(choices, list) and choices and isinstance(choices[0], dict) and "message" in choices[0]
    if is_openai_shape:
        return ProbeResult(
            "chat_completions_shape",
            "passed",
            [
                EvidenceItem(
                    "openai_compatible_chat_shape",
                    "strong",
                    True,
                    "Response matches OpenAI-compatible Chat Completions shape.",
                    tags=[EvidenceTag.OPENAI_COMPATIBLE_SHAPE_MATCH.value],
                )
            ],
        )
    if response.get("type") == "message" and "content" in response:
        return ProbeResult(
            "chat_completions_shape",
            "failed",
            [
                EvidenceItem(
                    "openai_compatible_chat_shape",
                    "strong",
                    False,
                    "Response is Anthropic native Messages shape despite an OpenAI-compatible claim.",
                    tags=[EvidenceTag.ANTHROPIC_NATIVE_SHAPE_DETECTED.value],
                )
            ],
        )
    return ProbeResult(
        "chat_completions_shape",
        "failed",
        [
            EvidenceItem(
                "openai_compatible_chat_shape",
                "strong",
                False,
                "Response does not match OpenAI-compatible Chat Completions shape.",
                tags=[EvidenceTag.OPENAI_COMPATIBLE_SHAPE_MISMATCH.value],
            )
        ],
    )


def evaluate_claude_claim_consistency(claimed_model: str, response: dict) -> ProbeResult:
    observed = str(response.get("model") or "")
    if not observed:
        return ProbeResult(
            "claude_claim_consistency",
            "skipped",
            [EvidenceItem("claude_model_claim", "strong", None, "No response model field was observed.")],
        )
    normalized_claim = _normalize_model_name(claimed_model)
    normalized_observed = _normalize_model_name(observed)
    passed = normalized_claim in normalized_observed or normalized_observed in normalized_claim
    return ProbeResult(
        "claude_claim_consistency",
        "passed" if passed else "failed",
        [
            EvidenceItem(
                "claude_model_claim",
                "strong",
                passed,
                f"Observed response model `{observed}` {'matches' if passed else 'contradicts'} claimed model `{claimed_model}`.",
                tags=[
                    EvidenceTag.CLAUDE_MODEL_CLAIM_MATCH.value
                    if passed
                    else EvidenceTag.CLAUDE_MODEL_CLAIM_MISMATCH.value
                ],
            )
        ],
    )


def evaluate_mixed_provider_consistency(responses: list[dict]) -> ProbeResult:
    observed_models = [str(response.get("model") or "") for response in responses if response.get("model")]
    provider_families = {_provider_family(model) for model in observed_models}
    provider_families.discard("unknown")
    if len(provider_families) > 1:
        return ProbeResult(
            "mixed_provider_consistency",
            "failed",
            [
                EvidenceItem(
                    "mixed_provider_inconsistency",
                    "strong",
                    False,
                    "Conditional mixed-provider inconsistency: repeated observations exposed different provider families. This is not guaranteed black-box identification.",
                    details={"observed_models": observed_models, "provider_families": sorted(provider_families)},
                    tags=[EvidenceTag.MIXED_PROVIDER_INCONSISTENCY_DETECTED.value],
                )
            ],
        )
    return ProbeResult(
        "mixed_provider_consistency",
        "passed" if observed_models else "skipped",
        [
            EvidenceItem(
                "mixed_provider_inconsistency",
                "strong",
                True if observed_models else None,
                "No cross-provider model family inconsistency was observed.",
                details={"observed_models": observed_models},
            )
        ],
    )


def evaluate_claude_version_and_thinking_capability(
    claimed_model: str,
    response: dict,
    thinking_error: str | None = None,
) -> ProbeResult:
    capability = lookup_model_capability(claimed_model)
    evidence: list[EvidenceItem] = []

    thinking_expected = capability.supports_extended_thinking is True
    if thinking_error and thinking_expected:
        evidence.append(
            EvidenceItem(
                "claude_thinking_capability",
                "strong",
                False,
                f"Claimed model is expected to support thinking, but the endpoint rejected the probe: {thinking_error}",
                tags=[EvidenceTag.CLAUDE_THINKING_CAPABILITY_MISMATCH.value],
            )
        )
    elif thinking_expected and _contains_dedicated_reasoning_field(response):
        evidence.append(
            EvidenceItem(
                "claude_thinking_capability",
                "strong",
                True,
                "Claimed model is thinking-capable and response exposed a dedicated reasoning field.",
                tags=[EvidenceTag.CLAUDE_THINKING_CAPABILITY_MATCH.value],
            )
        )

    leaked_version = _extract_leaked_version(response)
    if leaked_version:
        evidence.append(
            EvidenceItem(
                "claude_version_field",
                "strong",
                True,
                f"Response exposed an API-leaked Claude model/version field: `{leaked_version}`.",
                details={"leaked_version": leaked_version},
                tags=[EvidenceTag.CLAUDE_VERSION_FIELD_LEAKED.value],
            )
        )

    if not evidence:
        return ProbeResult(
            "claude_version_thinking_capability",
            "skipped",
            [
                EvidenceItem(
                    "claude_version_thinking_capability",
                    "strong",
                    None,
                    "No API-leaked version or dedicated thinking capability evidence was observed.",
                )
            ],
        )
    status = "failed" if any(item.passed is False for item in evidence if item.weight == "strong") else "passed"
    return ProbeResult("claude_version_thinking_capability", status, evidence)


def evaluate_reasoning_leakage(response: dict) -> ProbeResult:
    if _contains_reasoning_content(response):
        return ProbeResult(
            "reasoning_leakage",
            "failed",
            [
                EvidenceItem(
                    "cross_provider_reasoning_leaked",
                    "strong",
                    False,
                    "Response exposed provider-specific reasoning_content in an OpenAI-compatible Claude claim.",
                    tags=[EvidenceTag.CROSS_PROVIDER_REASONING_LEAKED.value],
                )
            ],
        )
    if _contains_fake_thinking_text(response):
        return ProbeResult(
            "reasoning_leakage",
            "warning",
            [
                EvidenceItem(
                    "synthetic_thinking_text",
                    "weak",
                    False,
                    "Thinking-like text was mixed into normal content with scripted prefixes.",
                    tags=[RiskTag.SYNTHETIC_THINKING_SUSPECT.value],
                )
            ],
        )
    return ProbeResult("reasoning_leakage", "passed", [])


def evaluate_channel_risk_observations(
    response_headers: dict[str, str] | None = None,
    error_message: str | None = None,
    region_claim: str | None = None,
    latency_samples: list[float] | None = None,
    observed_models: list[str] | None = None,
) -> ProbeResult:
    headers = {key.lower(): value for key, value in (response_headers or {}).items()}
    evidence: list[EvidenceItem] = []
    marker_text = " ".join([*headers.keys(), *headers.values(), error_message or ""]).lower()

    if "bedrock" in marker_text or "x-amzn" in marker_text or "amazon" in marker_text:
        evidence.append(
            EvidenceItem(
                "aws_bedrock_marker",
                "weak",
                False,
                "Headers or error text exposed AWS Bedrock-style routing markers.",
                tags=[RiskTag.HOSTED_BY_AWS.value],
            )
        )
    if "azure" in marker_text or "foundry" in marker_text or "x-ms-" in marker_text:
        evidence.append(
            EvidenceItem(
                "azure_foundry_marker",
                "weak",
                False,
                "Headers or error text exposed Azure or Foundry-style routing markers.",
                tags=[RiskTag.HOSTED_BY_AZURE.value],
            )
        )

    relay_header_keys = [
        key
        for key in headers
        if key.startswith("x-openrouter") or key.startswith("x-relay") or key.startswith("x-upstream")
    ]
    if relay_header_keys:
        evidence.append(
            EvidenceItem(
                "relay_header_markers",
                "weak",
                False,
                "Response headers exposed relay or upstream routing markers.",
                details={"header_keys": relay_header_keys, "request_id": _request_id(headers)},
                tags=[RiskTag.RELAY_HEADER_SUSPECT.value],
            )
        )

    if error_message and _looks_like_relay_rate_limit(error_message):
        evidence.append(
            EvidenceItem(
                "relay_rate_limit_behavior",
                "weak",
                False,
                "Rate-limit error text suggests gateway, upstream, or account-pool mediation.",
                details={"error_message": error_message},
                tags=[RiskTag.RATE_LIMIT_RELAY_SUSPECT.value],
            )
        )

    if _region_latency_inconsistent(region_claim, headers, latency_samples or []):
        evidence.append(
            EvidenceItem(
                "region_latency_consistency",
                "weak",
                False,
                "Observed region markers or latency spread are inconsistent with the claimed region.",
                details={"region_claim": region_claim, "latency_samples": latency_samples or []},
                tags=[RiskTag.REGION_LATENCY_INCONSISTENT.value],
            )
        )

    normalized_models = {_normalize_model_name(model) for model in observed_models or [] if model}
    if len(normalized_models) > 1:
        evidence.append(
            EvidenceItem(
                "model_drift",
                "weak",
                False,
                "Repeated observations reported different Claude model families.",
                details={"observed_models": observed_models or []},
                tags=[RiskTag.MODEL_DRIFT_SUSPECT.value],
            )
        )

    if not evidence:
        return ProbeResult("channel_risk_observations", "passed", [])
    return ProbeResult("channel_risk_observations", "warning", evidence)


def evaluate_repeated_run_variance(
    latency_samples: list[float],
    observed_models: list[str],
    min_samples: int = 5,
) -> ProbeResult:
    if len(latency_samples) < min_samples:
        return ProbeResult(
            "repeated_run_variance",
            "skipped",
            [
                EvidenceItem(
                    "repeated_run_variance_debounce",
                    "weak",
                    None,
                    f"Repeated-run variance debounce: {len(latency_samples)} samples is below the {min_samples}-sample threshold.",
                )
            ],
        )

    evidence: list[EvidenceItem] = []
    if max(latency_samples) - min(latency_samples) > 2.0:
        evidence.append(
            EvidenceItem(
                "ttft_variance",
                "weak",
                False,
                "Repeated-run latency samples show high variance after debounce.",
                details={"latency_samples": latency_samples},
                tags=[RiskTag.TTFT_VARIANCE_HIGH.value],
            )
        )
    normalized_models = {_normalize_model_name(model) for model in observed_models if model}
    if len(normalized_models) > 1:
        evidence.append(
            EvidenceItem(
                "model_drift",
                "weak",
                False,
                "Repeated-run model observations drifted across Claude model families after debounce.",
                details={"observed_models": observed_models},
                tags=[RiskTag.MODEL_DRIFT_SUSPECT.value],
            )
        )
    if not evidence:
        return ProbeResult("repeated_run_variance", "passed", [])
    return ProbeResult("repeated_run_variance", "warning", evidence)


def evaluate_openai_streaming_features(events: list[ProviderEvent]) -> ProbeResult:
    metrics = calculate_streaming_metrics(events)
    finish_reasons = [event.data.get("finish_reason") for event in events]
    terminal = next((reason for reason in reversed(finish_reasons) if reason), None)
    evidence: list[EvidenceItem] = []
    if terminal is None and events:
        evidence.append(
            EvidenceItem(
                "openai_stream_sequence",
                "strong",
                False,
                "Stream ended without a terminal finish_reason.",
                tags=[EvidenceTag.STREAM_EVENT_SEQUENCE_MISMATCH.value],
            )
        )
        return ProbeResult("openai_compatible_streaming", "failed", evidence, metrics=metrics)
    if terminal == "content_filter":
        evidence.append(
            EvidenceItem(
                "openai_stream_finish_reason",
                "weak",
                False,
                "Stream ended with content_filter finish_reason for a claimed Claude relay.",
                tags=[RiskTag.CROSS_PROVIDER_FINISH_REASON_SUSPECT.value],
            )
        )
        return ProbeResult("openai_compatible_streaming", "warning", evidence, metrics=metrics)
    if events:
        evidence.append(
            EvidenceItem(
                "openai_stream_sequence",
                "strong",
                True,
                "OpenAI-compatible stream included a terminal finish_reason.",
                tags=[EvidenceTag.OPENAI_STREAM_SEQUENCE_MATCH.value],
            )
        )
    if metrics.is_synthetic_stream:
        evidence.append(
            EvidenceItem(
                "synthetic_stream_heuristic",
                "weak",
                False,
                "Stream chunks were uniformly sized and emitted in a short burst.",
                tags=[RiskTag.SYNTHETIC_STREAM_SUSPECT.value, RiskTag.STREAM_UNIFORMITY_SUSPECT.value],
            )
        )
    return ProbeResult("openai_compatible_streaming", "warning" if metrics.is_synthetic_stream else "passed", evidence, metrics=metrics)


def _contains_reasoning_content(response: dict) -> bool:
    for choice in _choices(response):
        for key in ("delta", "message"):
            value = choice.get(key)
            if isinstance(value, dict) and "reasoning_content" in value:
                return True
    return False


def _contains_dedicated_reasoning_field(response: dict) -> bool:
    for choice in _choices(response):
        for key in ("delta", "message"):
            value = choice.get(key)
            if isinstance(value, dict) and ("reasoning" in value or "thinking" in value):
                return True
    return False


def _contains_fake_thinking_text(response: dict) -> bool:
    markers = (
        "thinking process:",
        "thinking process",
        "### thinking process",
        "[thinking]",
        "{thinking}",
        "analyzing...",
        "1. analyzing",
    )
    for choice in _choices(response):
        message = choice.get("message")
        delta = choice.get("delta")
        content = None
        if isinstance(message, dict):
            content = message.get("content")
        if content is None and isinstance(delta, dict):
            content = delta.get("content")
        normalized = content.strip().lower() if isinstance(content, str) else ""
        if normalized and any(marker in normalized for marker in markers):
            return True
    return False


def _choices(response: dict) -> list[dict]:
    choices = response.get("choices")
    return [choice for choice in choices if isinstance(choice, dict)] if isinstance(choices, list) else []


def _normalize_model_name(model: str) -> str:
    normalized = model.strip().lower()
    if "/" in normalized:
        normalized = normalized.rsplit("/", 1)[-1]
    return normalized.replace(".", "-")


def _provider_family(model: str) -> str:
    normalized = model.strip().lower()
    if "claude" in normalized or "anthropic" in normalized:
        return "anthropic"
    if "deepseek" in normalized:
        return "deepseek"
    if "gpt" in normalized or "openai" in normalized:
        return "openai"
    if "gemini" in normalized or "google" in normalized:
        return "google"
    if "qwen" in normalized:
        return "qwen"
    return "unknown"


def _extract_leaked_version(response: dict) -> str | None:
    for key in ("system_fingerprint", "model", "model_version", "upstream_model"):
        value = response.get(key)
        if isinstance(value, str) and "claude" in value.lower() and any(char.isdigit() for char in value):
            return value
    return None


def _request_id(headers: dict[str, str]) -> str | None:
    for key in ("x-request-id", "request-id", "cf-ray"):
        if key in headers:
            return headers[key]
    return None


def _looks_like_relay_rate_limit(message: str) -> bool:
    normalized = message.lower()
    return "429" in normalized and any(marker in normalized for marker in ("upstream", "account pool", "gateway", "relay"))


def _region_latency_inconsistent(
    region_claim: str | None,
    headers: dict[str, str],
    latency_samples: list[float],
) -> bool:
    claim = (region_claim or "").lower()
    cf_ray = headers.get("cf-ray", "").lower()
    if claim.startswith("us-east") and any(marker in cf_ray for marker in ("sjc", "lax", "sea")):
        return True
    if len(latency_samples) >= 3 and max(latency_samples) - min(latency_samples) > 2.0:
        return True
    return False
