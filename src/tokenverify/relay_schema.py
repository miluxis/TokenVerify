from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Protocol

from tokenverify.relay_live import NormalizedRelayRuntimeError, RelayLiveTransportResponse, normalize_live_runtime_error
from tokenverify.relay_models import (
    RelayAuditMode,
    RelayAuditProfile,
    RelayEvidence,
    RelayPackSummary,
    RelayResult,
    RelayRiskCategory,
    RelayRiskLevel,
    RelayRuntimeCategory,
    RelayVerdict,
)
from tokenverify.relay_safety import RelayLiveAuthorization, hash_relay_endpoint, sanitize_public_relay_text, sanitize_to_fqdn

SCHEMA_TOOL_NAME = "tv_schema_echo"
SCHEMA_REQUIRED_KEYS = ["item_count", "status"]


class RelaySchemaTransport(Protocol):
    def __call__(self, payload: dict[str, Any]) -> RelayLiveTransportResponse:
        ...


@dataclass(frozen=True)
class RelaySchemaObservation:
    tool_call_observed: bool
    tool_name_preserved: bool
    arguments_json_parseable: bool
    required_key_count: int
    required_keys_present_count: int
    unexpected_key_count: int
    item_count_type_match: bool
    status_type_match: bool
    enum_values_match: bool
    natural_language_fallback_observed: bool
    hybrid_content_observed: bool
    finish_reason: str | None = None


class RelaySchemaRuntimeError(RuntimeError):
    def __init__(self, category: RelayRuntimeCategory, public_message: str):
        self.category = category
        self.public_message = sanitize_public_relay_text(public_message)
        super().__init__(self.public_message)


@dataclass(frozen=True)
class NormalizedRelaySchemaRuntimeError:
    category: RelayRuntimeCategory
    public_message: str

    def raise_for_public_handling(self) -> None:
        raise RelaySchemaRuntimeError(self.category, self.public_message) from None


def build_minimal_schema_payload(model: str) -> dict[str, Any]:
    return {
        "model": sanitize_public_relay_text(model),
        "messages": [
            {"role": "user", "content": 'Call the provided tool with item_count=2 and status="ok".'}
        ],
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": SCHEMA_TOOL_NAME,
                    "description": "Return a small public audit object.",
                    "parameters": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": list(SCHEMA_REQUIRED_KEYS),
                        "properties": {
                            "item_count": {"type": "integer", "enum": [2]},
                            "status": {"type": "string", "enum": ["ok"]},
                        },
                    },
                },
            }
        ],
        "tool_choice": {"type": "function", "function": {"name": SCHEMA_TOOL_NAME}},
        "max_tokens": 64,
        "stream": False,
    }


def normalize_schema_response(response: RelayLiveTransportResponse) -> RelaySchemaObservation:
    body = response.body if isinstance(response.body, dict) else {}
    choices = body.get("choices")
    choice = choices[0] if isinstance(choices, list) and choices and isinstance(choices[0], dict) else {}
    message = choice.get("message") if isinstance(choice, dict) else {}
    message = message if isinstance(message, dict) else {}
    finish_reason = choice.get("finish_reason")
    content = message.get("content")
    tool_calls = message.get("tool_calls")
    first_tool = tool_calls[0] if isinstance(tool_calls, list) and tool_calls and isinstance(tool_calls[0], dict) else {}
    function = first_tool.get("function") if isinstance(first_tool, dict) else {}
    function = function if isinstance(function, dict) else {}
    tool_name = function.get("name")
    arguments_text = function.get("arguments")
    parsed_arguments: dict[str, Any] | None = None
    arguments_json_parseable = False
    if isinstance(arguments_text, str):
        try:
            value = json.loads(arguments_text)
        except json.JSONDecodeError:
            value = None
        if isinstance(value, dict):
            parsed_arguments = value
            arguments_json_parseable = True
    required_present = [
        key for key in SCHEMA_REQUIRED_KEYS if isinstance(parsed_arguments, dict) and key in parsed_arguments
    ]
    unexpected_keys = [
        key for key in (parsed_arguments or {}).keys() if key not in set(SCHEMA_REQUIRED_KEYS)
    ]
    item_count_type_match = isinstance((parsed_arguments or {}).get("item_count"), int)
    status_type_match = isinstance((parsed_arguments or {}).get("status"), str)
    enum_values_match = (parsed_arguments or {}).get("item_count") == 2 and (parsed_arguments or {}).get("status") == "ok"
    return RelaySchemaObservation(
        tool_call_observed=bool(first_tool),
        tool_name_preserved=tool_name == SCHEMA_TOOL_NAME,
        arguments_json_parseable=arguments_json_parseable,
        required_key_count=len(SCHEMA_REQUIRED_KEYS),
        required_keys_present_count=len(required_present),
        unexpected_key_count=len(unexpected_keys),
        item_count_type_match=item_count_type_match,
        status_type_match=status_type_match,
        enum_values_match=enum_values_match,
        natural_language_fallback_observed=bool(content) and not bool(first_tool),
        hybrid_content_observed=bool(content) and bool(first_tool),
        finish_reason=_public_finish_reason(finish_reason),
    )


def normalize_schema_runtime_error(exc: BaseException) -> NormalizedRelaySchemaRuntimeError:
    normalized = normalize_live_runtime_error(RuntimeError(_classification_text(exc)))
    return NormalizedRelaySchemaRuntimeError(
        category=normalized.category,
        public_message=_schema_public_message(normalized),
    )


def _public_finish_reason(value: object) -> str | None:
    if value is None:
        return None
    text = sanitize_public_relay_text(value)
    if text == "tool_calls":
        return "tool-call-finish"
    return text


def _classification_text(exc: BaseException) -> str:
    if isinstance(exc, json.JSONDecodeError):
        return "malformed schema response json"
    text = str(exc)
    text = text.replace("Authorization: Bearer", "redacted header")
    text = text.replace("authorization: bearer", "redacted header")
    return text


def _schema_public_message(normalized: NormalizedRelayRuntimeError) -> str:
    messages = {
        RelayRuntimeCategory.AUTH_ERROR: "Provider authentication or authorization error during schema check.",
        RelayRuntimeCategory.QUOTA_OR_RATE_LIMIT: "Provider quota or rate-limit error during schema check.",
        RelayRuntimeCategory.TIMEOUT: "Provider timeout before a conclusive schema result.",
        RelayRuntimeCategory.DISCONNECT: "Provider disconnect before a conclusive schema result.",
        RelayRuntimeCategory.NETWORK_ERROR: "Provider network error before a conclusive schema result.",
        RelayRuntimeCategory.UNSUPPORTED_LIVE_TARGET: "Relay schema live transport is not configured for this execution path.",
        RelayRuntimeCategory.UNKNOWN_RUNTIME_ERROR: "Provider schema runtime error before a conclusive relay result.",
    }
    return messages[normalized.category]


def run_minimal_schema_live_check(
    *,
    authorization: RelayLiveAuthorization,
    endpoint: str,
    model: str,
    api_key: str | None,
    pack_summary: RelayPackSummary,
    transport: RelaySchemaTransport | None,
) -> RelayResult:
    endpoint_host = sanitize_to_fqdn(endpoint)
    endpoint_hash = hash_relay_endpoint(endpoint)
    if transport is None:
        normalized = NormalizedRelaySchemaRuntimeError(
            RelayRuntimeCategory.UNSUPPORTED_LIVE_TARGET,
            "Relay schema live transport is not configured for this execution path.",
        )
        return _inconclusive_schema_result(
            endpoint_host=endpoint_host,
            endpoint_hash=endpoint_hash,
            model=model,
            pack_summary=pack_summary,
            normalized=normalized,
        )
    try:
        response = transport(build_minimal_schema_payload(model))
    except BaseException as exc:
        normalized = normalize_schema_runtime_error(exc)
        return _inconclusive_schema_result(
            endpoint_host=endpoint_host,
            endpoint_hash=endpoint_hash,
            model=model,
            pack_summary=pack_summary,
            normalized=normalized,
        )
    status_error = _schema_runtime_error_for_status(response.status_code)
    if status_error is not None:
        return _inconclusive_schema_result(
            endpoint_host=endpoint_host,
            endpoint_hash=endpoint_hash,
            model=model,
            pack_summary=pack_summary,
            normalized=status_error,
        )
    observation = normalize_schema_response(response)
    if not observation.tool_call_observed and not observation.natural_language_fallback_observed:
        normalized = NormalizedRelaySchemaRuntimeError(
            RelayRuntimeCategory.UNKNOWN_RUNTIME_ERROR,
            "Provider schema runtime error before a conclusive relay result.",
        )
        return _inconclusive_schema_result(
            endpoint_host=endpoint_host,
            endpoint_hash=endpoint_hash,
            model=model,
            pack_summary=pack_summary,
            normalized=normalized,
        )
    verdict, risk_level, evidence = _schema_verdict_and_evidence(observation)
    return _schema_result(
        endpoint_host=endpoint_host,
        endpoint_hash=endpoint_hash,
        model=model,
        pack_summary=pack_summary,
        verdict=verdict,
        risk_level=risk_level,
        evidence=evidence,
    )


def _schema_verdict_and_evidence(
    observation: RelaySchemaObservation,
) -> tuple[RelayVerdict, RelayRiskLevel, list[RelayEvidence]]:
    evidence = [
        RelayEvidence(
            key="schema_tool_envelope",
            category=RelayRiskCategory.SCHEMA_TOOL_REWRITE,
            status="pass" if observation.tool_call_observed else "fail",
            summary=(
                "A forced public tool-call envelope was observed."
                if observation.tool_call_observed
                else "The relay returned natural-language content instead of the forced public tool call."
            ),
            metrics={
                "tool_call_observed": observation.tool_call_observed,
                "natural_language_fallback_observed": observation.natural_language_fallback_observed,
                "hybrid_content_observed": observation.hybrid_content_observed,
                "finish_reason": observation.finish_reason,
            },
        )
    ]
    if not observation.tool_call_observed:
        evidence.append(
            RelayEvidence(
                key="schema_contract_violation",
                category=RelayRiskCategory.SCHEMA_TOOL_REWRITE,
                status="fail",
                summary="The forced public schema tool contract was not honored.",
                metrics={"natural_language_fallback_observed": observation.natural_language_fallback_observed},
            )
        )
        return RelayVerdict.FAIL, RelayRiskLevel.HIGH, evidence
    evidence.extend(
        [
            RelayEvidence(
                key="schema_tool_name_preservation",
                category=RelayRiskCategory.SCHEMA_TOOL_REWRITE,
                status="pass" if observation.tool_name_preserved else "fail",
                summary=(
                    "The forced public tool name was preserved."
                    if observation.tool_name_preserved
                    else "The forced public tool name was rewritten or missing."
                ),
                metrics={"tool_name_preserved": observation.tool_name_preserved},
            ),
            RelayEvidence(
                key="schema_arguments_json",
                category=RelayRiskCategory.SCHEMA_TOOL_REWRITE,
                status="pass" if observation.arguments_json_parseable else "fail",
                summary=(
                    "Tool arguments were parseable as JSON metadata."
                    if observation.arguments_json_parseable
                    else "Tool arguments were not parseable as JSON metadata."
                ),
                metrics={"arguments_json_parseable": observation.arguments_json_parseable},
            ),
            RelayEvidence(
                key="schema_required_keys",
                category=RelayRiskCategory.SCHEMA_TOOL_REWRITE,
                status="pass" if observation.required_keys_present_count == observation.required_key_count else "fail",
                summary="Required public schema keys were checked using safe counts.",
                metrics={
                    "required_key_count": observation.required_key_count,
                    "required_keys_present_count": observation.required_keys_present_count,
                },
            ),
            RelayEvidence(
                key="schema_type_enum_match",
                category=RelayRiskCategory.SCHEMA_TOOL_REWRITE,
                status=(
                    "pass"
                    if observation.item_count_type_match
                    and observation.status_type_match
                    and observation.enum_values_match
                    else "fail"
                ),
                summary="Public schema type and enum compatibility were checked using safe booleans.",
                metrics={
                    "item_count_type_match": observation.item_count_type_match,
                    "status_type_match": observation.status_type_match,
                    "enum_values_match": observation.enum_values_match,
                },
            ),
        ]
    )
    if observation.unexpected_key_count:
        evidence.append(
            RelayEvidence(
                key="schema_extra_keys",
                category=RelayRiskCategory.SCHEMA_TOOL_REWRITE,
                status="suspicious",
                summary="The relay returned extra tool argument keys beyond the public schema.",
                metrics={"unexpected_key_count": observation.unexpected_key_count},
            )
        )
    hard_fail = (
        not observation.tool_name_preserved
        or not observation.arguments_json_parseable
        or observation.required_keys_present_count != observation.required_key_count
        or not observation.item_count_type_match
        or not observation.status_type_match
        or not observation.enum_values_match
    )
    if hard_fail:
        return RelayVerdict.FAIL, RelayRiskLevel.HIGH, evidence
    if observation.unexpected_key_count or observation.hybrid_content_observed:
        return RelayVerdict.SUSPICIOUS, RelayRiskLevel.MEDIUM, evidence
    return RelayVerdict.PASS, RelayRiskLevel.LOW, evidence


def _schema_result(
    *,
    endpoint_host: str,
    endpoint_hash: str,
    model: str,
    pack_summary: RelayPackSummary,
    verdict: RelayVerdict,
    risk_level: RelayRiskLevel,
    evidence: list[RelayEvidence],
) -> RelayResult:
    return RelayResult(
        run_id=_schema_run_id(endpoint_hash, model, verdict.value),
        profile=RelayAuditProfile.SCHEMA,
        scenario=verdict,
        mode=RelayAuditMode.LIVE,
        model=sanitize_public_relay_text(model),
        endpoint_host=endpoint_host,
        endpoint_hash=endpoint_hash,
        pack_summary=pack_summary,
        verdict=verdict,
        risk_level=risk_level,
        risk_categories=[RelayRiskCategory.SCHEMA_TOOL_REWRITE],
        evidence=evidence,
        retest_guidance="Rerun schema checks and compare with privacy/full milestones when approved.",
    )


def _inconclusive_schema_result(
    *,
    endpoint_host: str,
    endpoint_hash: str,
    model: str,
    pack_summary: RelayPackSummary,
    normalized: NormalizedRelaySchemaRuntimeError,
) -> RelayResult:
    return RelayResult(
        run_id=_schema_run_id(endpoint_hash, model, normalized.category.value),
        profile=RelayAuditProfile.SCHEMA,
        scenario=RelayVerdict.INCONCLUSIVE,
        mode=RelayAuditMode.LIVE,
        model=sanitize_public_relay_text(model),
        endpoint_host=endpoint_host,
        endpoint_hash=endpoint_hash,
        pack_summary=pack_summary,
        verdict=RelayVerdict.INCONCLUSIVE,
        risk_level=RelayRiskLevel.UNKNOWN,
        risk_categories=[RelayRiskCategory.UPSTREAM_ERROR_LEAKAGE],
        evidence=[
            RelayEvidence(
                key=normalized.category.value,
                category=RelayRiskCategory.UPSTREAM_ERROR_LEAKAGE,
                status="inconclusive",
                summary=normalized.public_message,
            )
        ],
        retest_guidance="Resolve the schema runtime condition, then rerun with explicit --live.",
        inconclusive_reason=normalized.public_message,
        runtime_category=normalized.category,
    )


def _schema_runtime_error_for_status(status_code: int) -> NormalizedRelaySchemaRuntimeError | None:
    if status_code in {401, 403}:
        return NormalizedRelaySchemaRuntimeError(
            RelayRuntimeCategory.AUTH_ERROR,
            "Provider authentication or authorization error during schema check.",
        )
    if status_code == 429:
        return NormalizedRelaySchemaRuntimeError(
            RelayRuntimeCategory.QUOTA_OR_RATE_LIMIT,
            "Provider quota or rate-limit error during schema check.",
        )
    if status_code == 504:
        return NormalizedRelaySchemaRuntimeError(
            RelayRuntimeCategory.TIMEOUT,
            "Provider timeout before a conclusive schema result.",
        )
    if status_code in {502, 503}:
        return NormalizedRelaySchemaRuntimeError(
            RelayRuntimeCategory.NETWORK_ERROR,
            "Provider network error before a conclusive schema result.",
        )
    if status_code != 200:
        return NormalizedRelaySchemaRuntimeError(
            RelayRuntimeCategory.UNKNOWN_RUNTIME_ERROR,
            "Provider schema runtime error before a conclusive relay result.",
        )
    return None


def _schema_run_id(endpoint_hash: str, model: str, suffix: str) -> str:
    material = "|".join(["schema-live", endpoint_hash, model, suffix])
    return "relay-schema-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
