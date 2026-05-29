from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from tokenverify.audit_plan import UnsupportedAuditTarget, build_audit_plan
from tokenverify.models import AuditResult, EvidenceItem, ProbeResult, ProviderEvent, RiskTag
from tokenverify.providers.anthropic import AnthropicMessagesClient, build_messages_payload
from tokenverify.providers.openai_compatible import (
    OpenAICompatibleChatClient,
    SelfRelayLoopError,
    build_chat_completions_payload,
)
from tokenverify.probes.messages import evaluate_messages_response
from tokenverify.probes.openai import (
    evaluate_openai_channel,
    evaluate_openai_chat_completion_response,
    evaluate_openai_model_claim,
    evaluate_openai_reasoning_capability,
    evaluate_openai_streaming_features as evaluate_openai_model_streaming_features,
)
from tokenverify.probes.openai_compatible import (
    evaluate_channel_risk_observations,
    evaluate_chat_completions_response,
    evaluate_claude_claim_consistency,
    evaluate_claude_version_and_thinking_capability,
    evaluate_mixed_provider_consistency,
    evaluate_openai_streaming_features,
    evaluate_reasoning_leakage,
    evaluate_repeated_run_variance,
)
from tokenverify.probes.streaming import evaluate_streaming_features
from tokenverify.probes.thinking import build_thinking_payload, evaluate_thinking_outcome
from tokenverify.scoring import score_probe_results


@dataclass(frozen=True)
class AuditObservations:
    messages_response: dict | None = None
    messages_error: str | None = None
    thinking_response: dict | None = None
    thinking_error: str | None = None
    stream_events: list[ProviderEvent] = field(default_factory=list)
    repeated_messages_responses: list[dict] = field(default_factory=list)
    response_headers: dict[str, str] = field(default_factory=dict)
    latency_samples: list[float] = field(default_factory=list)
    accepted_parameters: list[str] = field(default_factory=list)
    rejected_parameters: list[str] = field(default_factory=list)
    reasoning_tokens: int | None = None
    is_trivial_prompt: bool = False


def run_audit(runtime_config, observations: AuditObservations | None = None) -> AuditResult:
    claim = runtime_config.endpoint.claim
    if claim:
        try:
            plan = build_audit_plan(claim)
        except UnsupportedAuditTarget as exc:
            probe_results = [ProbeResult("unsupported_audit_target", "error", errors=[str(exc)])]
            rating, breakdown, verdict = score_probe_results(probe_results)
            return _result(runtime_config, probe_results, rating, breakdown, verdict)
        if plan.path == "anthropic_openai_compatible":
            return _run_openai_compatible_claude_audit(runtime_config, observations)
        if plan.path == "openai_openai_compatible":
            return _run_openai_compatible_audit(runtime_config, observations)

    observations = observations or _collect_live_observations(runtime_config)
    probe_results: list[ProbeResult] = []
    if observations.thinking_error == "API key is required for live audit.":
        probe_results.append(ProbeResult("messages_protocol", "error", errors=[observations.thinking_error]))
        rating, breakdown, verdict = score_probe_results(probe_results)
        return _result(runtime_config, probe_results, rating, breakdown, verdict)
    if observations.messages_response is not None:
        probe_results.append(evaluate_messages_response(observations.messages_response))
    if observations.messages_error is not None:
        probe_results.append(ProbeResult("messages_protocol", "error", errors=[observations.messages_error]))
    if observations.thinking_response is not None or observations.thinking_error is not None:
        probe_results.append(
            evaluate_thinking_outcome(
                model=runtime_config.endpoint.model,
                response=observations.thinking_response,
                error_message=observations.thinking_error,
            )
        )
    if observations.stream_events:
        probe_results.append(evaluate_streaming_features(observations.stream_events))
        _write_raw_logs(runtime_config.raw_log_path, observations.stream_events, runtime_config.raw_logs_enabled)

    rating, breakdown, verdict = score_probe_results(probe_results)
    return _result(runtime_config, probe_results, rating, breakdown, verdict)


def _collect_live_observations(runtime_config) -> AuditObservations:
    if not runtime_config.endpoint.api_key:
        return AuditObservations(thinking_error="API key is required for live audit.")
    client = AnthropicMessagesClient(
        base_url=runtime_config.endpoint.base_url,
        api_key=runtime_config.endpoint.api_key,
        headers=runtime_config.endpoint.headers,
    )
    messages_payload = build_messages_payload(
        model=runtime_config.endpoint.model,
        messages=[{"role": "user", "content": "Reply with exactly: ok"}],
        max_tokens=64,
        stream=False,
    )
    messages_response = None
    messages_error = None
    thinking_response = None
    thinking_error = None
    stream_events: list[ProviderEvent] = []
    try:
        messages_response = client.create_message(messages_payload)
    except Exception as exc:  # Provider errors are normalized into inconclusive/negative evidence downstream.
        messages_error = str(exc)
    try:
        thinking_response = client.create_message(build_thinking_payload(runtime_config.endpoint.model))
    except Exception as exc:
        thinking_error = str(exc)
    try:
        stream_events = client.stream_message_events(messages_payload)
    except Exception:
        stream_events = []
    return AuditObservations(
        messages_response=messages_response,
        messages_error=messages_error,
        thinking_response=thinking_response,
        thinking_error=thinking_error,
        stream_events=stream_events,
    )


def _run_openai_compatible_claude_audit(runtime_config, observations: AuditObservations | None) -> AuditResult:
    observations = observations or _collect_openai_compatible_observations(runtime_config)
    probe_results: list[ProbeResult] = []

    if observations.messages_error and "self-relay-loop" in observations.messages_error.lower():
        probe_results.append(
            ProbeResult(
                "self_relay_loop_safety_gate",
                "error",
                [
                    EvidenceItem(
                        "self_relay_loop_detected",
                        "weak",
                        False,
                        observations.messages_error,
                        tags=[RiskTag.SELF_RELAY_LOOP_DETECTED.value],
                    )
                ],
                errors=[observations.messages_error],
            )
        )
        rating, breakdown, verdict = score_probe_results(probe_results)
        return _result(runtime_config, probe_results, rating, breakdown, verdict)

    if observations.messages_response is not None:
        probe_results.append(evaluate_chat_completions_response(observations.messages_response))
        probe_results.append(
            evaluate_claude_claim_consistency(runtime_config.endpoint.model, observations.messages_response)
        )
        repeated_responses = [observations.messages_response, *observations.repeated_messages_responses]
        if len(repeated_responses) > 1:
            probe_results.append(evaluate_mixed_provider_consistency(repeated_responses))
        probe_results.append(
            evaluate_claude_version_and_thinking_capability(
                claimed_model=runtime_config.endpoint.model,
                response=observations.messages_response,
                thinking_error=observations.thinking_error,
            )
        )
        probe_results.append(evaluate_reasoning_leakage(observations.messages_response))
    if observations.messages_error is not None:
        probe_results.append(ProbeResult("chat_completions_shape", "error", errors=[observations.messages_error]))
    if observations.response_headers or observations.latency_samples or observations.repeated_messages_responses:
        observed_models = [
            str(response.get("model"))
            for response in ([observations.messages_response] if observations.messages_response else [])
            + observations.repeated_messages_responses
            if response.get("model")
        ]
        probe_results.append(
            evaluate_channel_risk_observations(
                response_headers=observations.response_headers,
                error_message=observations.messages_error,
                region_claim=runtime_config.endpoint.claim.region_claim if runtime_config.endpoint.claim else None,
                latency_samples=observations.latency_samples,
                observed_models=observed_models,
            )
        )
        if observations.latency_samples:
            probe_results.append(
                evaluate_repeated_run_variance(
                    latency_samples=observations.latency_samples,
                    observed_models=observed_models,
                )
            )
    if observations.stream_events:
        probe_results.append(evaluate_openai_streaming_features(observations.stream_events))
        _write_raw_logs(runtime_config.raw_log_path, observations.stream_events, runtime_config.raw_logs_enabled)

    rating, breakdown, verdict = score_probe_results(probe_results)
    return _result(runtime_config, probe_results, rating, breakdown, verdict)


def _collect_openai_compatible_observations(runtime_config) -> AuditObservations:
    if not runtime_config.endpoint.api_key:
        return AuditObservations(messages_error="API key is required for live audit.")

    client = OpenAICompatibleChatClient(
        base_url=runtime_config.endpoint.base_url,
        api_key=runtime_config.endpoint.api_key,
        headers=runtime_config.endpoint.headers,
    )
    payload = build_chat_completions_payload(
        model=runtime_config.endpoint.model,
        messages=[{"role": "user", "content": "Reply with exactly: ok"}],
        max_tokens=64,
        stream=False,
    )
    messages_response = None
    messages_error = None
    stream_events: list[ProviderEvent] = []
    try:
        messages_response = client.create_chat_completion(payload)
    except SelfRelayLoopError as exc:
        messages_error = f"self-relay-loop: {exc}"
    except Exception as exc:  # Provider errors are normalized into inconclusive/negative evidence downstream.
        messages_error = str(exc)

    try:
        stream_payload = {**payload, "stream": True}
        stream_events = client.stream_chat_completion_events(stream_payload)
    except SelfRelayLoopError as exc:
        messages_error = f"self-relay-loop: {exc}"
    except Exception:
        stream_events = []

    return AuditObservations(
        messages_response=messages_response,
        messages_error=messages_error,
        stream_events=stream_events,
    )


def _run_openai_compatible_audit(runtime_config, observations: AuditObservations | None) -> AuditResult:
    observations = observations or _collect_openai_compatible_observations(runtime_config)
    probe_results: list[ProbeResult] = []

    if observations.messages_response is not None:
        probe_results.append(evaluate_openai_chat_completion_response(observations.messages_response))
        probe_results.append(evaluate_openai_model_claim(runtime_config.endpoint.model, observations.messages_response))
        if observations.accepted_parameters or observations.rejected_parameters:
            probe_results.append(
                evaluate_openai_reasoning_capability(
                    runtime_config.endpoint.model,
                    accepted_parameters=observations.accepted_parameters,
                    rejected_parameters=observations.rejected_parameters,
                    reasoning_tokens=observations.reasoning_tokens,
                    is_trivial_prompt=observations.is_trivial_prompt,
                )
            )
        else:
            probe_results.append(
                ProbeResult(
                    "openai_reasoning_capability",
                    "skipped",
                    [
                        EvidenceItem(
                            "openai_reasoning_capability",
                            "strong",
                            None,
                            "No reasoning_effort parameter acceptance observation was available.",
                        )
                    ],
                )
            )
    if observations.messages_error is not None:
        probe_results.append(ProbeResult("openai_chat_completions_shape", "error", errors=[observations.messages_error]))
    probe_results.append(
        evaluate_openai_channel(
            base_url=runtime_config.endpoint.base_url,
            channel_claim=runtime_config.endpoint.claim.channel_claim if runtime_config.endpoint.claim else "unknown",
            response_headers=observations.response_headers,
            error_message=observations.messages_error,
        )
    )
    if observations.stream_events:
        probe_results.append(evaluate_openai_model_streaming_features(observations.stream_events))
        _write_raw_logs(runtime_config.raw_log_path, observations.stream_events, runtime_config.raw_logs_enabled)

    rating, breakdown, verdict = score_probe_results(probe_results)
    return _result(runtime_config, probe_results, rating, breakdown, verdict)


def _result(runtime_config, probe_results: list[ProbeResult], rating, breakdown: dict[str, int], verdict) -> AuditResult:
    claim = runtime_config.endpoint.claim
    return AuditResult(
        target_summary={
            "base_url_host": _host(runtime_config.endpoint.base_url),
            "model": runtime_config.endpoint.model,
            "endpoint": runtime_config.endpoint.name,
            "claimed_provider": claim.provider if claim else "anthropic",
            "claimed_api_shape": claim.api_shape if claim else "native",
            "claimed_model": claim.model if claim else runtime_config.endpoint.model,
            "claimed_channel": claim.channel_claim if claim else "unknown",
            "claimed_region": claim.region_claim if claim else None,
        },
        probe_results=probe_results,
        rating=rating,
        score_breakdown=breakdown,
        verdict=verdict,
        claim=claim,
        report_warnings=["raw logging enabled"] if runtime_config.raw_logs_enabled else [],
        raw_log_path=runtime_config.raw_log_path if runtime_config.raw_logs_enabled else None,
        redacted_config=runtime_config.redacted_config,
        extension_probe_results=[
            ProbeResult(name=str(probe.get("name", "extension_probe")), status="observation_only")
            for probe in runtime_config.extension_probes
        ],
    )


def _write_raw_logs(path: Path | None, events: list[ProviderEvent], enabled: bool) -> None:
    if not enabled or path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(
                json.dumps(
                    {
                        "timestamp": event.timestamp,
                        "event_type": event.event_type,
                        "text_length": event.text_length,
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )


def _host(base_url: str) -> str:
    return base_url.removeprefix("https://").removeprefix("http://").split("/")[0]
