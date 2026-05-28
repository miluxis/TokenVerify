from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from tokenverify.models import AuditResult, ProbeResult, ProviderEvent
from tokenverify.providers.anthropic import AnthropicMessagesClient, build_messages_payload
from tokenverify.probes.messages import evaluate_messages_response
from tokenverify.probes.streaming import calculate_streaming_metrics
from tokenverify.probes.thinking import build_thinking_payload, evaluate_thinking_outcome
from tokenverify.scoring import score_probe_results


@dataclass(frozen=True)
class AuditObservations:
    messages_response: dict | None = None
    messages_error: str | None = None
    thinking_response: dict | None = None
    thinking_error: str | None = None
    stream_events: list[ProviderEvent] = field(default_factory=list)


def run_audit(runtime_config, observations: AuditObservations | None = None) -> AuditResult:
    observations = observations or _collect_live_observations(runtime_config)
    probe_results: list[ProbeResult] = []
    if observations.thinking_error == "API key is required for live audit.":
        probe_results.append(ProbeResult("messages_protocol", "error", errors=[observations.thinking_error]))
        rating, breakdown = score_probe_results(probe_results)
        return _result(runtime_config, probe_results, rating, breakdown)
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
        metrics = calculate_streaming_metrics(observations.stream_events)
        probe_results.append(
            ProbeResult(
                name="streaming_features",
                status="warning" if metrics.is_synthetic_stream else "passed",
                evidence=[],
                metrics=metrics,
            )
        )
        _write_raw_logs(runtime_config.raw_log_path, observations.stream_events, runtime_config.raw_logs_enabled)

    rating, breakdown = score_probe_results(probe_results)
    return _result(runtime_config, probe_results, rating, breakdown)


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


def _result(runtime_config, probe_results: list[ProbeResult], rating, breakdown: dict[str, int]) -> AuditResult:
    return AuditResult(
        target_summary={
            "base_url_host": _host(runtime_config.endpoint.base_url),
            "model": runtime_config.endpoint.model,
            "endpoint": runtime_config.endpoint.name,
        },
        probe_results=probe_results,
        rating=rating,
        score_breakdown=breakdown,
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
