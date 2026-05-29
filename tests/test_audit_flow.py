from pathlib import Path

from tokenverify.audit import AuditObservations, _collect_openai_compatible_observations, run_audit
from tokenverify.config import load_runtime_config
from tokenverify.models import ProviderEvent, Rating
from tokenverify.report import render_markdown


def test_full_mocked_audit_generates_markdown_report(tmp_path):
    config_path = tmp_path / "audit.yaml"
    raw_log_path = tmp_path / "events.jsonl"
    config_path.write_text(
        f"""
selected_endpoint: primary
output: audit.md
raw_logs:
  enabled: true
  path: {raw_log_path}
endpoints:
  - name: primary
    base_url: https://api.anthropic.com
    model: claude-sonnet-4-5
    api_key_env: ANTHROPIC_API_KEY
extension_probes:
  - name: appendix-only
    prompt: observation
""",
        encoding="utf-8",
    )
    runtime_config = load_runtime_config(config_path, env={"ANTHROPIC_API_KEY": "ENV_TOKEN_PLACEHOLDER"})
    observations = AuditObservations(
        messages_response={
            "id": "msg_1",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "ok"}],
        },
        thinking_response={"content": [{"type": "thinking", "thinking": "internal"}, {"type": "text", "text": "ok"}]},
        stream_events=[
            ProviderEvent(timestamp=1.0, event_type="message_start"),
            ProviderEvent(timestamp=1.2, event_type="content_block_delta", text_length=2),
            ProviderEvent(timestamp=1.4, event_type="content_block_delta", text_length=3),
        ],
    )

    result = run_audit(runtime_config, observations=observations)
    markdown = render_markdown(result)

    assert result.rating == Rating.HIGH_TRUST
    assert "TokenVerify Audit Report" in markdown
    assert "Plain-Language Summary" in markdown
    assert "ENV_TOKEN_PLACEHOLDER" not in markdown
    assert result.extension_probe_results[0].name == "appendix-only"


def test_audit_without_api_key_is_inconclusive(tmp_path):
    config_path = tmp_path / "audit.yaml"
    config_path.write_text(
        """
selected_endpoint: primary
endpoints:
  - name: primary
    base_url: https://api.anthropic.com
    model: claude-sonnet-4-5
""",
        encoding="utf-8",
    )
    runtime_config = load_runtime_config(config_path)

    result = run_audit(runtime_config)

    assert result.rating == Rating.INCONCLUSIVE
    assert "API key is required" in result.probe_results[0].errors[0]


def test_messages_request_error_is_reported_in_messages_probe(tmp_path):
    config_path = tmp_path / "audit.yaml"
    config_path.write_text(
        """
selected_endpoint: primary
endpoints:
  - name: primary
    base_url: https://api.anthropic.com
    model: claude-haiku-4-5-20251001-thinking
    api_key: TOKEN_PLACEHOLDER
""",
        encoding="utf-8",
    )
    runtime_config = load_runtime_config(config_path)
    observations = AuditObservations(
        messages_error="404 not found: /v1/messages",
        thinking_error="unknown field: thinking",
    )

    result = run_audit(runtime_config, observations=observations)

    assert result.rating == Rating.LOW_TRUST
    assert result.probe_results[0].name == "messages_protocol"
    assert result.probe_results[0].status == "error"
    assert "404 not found" in result.probe_results[0].errors[0]
    assert result.probe_results[1].name == "extended_thinking"
    assert result.probe_results[1].status == "failed"


def test_openai_compatible_claim_uses_chat_completion_observations(tmp_path):
    config_path = tmp_path / "audit.yaml"
    config_path.write_text(
        """
selected_endpoint: relay
endpoints:
  - name: relay
    base_url: https://relay.example/v1
    provider: anthropic
    api_shape: openai-compatible
    model: claude-sonnet-4.5
    api_key: TOKEN_PLACEHOLDER
""",
        encoding="utf-8",
    )
    runtime_config = load_runtime_config(config_path)
    observations = AuditObservations(
        messages_response={"model": "claude-sonnet-4.5", "choices": [{"message": {"content": "ok"}}]},
        stream_events=[
            ProviderEvent(0.0, "chat.completion.chunk", text_length=2, data={"finish_reason": None}),
            ProviderEvent(0.1, "chat.completion.chunk", text_length=2, data={"finish_reason": "stop"}),
        ],
    )

    result = run_audit(runtime_config, observations=observations)

    assert result.target_summary["claimed_api_shape"] == "openai-compatible"
    assert [probe.name for probe in result.probe_results] == [
        "chat_completions_shape",
        "claude_claim_consistency",
        "claude_version_thinking_capability",
        "reasoning_leakage",
        "openai_compatible_streaming",
    ]
    assert result.rating == Rating.HIGH_TRUST


def test_openai_compatible_repeat_collection_records_repeated_responses_and_latency(tmp_path, monkeypatch):
    config_path = tmp_path / "audit.yaml"
    config_path.write_text(
        """
selected_endpoint: relay
endpoints:
  - name: relay
    base_url: https://relay.example/v1
    provider: anthropic
    api_shape: openai-compatible
    model: claude-haiku-4-5-20251001
    api_key: TOKEN_PLACEHOLDER
""",
        encoding="utf-8",
    )
    runtime_config = load_runtime_config(config_path)

    class FakeOpenAICompatibleChatClient:
        def __init__(self, **kwargs):
            self.responses = [
                {"model": "claude-haiku-4-5-20251001", "choices": [{"message": {"content": "ok"}}]},
                {"model": "claude-haiku-4-5-20251001", "choices": [{"message": {"content": "ok"}}]},
                {"model": "openai/gpt-4o", "choices": [{"message": {"content": "ok"}}]},
            ]

        def create_chat_completion(self, payload):
            return self.responses.pop(0)

        def stream_chat_completion_events(self, payload):
            return []

    ticks = iter([0.0, 0.1, 1.0, 1.4, 2.0, 3.2])
    monkeypatch.setattr("tokenverify.audit.OpenAICompatibleChatClient", FakeOpenAICompatibleChatClient)
    monkeypatch.setattr("tokenverify.audit.time.monotonic", lambda: next(ticks))

    observations = _collect_openai_compatible_observations(runtime_config, repeat_count=3)

    assert observations.messages_response["model"] == "claude-haiku-4-5-20251001"
    assert [response["model"] for response in observations.repeated_messages_responses] == [
        "claude-haiku-4-5-20251001",
        "openai/gpt-4o",
    ]
    assert observations.latency_samples == [0.1, 0.4, 1.2]


def test_openai_compatible_self_relay_loop_short_circuits(tmp_path):
    config_path = tmp_path / "audit.yaml"
    config_path.write_text(
        """
selected_endpoint: relay
endpoints:
  - name: relay
    base_url: https://relay.example/v1
    provider: anthropic
    api_shape: openai-compatible
    model: claude-sonnet-4.5
    api_key: TOKEN_PLACEHOLDER
""",
        encoding="utf-8",
    )
    runtime_config = load_runtime_config(config_path)
    observations = AuditObservations(messages_error="self-relay-loop: TokenVerify scan marker was echoed")

    result = run_audit(runtime_config, observations=observations)

    assert result.rating == Rating.INCONCLUSIVE
    assert "SELF_RELAY_LOOP_DETECTED" in result.verdict.tags


def test_scoring_counts_openai_compatible_probe_evidence_generically(tmp_path):
    config_path = tmp_path / "audit.yaml"
    config_path.write_text(
        """
selected_endpoint: relay
endpoints:
  - name: relay
    base_url: https://relay.example/v1
    provider: anthropic
    api_shape: openai-compatible
    model: claude-sonnet-4.5
    api_key: TOKEN_PLACEHOLDER
""",
        encoding="utf-8",
    )
    runtime_config = load_runtime_config(config_path)
    observations = AuditObservations(
        messages_response={"model": "claude-sonnet-4.5", "choices": [{"message": {"content": "ok"}}]},
    )

    result = run_audit(runtime_config, observations=observations)

    assert result.score_breakdown["strong_passed"] >= 2
    assert result.verdict.authenticity_score >= 90


def test_openai_compatible_audit_includes_deep_dive_and_channel_risk_probes(tmp_path):
    config_path = tmp_path / "audit.yaml"
    config_path.write_text(
        """
selected_endpoint: relay
endpoints:
  - name: relay
    base_url: https://relay.example/v1
    provider: anthropic
    api_shape: openai-compatible
    model: claude-sonnet-4.5
    channel_claim: openrouter
    region_claim: us-east-1
    api_key: TOKEN_PLACEHOLDER
""",
        encoding="utf-8",
    )
    runtime_config = load_runtime_config(config_path)
    observations = AuditObservations(
        messages_response={
            "model": "anthropic/claude-sonnet-4.5",
            "system_fingerprint": "claude-sonnet-4.5-20250929",
            "choices": [{"message": {"reasoning": "dedicated reasoning field"}}],
        },
        repeated_messages_responses=[
            {"model": "anthropic/claude-sonnet-4.5"},
            {"model": "openai/gpt-4o"},
        ],
        response_headers={"x-request-id": "req_123", "x-openrouter-provider": "anthropic", "cf-ray": "abc-SJC"},
        messages_error="HTTP 429: upstream rate limit exceeded by account pool",
        latency_samples=[0.2, 0.25, 0.22, 3.5, 3.7],
    )

    result = run_audit(runtime_config, observations=observations)

    probe_names = [probe.name for probe in result.probe_results]
    assert "mixed_provider_consistency" in probe_names
    assert "claude_version_thinking_capability" in probe_names
    assert "channel_risk_observations" in probe_names
    assert "repeated_run_variance" in probe_names
    assert "MIXED_PROVIDER_INCONSISTENCY_DETECTED" in result.verdict.tags
    assert "CLAUDE_VERSION_FIELD_LEAKED" in result.verdict.tags
    assert "RELAY_HEADER_SUSPECT" in result.verdict.tags
    assert "TTFT_VARIANCE_HIGH" in result.verdict.tags


def test_unsupported_provider_claim_is_explicitly_out_of_scope(tmp_path):
    config_path = tmp_path / "audit.yaml"
    config_path.write_text(
        """
selected_endpoint: relay
endpoints:
  - name: relay
    base_url: https://relay.example/v1
    provider: gemini
    api_shape: openai-compatible
    model: gemini-2.5-pro
    api_key: TOKEN_PLACEHOLDER
""",
        encoding="utf-8",
    )
    runtime_config = load_runtime_config(config_path)

    result = run_audit(runtime_config, observations=AuditObservations())

    assert result.rating == Rating.INCONCLUSIVE
    assert result.probe_results[0].name == "unsupported_audit_target"
    assert "out of scope" in result.probe_results[0].errors[0]


def test_deepseek_compatible_claim_uses_deepseek_probe_path(tmp_path):
    config_path = tmp_path / "audit.yaml"
    config_path.write_text(
        """
selected_endpoint: deepseek
endpoints:
  - name: deepseek
    base_url: https://api.deepseek.com/v1
    provider: deepseek
    api_shape: openai-compatible
    model: deepseek-r1
    channel_claim: official
    api_key: TOKEN_PLACEHOLDER
""",
        encoding="utf-8",
    )
    runtime_config = load_runtime_config(config_path)
    observations = AuditObservations(
        messages_response={
            "model": "deepseek-reasoner",
            "choices": [{"message": {"reasoning_content": "work", "content": "ok"}, "finish_reason": "stop"}],
        },
        response_headers={"x-request-id": "req_123"},
        stream_events=[
            ProviderEvent(
                0.0,
                "chat.completion.chunk",
                data={"choices": [{"delta": {"reasoning_content": "work"}, "finish_reason": None}]},
            ),
            ProviderEvent(
                0.1,
                "chat.completion.chunk",
                data={"choices": [{"delta": {"content": "ok"}, "finish_reason": "stop"}]},
            ),
        ],
    )

    result = run_audit(runtime_config, observations=observations)

    assert result.target_summary["claimed_provider"] == "deepseek"
    probe_names = [probe.name for probe in result.probe_results]
    assert "deepseek_chat_completions_shape" in probe_names
    assert "deepseek_model_claim_consistency" in probe_names
    assert "deepseek_reasoning_content" in probe_names
    assert "deepseek_channel_risk" in probe_names
    assert "DEEPSEEK_REASONING_CONTENT_MATCH" in result.verdict.tags


def test_deepseek_r1_missing_reasoning_content_lowers_trust(tmp_path):
    config_path = tmp_path / "audit.yaml"
    config_path.write_text(
        """
selected_endpoint: deepseek
endpoints:
  - name: deepseek
    base_url: https://api.deepseek.com/v1
    provider: deepseek
    api_shape: openai-compatible
    model: deepseek-r1
    channel_claim: official
    api_key: TOKEN_PLACEHOLDER
""",
        encoding="utf-8",
    )
    runtime_config = load_runtime_config(config_path)
    observations = AuditObservations(
        messages_response={
            "model": "deepseek-r1",
            "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
        },
    )

    result = run_audit(runtime_config, observations=observations)

    assert result.rating == Rating.LOW_TRUST
    assert "DEEPSEEK_REASONING_CONTENT_MISSING" in result.verdict.tags


def test_openai_compatible_claim_uses_openai_probe_path(tmp_path):
    config_path = tmp_path / "audit.yaml"
    config_path.write_text(
        """
selected_endpoint: openai
endpoints:
  - name: openai
    base_url: https://api.openai.com/v1
    provider: openai
    api_shape: openai-compatible
    model: gpt-5.1
    channel_claim: official
    api_key: TOKEN_PLACEHOLDER
""",
        encoding="utf-8",
    )
    runtime_config = load_runtime_config(config_path)
    observations = AuditObservations(
        messages_response={
            "object": "chat.completion",
            "model": "gpt-5.1",
            "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
        },
        response_headers={"x-request-id": "req_123"},
        stream_events=[
            ProviderEvent(
                0.0,
                "chat.completion.chunk",
                text_length=2,
                data={"object": "chat.completion.chunk", "finish_reason": "stop"},
            )
        ],
    )

    result = run_audit(runtime_config, observations=observations)

    assert result.target_summary["claimed_provider"] == "openai"
    probe_names = [probe.name for probe in result.probe_results]
    assert "openai_chat_completions_shape" in probe_names
    assert "openai_model_claim_consistency" in probe_names
    assert "openai_channel_risk" in probe_names
    assert "OPENAI_OFFICIAL_CHANNEL_MATCH" in result.verdict.tags


def test_openai_compatible_reasoning_probe_skips_without_parameter_observations(tmp_path):
    config_path = tmp_path / "audit.yaml"
    config_path.write_text(
        """
selected_endpoint: openai
endpoints:
  - name: openai
    base_url: https://api.openai.com/v1
    provider: openai
    api_shape: openai-compatible
    model: gpt-5.1
    channel_claim: official
    api_key: TOKEN_PLACEHOLDER
""",
        encoding="utf-8",
    )
    runtime_config = load_runtime_config(config_path)
    observations = AuditObservations(
        messages_response={
            "object": "chat.completion",
            "model": "gpt-5.1",
            "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
        },
        response_headers={"x-request-id": "req_123"},
    )

    result = run_audit(runtime_config, observations=observations)

    reasoning_probe = next(probe for probe in result.probe_results if probe.name == "openai_reasoning_capability")
    assert reasoning_probe.status == "skipped"
    assert "OPENAI_REASONING_CAPABILITY_MISMATCH" not in result.verdict.tags


def test_cross_provider_model_leak_forces_low_trust(tmp_path):
    config_path = tmp_path / "audit.yaml"
    config_path.write_text(
        """
selected_endpoint: openai
endpoints:
  - name: openai
    base_url: https://api.openai.com/v1
    provider: openai
    api_shape: openai-compatible
    model: gpt-5.1
    channel_claim: official
    api_key: TOKEN_PLACEHOLDER
""",
        encoding="utf-8",
    )
    runtime_config = load_runtime_config(config_path)
    observations = AuditObservations(
        messages_response={
            "object": "chat.completion",
            "model": "anthropic/claude-3-5-sonnet",
            "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
        },
        response_headers={"x-request-id": "req_123"},
    )

    result = run_audit(runtime_config, observations=observations)

    assert result.rating == Rating.LOW_TRUST
    assert result.verdict.authenticity_score <= 39
    assert "CROSS_PROVIDER_MODEL_LEAKED" in result.verdict.tags
