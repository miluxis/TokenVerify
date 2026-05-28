from pathlib import Path

from tokenverify.audit import AuditObservations, run_audit
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
    assert "TokenVerify Claude Audit Report" in markdown
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
