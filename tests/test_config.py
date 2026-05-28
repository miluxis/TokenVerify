from pathlib import Path

import pytest

from tokenverify.config import ConfigError, CliOverrides, load_runtime_config, redact_secrets


def write_config(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "audit.yaml"
    path.write_text(content, encoding="utf-8")
    return path


def test_load_single_endpoint_config(tmp_path):
    path = write_config(
        tmp_path,
        """
selected_endpoint: primary
output: reports/audit.md
raw_logs:
  enabled: false
endpoints:
  - name: primary
    base_url: https://api.anthropic.com
    model: claude-sonnet-4-5
    api_key_env: ANTHROPIC_API_KEY
extension_probes:
  - name: observation-only
    prompt: hello
""",
    )

    config = load_runtime_config(path, env={"ANTHROPIC_API_KEY": "ENV_TOKEN_PLACEHOLDER"})

    assert config.endpoint.name == "primary"
    assert config.endpoint.base_url == "https://api.anthropic.com"
    assert config.endpoint.model == "claude-sonnet-4-5"
    assert config.endpoint.api_key == "ENV_TOKEN_PLACEHOLDER"
    assert config.output_path == Path("reports/audit.md")
    assert config.raw_logs_enabled is False
    assert config.extension_probes[0]["name"] == "observation-only"


def test_config_normalizes_default_anthropic_native_claim(tmp_path):
    path = write_config(
        tmp_path,
        """
selected_endpoint: primary
endpoints:
  - name: primary
    base_url: https://api.anthropic.com
    model: claude-sonnet-4-5
""",
    )

    config = load_runtime_config(path)

    assert config.endpoint.claim.provider == "anthropic"
    assert config.endpoint.claim.api_shape == "native"
    assert config.endpoint.claim.model == "claude-sonnet-4-5"
    assert config.endpoint.claim.channel_claim == "unknown"


def test_config_uses_explicit_claim_fields(tmp_path):
    path = write_config(
        tmp_path,
        """
selected_endpoint: primary
endpoints:
  - name: primary
    base_url: https://relay.example/v1
    provider: anthropic
    api_shape: openai-compatible
    model: claude-sonnet-4-5
    channel_claim: openrouter
    region_claim: us-east-1
""",
    )

    config = load_runtime_config(path)

    assert config.endpoint.claim.provider == "anthropic"
    assert config.endpoint.claim.api_shape == "openai-compatible"
    assert config.endpoint.claim.channel_claim == "openrouter"
    assert config.endpoint.claim.region_claim == "us-east-1"


def test_config_infers_openai_compatible_shape_from_base_url(tmp_path):
    path = write_config(
        tmp_path,
        """
selected_endpoint: primary
endpoints:
  - name: primary
    base_url: https://relay.example/v1/chat/completions
    provider: anthropic
    model: claude-sonnet-4-5
""",
    )

    config = load_runtime_config(path)

    assert config.endpoint.claim.api_shape == "openai-compatible"


def test_cli_overrides_yaml_fields(tmp_path):
    path = write_config(
        tmp_path,
        """
selected_endpoint: primary
output: reports/audit.md
endpoints:
  - name: primary
    base_url: https://relay.example
    model: claude-3-5-sonnet
    api_key: YAML_TOKEN_PLACEHOLDER
""",
    )

    config = load_runtime_config(
        path,
        overrides=CliOverrides(
            base_url="https://override.example",
            model="claude-opus-4-1",
            api_key="CLI_TOKEN_PLACEHOLDER",
            output="override.md",
            raw_log_path="events.jsonl",
        ),
    )

    assert config.endpoint.base_url == "https://override.example"
    assert config.endpoint.model == "claude-opus-4-1"
    assert config.endpoint.api_key == "CLI_TOKEN_PLACEHOLDER"
    assert config.output_path == Path("override.md")
    assert config.raw_logs_enabled is True
    assert config.raw_log_path == Path("events.jsonl")


def test_multiple_endpoints_require_selection(tmp_path):
    path = write_config(
        tmp_path,
        """
endpoints:
  - name: first
    base_url: https://first.example
    model: claude-sonnet-4-5
    api_key: FIRST_TOKEN_PLACEHOLDER
  - name: second
    base_url: https://second.example
    model: claude-sonnet-4-5
    api_key: SECOND_TOKEN_PLACEHOLDER
""",
    )

    with pytest.raises(ConfigError, match="select one endpoint"):
        load_runtime_config(path)


def test_secret_redaction_never_leaks_api_key():
    redacted = redact_secrets(
        {
            "api_key": "TOKEN_SHOULD_BE_REDACTED",
            "nested": {"Authorization": "Bearer TOKEN_SHOULD_BE_REDACTED"},
            "safe": "visible",
        }
    )

    assert "TOKEN_SHOULD_BE_REDACTED" not in str(redacted)
    assert redacted["api_key"] == "***REDACTED***"
    assert redacted["nested"]["Authorization"] == "***REDACTED***"
    assert redacted["safe"] == "visible"
