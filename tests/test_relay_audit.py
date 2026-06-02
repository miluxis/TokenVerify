from pathlib import Path
import traceback

import pytest

from tokenverify.relay_audit import RelayAuditRequest, exit_code_for_relay_verdict, load_relay_pack_summary, run_relay_audit
from tokenverify.relay_models import RelayAuditConfigError, RelayAuditProfile, RelayVerdict
from tokenverify.relay_safety import RelayAuditSecurityViolation
from tokenverify.relay_streaming import RelayStreamEvent


def test_load_relay_pack_summary_hashes_metadata_without_prompt_or_answer_leakage(tmp_path):
    pack_path = tmp_path / "my_private_pack.yaml"
    pack_path.write_text(
        """
id: private-media-pack
version: "2026.06"
challenges:
  - id: secret-case
    prompt: "raw prompt must not appear"
    expected_answer: "private expected answer"
    verifier: "secret verifier expression"
""",
        encoding="utf-8",
    )

    summary = load_relay_pack_summary(pack_path)
    rendered = str(summary)

    assert summary.label == "Local Private Pack"
    assert summary.pack_id == "private-media-pack"
    assert summary.version == "2026.06"
    assert summary.basename == "my_private_pack.yaml"
    assert summary.pack_hash is not None
    assert len(summary.pack_hash) == 16
    assert "raw prompt" not in rendered
    assert "private expected answer" not in rendered
    assert "secret verifier" not in rendered
    assert str(tmp_path) not in rendered


def test_load_relay_pack_summary_extracts_safe_metadata_lists_and_count(tmp_path):
    pack_path = tmp_path / "my_private_pack.yaml"
    pack_path.write_text(
        """
id: private-media-pack
version: "2026.06"
profiles:
  - general
  - privacy
categories:
  - model_substitution
  - upstream_error_leakage
challenges:
  - id: stable-case-001
    profile: general
    category: model_substitution
    level: basic
    public_intent: "Checks a public relay contract."
    prompt: "raw prompt must not appear"
    expected_answer: "private expected answer"
    verifier: "secret verifier expression"
  - id: stable-case-002
    profile: privacy
    category: upstream_error_leakage
    level: strict
    public_intent: "Checks sanitized upstream error behavior."
    messages:
      - role: user
        content: "private message must not appear"
    answers:
      - "private alternate answer"
    variables:
      secret: "private variable value"
""",
        encoding="utf-8",
    )

    summary = load_relay_pack_summary(pack_path)
    rendered = str(summary)

    assert summary.label == "Local Private Pack"
    assert summary.pack_id == "private-media-pack"
    assert summary.version == "2026.06"
    assert summary.basename == "my_private_pack.yaml"
    assert len(summary.pack_hash) == 16
    assert summary.profiles == ["general", "privacy"]
    assert summary.categories == ["model_substitution", "upstream_error_leakage"]
    assert summary.challenge_count == 2
    assert summary.public_intents == [
        "Checks a public relay contract.",
        "Checks sanitized upstream error behavior.",
    ]
    assert "raw prompt" not in rendered
    assert "private expected answer" not in rendered
    assert "secret verifier" not in rendered
    assert "private message" not in rendered
    assert "private alternate answer" not in rendered
    assert "private variable value" not in rendered


def test_pack_hash_changes_when_private_prompt_changes(tmp_path):
    pack_path = tmp_path / "my_private_pack.yaml"
    pack_path.write_text(
        """
id: private-media-pack
version: "2026.06"
challenges:
  - id: case
    prompt: "private prompt A"
    expected_answer: "private answer"
""",
        encoding="utf-8",
    )
    first = load_relay_pack_summary(pack_path)

    pack_path.write_text(
        """
id: private-media-pack
version: "2026.06"
challenges:
  - id: case
    prompt: "private prompt B"
    expected_answer: "private answer"
""",
        encoding="utf-8",
    )
    second = load_relay_pack_summary(pack_path)

    assert first.pack_hash != second.pack_hash
    assert first.pack_id == second.pack_id == "private-media-pack"
    assert first.version == second.version == "2026.06"


def test_pack_metadata_values_are_sanitized_before_summary(tmp_path):
    pack_path = tmp_path / "my_private_pack.yaml"
    pack_path.write_text(
        """
id: "https://api.relay.com/v1/chat/completions?token=secret#frag"
version: "/Users/Teng/Desktop/heiyan_studio/version-secret"
profiles:
  - general
categories:
  - model_substitution
challenges:
  - id: hidden-local-case
    profile: general
    category: model_substitution
    public_intent: "Uses sk-or-v1-private-token and /Users/Teng/Desktop/heiyan_studio/private.yaml"
    prompt: "raw prompt must not appear"
    expected_answer: "private expected answer"
""",
        encoding="utf-8",
    )

    summary = load_relay_pack_summary(pack_path)
    rendered = str(summary)

    assert summary.pack_id == "api.relay.com"
    assert summary.version == "version-secret"
    assert summary.public_intents == ["Uses ***REDACTED*** and private.yaml"]
    assert "https://" not in rendered
    assert "/v1" not in rendered
    assert "token=secret" not in rendered
    assert "sk-or-v1-private-token" not in rendered
    assert "/Users" not in rendered
    assert "Teng" not in rendered
    assert "heiyan_studio" not in rendered
    assert "raw prompt" not in rendered
    assert "private expected answer" not in rendered


def test_missing_pack_error_uses_exit_two_category_and_basename_only():
    with pytest.raises(RelayAuditConfigError) as exc_info:
        load_relay_pack_summary(Path("~/Desktop/heiyan_studio/missing.yaml"))

    message = str(exc_info.value)
    assert "missing.yaml" in message
    assert "heiyan_studio" not in message
    assert "Desktop" not in message
    assert "~" not in message


def test_invalid_pack_metadata_is_configuration_error(tmp_path):
    pack_path = tmp_path / "bad_private.yaml"
    pack_path.write_text("id:\n  nested: not-public\nversion: '2026.06'\n", encoding="utf-8")

    with pytest.raises(RelayAuditConfigError) as exc_info:
        load_relay_pack_summary(pack_path)

    assert "bad_private.yaml" in str(exc_info.value)
    assert str(tmp_path) not in str(exc_info.value)


def test_directory_pack_path_is_config_error_with_basename_only(tmp_path):
    pack_dir = tmp_path / "heiyan_studio_private_pack"
    pack_dir.mkdir()

    with pytest.raises(RelayAuditConfigError) as exc_info:
        load_relay_pack_summary(pack_dir)

    message = str(exc_info.value)
    assert "heiyan_studio_private_pack" in message
    assert str(tmp_path) not in message
    assert exc_info.value.__cause__ is None


def test_oversized_pack_file_fails_before_yaml_parsing_with_basename_only(tmp_path):
    pack_path = tmp_path / "huge_private_pack.yaml"
    pack_path.write_text("x" * (5 * 1024 * 1024 + 1), encoding="utf-8")

    with pytest.raises(RelayAuditConfigError) as exc_info:
        load_relay_pack_summary(pack_path)

    message = str(exc_info.value)
    assert "too large" in message
    assert "huge_private_pack.yaml" in message
    assert str(tmp_path) not in message
    assert exc_info.value.__cause__ is None


def test_malformed_yaml_error_cuts_exception_chain_and_raw_yaml(tmp_path):
    pack_path = tmp_path / "bad_private.yaml"
    pack_path.write_text(
        'id: private\nchallenges:\n  - prompt: "raw prompt must not appear"\n    expected_answer: "private expected answer"\n    verifier: [unterminated\n',
        encoding="utf-8",
    )

    with pytest.raises(RelayAuditConfigError) as exc_info:
        load_relay_pack_summary(pack_path)

    exc = exc_info.value
    rendered = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    assert exc.__cause__ is None
    assert "bad_private.yaml" in rendered
    assert str(tmp_path) not in rendered
    assert "raw prompt" not in rendered
    assert "private expected answer" not in rendered
    assert "unterminated" not in rendered


def test_nested_invalid_metadata_error_does_not_leak_raw_object(tmp_path):
    pack_path = tmp_path / "bad_metadata.yaml"
    pack_path.write_text(
        """
id:
  nested: "StudioSecret"
version: "2026.06"
challenges:
  - prompt: "raw prompt must not appear"
    expected_answer: "private expected answer"
""",
        encoding="utf-8",
    )

    with pytest.raises(RelayAuditConfigError) as exc_info:
        load_relay_pack_summary(pack_path)

    message = str(exc_info.value)
    assert "bad_metadata.yaml" in message
    assert "StudioSecret" not in message
    assert "raw prompt" not in message
    assert "private expected answer" not in message
    assert exc_info.value.__cause__ is None


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("profiles", "not-a-list"),
        ("categories", "not-a-list"),
        ("profiles", ["general", "unknown-profile"]),
        ("categories", ["model_substitution", "unknown-category"]),
    ],
)
def test_unsupported_top_level_pack_metadata_is_sanitized_config_error(tmp_path, field, value):
    import yaml

    pack_path = tmp_path / "bad_private.yaml"
    data = {
        "id": "private-media-pack",
        "version": "2026.06",
        field: value,
        "challenges": [
            {
                "prompt": "raw prompt must not appear",
                "expected_answer": "private expected answer",
            }
        ],
    }
    pack_path.write_text(yaml.safe_dump(data), encoding="utf-8")

    with pytest.raises(RelayAuditConfigError) as exc_info:
        load_relay_pack_summary(pack_path)

    message = str(exc_info.value)
    assert "bad_private.yaml" in message
    assert "unknown-profile" not in message
    assert "unknown-category" not in message
    assert "raw prompt" not in message
    assert "private expected answer" not in message


def test_remote_pack_path_is_rejected_without_fetching_or_echoing_url():
    with pytest.raises(RelayAuditConfigError) as exc_info:
        load_relay_pack_summary("https://api.relay.com/v1/my_private_pack.yaml?token=secret#frag")

    message = str(exc_info.value)
    assert "my_private_pack.yaml" in message or "[redacted-path]" in message
    assert "https://" not in message
    assert "/v1" not in message
    assert "token=secret" not in message


def test_run_relay_audit_fake_scenario_returns_result_without_live_gate():
    request = RelayAuditRequest(
        base_url="https://api.relay.com/v1/chat/completions?user=heiyan_studio#frag",
        model="example-model",
        profile=RelayAuditProfile.GENERAL,
        fake_scenario=RelayVerdict.SUSPICIOUS,
        pack_path=None,
        live=False,
    )

    result = run_relay_audit(request)

    assert result.verdict == RelayVerdict.SUSPICIOUS
    assert result.endpoint_host == "api.relay.com"


def test_run_relay_audit_without_fake_run_blocks_missing_live():
    request = RelayAuditRequest(
        base_url="https://api.relay.com/v1",
        model="example-model",
        profile=RelayAuditProfile.GENERAL,
        fake_scenario=None,
        pack_path=None,
        live=False,
    )

    with pytest.raises(RelayAuditSecurityViolation) as exc_info:
        run_relay_audit(request)

    assert str(exc_info.value) == "Network execution blocked: --live flag missing."


def test_run_relay_audit_with_live_general_requires_transport_for_live_execution():
    request = RelayAuditRequest(
        base_url="https://api.relay.com/v1",
        model="example-model",
        profile=RelayAuditProfile.GENERAL,
        fake_scenario=None,
        pack_path=None,
        live=True,
        api_key="sk-secret",
        live_transport_factory=None,
    )

    result = run_relay_audit(request)

    assert result.verdict == RelayVerdict.INCONCLUSIVE
    assert result.runtime_category.value == "unsupported_live_target"


def test_run_relay_audit_with_live_general_uses_injected_transport():
    calls = []

    def transport(payload):
        calls.append(payload)
        from tokenverify.relay_live import RelayLiveTransportResponse

        return RelayLiveTransportResponse(status_code=200, body={"choices": [{"message": {"content": "ok"}}]})

    request = RelayAuditRequest(
        base_url="https://api.relay.com/v1/chat/completions?user=heiyan_studio#frag",
        model="example-model",
        profile=RelayAuditProfile.GENERAL,
        fake_scenario=None,
        pack_path=None,
        live=True,
        api_key="sk-secret",
        live_transport_factory=lambda: transport,
    )

    result = run_relay_audit(request)

    assert len(calls) == 1
    assert result.verdict == RelayVerdict.PASS
    assert result.endpoint_host == "api.relay.com"


def test_run_relay_audit_with_live_streaming_uses_injected_stream_transport():
    calls = []

    def transport(payload):
        calls.append(payload)
        return [
            RelayStreamEvent("chat.completion.chunk", 0, True, 2, False, None),
            RelayStreamEvent("chat.completion.chunk", 1, False, 0, True, "stop"),
        ]

    request = RelayAuditRequest(
        base_url="https://api.relay.com/v1/chat/completions?user=heiyan_studio#frag",
        model="example-model",
        profile=RelayAuditProfile.STREAMING,
        fake_scenario=None,
        pack_path=None,
        live=True,
        api_key="sk-secret",
        stream_transport_factory=lambda: transport,
    )

    result = run_relay_audit(request)

    assert len(calls) == 1
    assert calls[0]["stream"] is True
    assert result.verdict == RelayVerdict.PASS
    assert result.profile == RelayAuditProfile.STREAMING
    assert result.endpoint_host == "api.relay.com"


def test_run_relay_audit_streaming_without_live_does_not_touch_stream_transport_factory():
    calls = []

    def stream_factory():
        calls.append("factory")
        raise AssertionError("streaming factory must not be touched without --live")

    request = RelayAuditRequest(
        base_url="https://api.relay.com/v1",
        model="example-model",
        profile=RelayAuditProfile.STREAMING,
        fake_scenario=None,
        pack_path=None,
        live=False,
        stream_transport_factory=stream_factory,
    )

    with pytest.raises(RelayAuditSecurityViolation):
        run_relay_audit(request)

    assert calls == []


@pytest.mark.parametrize(
    "profile",
    [RelayAuditProfile.SCHEMA, RelayAuditProfile.PRIVACY, RelayAuditProfile.FULL],
)
def test_run_relay_audit_live_unsupported_profile_blocks_before_stream_transport(profile):
    calls = []

    def stream_factory():
        calls.append("factory")
        raise AssertionError("streaming factory must not be touched for blocked profiles")

    request = RelayAuditRequest(
        base_url="https://api.relay.com/v1",
        model="example-model",
        profile=profile,
        fake_scenario=None,
        pack_path=None,
        live=True,
        api_key="sk-secret",
        stream_transport_factory=stream_factory,
    )

    with pytest.raises(RelayAuditSecurityViolation):
        run_relay_audit(request)

    assert calls == []


def test_exit_code_for_relay_verdict_isolated_from_config_errors():
    assert exit_code_for_relay_verdict(RelayVerdict.PASS) == 0
    assert exit_code_for_relay_verdict(RelayVerdict.SUSPICIOUS) == 0
    assert exit_code_for_relay_verdict(RelayVerdict.FAIL) == 1
    assert exit_code_for_relay_verdict(RelayVerdict.INCONCLUSIVE) == 3
