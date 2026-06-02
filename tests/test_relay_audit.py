from pathlib import Path

import pytest

from tokenverify.relay_audit import RelayAuditRequest, exit_code_for_relay_verdict, load_relay_pack_summary, run_relay_audit
from tokenverify.relay_models import RelayAuditConfigError, RelayAuditProfile, RelayVerdict
from tokenverify.relay_safety import RelayAuditSecurityViolation


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


def test_run_relay_audit_live_unsupported_profile_blocks_before_transport():
    calls = []

    def transport(payload):
        calls.append(payload)

    request = RelayAuditRequest(
        base_url="https://api.relay.com/v1",
        model="example-model",
        profile=RelayAuditProfile.STREAMING,
        fake_scenario=None,
        pack_path=None,
        live=True,
        api_key="sk-secret",
        live_transport_factory=lambda: transport,
    )

    with pytest.raises(RelayAuditSecurityViolation):
        run_relay_audit(request)

    assert calls == []


def test_exit_code_for_relay_verdict_isolated_from_config_errors():
    assert exit_code_for_relay_verdict(RelayVerdict.PASS) == 0
    assert exit_code_for_relay_verdict(RelayVerdict.SUSPICIOUS) == 0
    assert exit_code_for_relay_verdict(RelayVerdict.FAIL) == 1
    assert exit_code_for_relay_verdict(RelayVerdict.INCONCLUSIVE) == 3
