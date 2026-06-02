import pytest

from tokenverify.relay_models import RelayAuditConfigError, RelayAuditProfile
from tokenverify.relay_safety import (
    RelayAuditSecurityViolation,
    RelayLiveAuthorization,
    authorize_relay_live_execution,
    guard_api_key_env_name,
)


def test_api_key_env_guard_accepts_normal_environment_variable_names():
    assert guard_api_key_env_name(None) is None
    assert guard_api_key_env_name("RELAY_API_KEY") == "RELAY_API_KEY"
    assert guard_api_key_env_name("OPENROUTER_TOKEN_1") == "OPENROUTER_TOKEN_1"


@pytest.mark.parametrize(
    "value",
    [
        "sk-or-v1-abcdef",
        "Bearer abcdef",
        "eyJhbGciOi.eyJzdWIiOiJ1c2Vy.signature",
        "https://api.example.com/key",
        "token.with.dots",
        "relay_api_key",
        "RELAY-API-KEY",
        "RELAY API KEY",
        "9RELAY_API_KEY",
        "RELAY.API.KEY",
    ],
)
def test_api_key_env_guard_rejects_secret_looking_values_without_echo(value):
    with pytest.raises(RelayAuditConfigError) as exc_info:
        guard_api_key_env_name(value)

    message = str(exc_info.value)
    assert "--api-key-env expects an environment variable name" in message
    assert value not in message
    assert "sk-or-v1" not in message
    assert "Bearer" not in message
    assert "eyJ" not in message


def test_authorization_blocks_missing_live_before_factories_are_touched():
    calls = []

    def client_factory():
        calls.append("client")

    with pytest.raises(RelayAuditSecurityViolation) as exc_info:
        authorize_relay_live_execution(
            live_mode=False,
            profile=RelayAuditProfile.GENERAL,
            client_factory=client_factory,
        )

    assert str(exc_info.value) == "Network execution blocked: --live flag missing."
    assert calls == []


def test_authorization_allows_general_live_without_touching_factory():
    calls = []

    def client_factory():
        calls.append("client")

    auth = authorize_relay_live_execution(
        live_mode=True,
        profile=RelayAuditProfile.GENERAL,
        client_factory=client_factory,
    )

    assert auth == RelayLiveAuthorization(
        live_mode=True,
        profile=RelayAuditProfile.GENERAL,
        approved_live_path="general_minimal_connectivity",
        network_scope="single_non_streaming_request",
    )
    assert calls == []


def test_authorization_allows_streaming_live_without_touching_factory():
    calls = []

    def client_factory():
        calls.append("client")

    auth = authorize_relay_live_execution(
        live_mode=True,
        profile=RelayAuditProfile.STREAMING,
        client_factory=client_factory,
    )

    assert auth == RelayLiveAuthorization(
        live_mode=True,
        profile=RelayAuditProfile.STREAMING,
        approved_live_path="streaming_minimal_sse_integrity",
        network_scope="single_streaming_request",
    )
    assert calls == []


@pytest.mark.parametrize(
    "profile",
    [
        RelayAuditProfile.SCHEMA,
        RelayAuditProfile.PRIVACY,
        RelayAuditProfile.FULL,
    ],
)
def test_authorization_blocks_unsupported_profiles_before_factories(profile):
    calls = []

    def client_factory():
        calls.append("client")

    with pytest.raises(RelayAuditSecurityViolation) as exc_info:
        authorize_relay_live_execution(
            live_mode=True,
            profile=profile,
            client_factory=client_factory,
        )

    assert "not opened for this profile" in str(exc_info.value)
    assert calls == []
