import pytest

from tokenverify.relay_safety import (
    RelayAuditSecurityViolation,
    basename_only,
    enforce_relay_live_gate,
    hash_relay_endpoint,
    sanitize_public_relay_text,
    sanitize_to_fqdn,
)


def test_url_cleaner_returns_host_only_and_endpoint_hash_is_stable():
    raw = "https://user:pass@api.relay.com/v1/chat/completions?user=heiyan_studio#frag"

    assert sanitize_to_fqdn(raw) == "api.relay.com"
    assert hash_relay_endpoint(raw) == hash_relay_endpoint(raw)
    assert len(hash_relay_endpoint(raw)) == 16


def test_url_cleaner_never_returns_raw_url_material():
    raw = "https://api.relay.com/v1/chat/completions?user=heiyan_studio#frag"
    cleaned = sanitize_public_relay_text(f"Endpoint failed: {raw}")

    assert "api.relay.com" in cleaned
    assert "https://" not in cleaned
    assert "/v1" not in cleaned
    assert "chat" not in cleaned
    assert "heiyan_studio" not in cleaned
    assert "#frag" not in cleaned


def test_path_cleaner_returns_basename_only_for_sensitive_paths():
    assert basename_only("~/Desktop/heiyan_studio/my_private_pack.yaml") == "my_private_pack.yaml"
    assert basename_only("/Users/ceo/StudioSecret/private.yaml") == "private.yaml"
    assert basename_only(r"C:\Users\CEO\StudioSecret\private.yaml") == "private.yaml"


def test_public_relay_text_washes_paths_tokens_and_urls():
    raw = (
        "Pack /Users/ceo/StudioSecret/private.yaml failed for "
        "https://api.relay.com/v1/chat/completions?user=heiyan_studio "
        "with Bearer sk-secret-token"
    )
    cleaned = sanitize_public_relay_text(raw)

    assert "private.yaml" in cleaned
    assert "api.relay.com" in cleaned
    assert "/Users" not in cleaned
    assert "ceo" not in cleaned
    assert "StudioSecret" not in cleaned
    assert "https://" not in cleaned
    assert "/v1" not in cleaned
    assert "heiyan_studio" not in cleaned
    assert "sk-secret-token" not in cleaned


def test_live_gate_blocks_without_live_before_transport_creation():
    calls = []

    def transport_factory():
        calls.append("constructed")
        return object()

    with pytest.raises(RelayAuditSecurityViolation) as exc_info:
        enforce_relay_live_gate(live_mode=False, transport_factory=transport_factory)

    assert str(exc_info.value) == "Network execution blocked: --live flag missing."
    assert calls == []


def test_live_gate_allows_live_general_through_compatibility_wrapper():
    calls = []

    def transport_factory():
        calls.append("constructed")
        return object()

    transport = enforce_relay_live_gate(live_mode=True, transport_factory=transport_factory)

    assert transport is not None
    assert calls == ["constructed"]
