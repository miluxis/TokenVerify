import pytest

from tokenverify.audit_plan import UnsupportedAuditTarget, build_audit_plan
from tokenverify.models import Claim


def test_audit_plan_routes_anthropic_native_by_composite_claim():
    plan = build_audit_plan(Claim(provider="anthropic", api_shape="native", model="claude-sonnet-4-5"))

    assert plan.path == "anthropic_native"
    assert plan.provider == "anthropic"
    assert plan.api_shape == "native"
    assert "messages_protocol" in plan.probe_names
    assert "chat_completions_shape" not in plan.probe_names


def test_audit_plan_routes_openai_compatible_claude_by_composite_claim():
    plan = build_audit_plan(Claim(provider="anthropic", api_shape="openai-compatible", model="claude-sonnet-4.5"))

    assert plan.path == "anthropic_openai_compatible"
    assert "chat_completions_shape" in plan.probe_names
    assert "messages_protocol" not in plan.probe_names


def test_audit_plan_rejects_unknown_provider_as_out_of_scope():
    with pytest.raises(UnsupportedAuditTarget, match="out of scope"):
        build_audit_plan(Claim(provider="gemini", api_shape="openai-compatible", model="gemini-2.5-pro"))


def test_audit_plan_documents_repeat_sampling_without_single_anomaly_claims():
    plan = build_audit_plan(Claim(provider="anthropic", api_shape="openai-compatible", model="claude-sonnet-4.5"))

    assert plan.repeat_sampling_min_runs == 5
    assert "single" in plan.single_anomaly_policy
    assert "proof" in plan.single_anomaly_policy


def test_audit_plan_routes_openai_compatible_claim():
    plan = build_audit_plan(Claim(provider="openai", api_shape="openai-compatible", model="gpt-5.1"))

    assert plan.path == "openai_openai_compatible"
    assert plan.provider == "openai"
    assert plan.api_shape == "openai-compatible"
    assert "openai_chat_completions_shape" in plan.probe_names
    assert "messages_protocol" not in plan.probe_names


def test_audit_plan_routes_deepseek_compatible_claim():
    plan = build_audit_plan(Claim(provider="deepseek", api_shape="openai-compatible", model="deepseek-r1"))

    assert plan.path == "deepseek_openai_compatible"
    assert plan.probe_names == (
        "deepseek_chat_completions_shape",
        "deepseek_model_claim_consistency",
        "deepseek_reasoning_content",
        "deepseek_channel_risk",
        "deepseek_compatible_streaming",
    )
