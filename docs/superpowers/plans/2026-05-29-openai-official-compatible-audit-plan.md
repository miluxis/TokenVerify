# OpenAI Official And Compatible Model Audit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a mocked, test-covered audit path for endpoints claiming OpenAI models through a Chat Completions-compatible API shape.

**Architecture:** Reuse the existing OpenAI-compatible HTTP client and `ProviderAdapter` contract. Add OpenAI-specific model capability classification, focused probes, audit-plan routing, and report rendering without implementing Responses API or non-OpenAI providers.

**Tech Stack:** Python 3.11+, dataclasses, enums, httpx MockTransport, pytest, existing TokenVerify CLI/report/scoring model.

---

## Execution Rules

- Implement one task at a time with TDD: write failing tests, verify failure, implement, verify pass.
- Do not implement DeepSeek, Gemini, Anthropic expansion, Seed, Qwen, Doubao, dashboard, batch mode, JSON output, or Responses API.
- Do not run real-network tests.
- Do not commit unless the user explicitly asks.
- Use `PYTHONPATH=src python3 -m pytest ...` for verification.
- Keep strong authenticity assertions separate from heuristic channel-risk observations.

## File Structure

- Modify `src/tokenverify/models.py`: add stable OpenAI evidence/risk tags.
- Create `src/tokenverify/openai_capabilities.py`: classify OpenAI model families, reasoning support, and confidence wording.
- Create `src/tokenverify/probes/openai.py`: OpenAI Chat Completions shape, model claim, reasoning capability, streaming, and channel-risk probes.
- Modify `src/tokenverify/audit_plan.py`: route `Claim(provider="openai", api_shape="openai-compatible", ...)`.
- Modify `src/tokenverify/audit.py`: run the new OpenAI audit path using existing OpenAI-compatible provider collection patterns.
- Modify `src/tokenverify/report.py`: render OpenAI probe sections.
- Modify `src/tokenverify/tag_taxonomy.py`: classify new OpenAI tags.
- Create `tests/test_openai_capabilities.py`: model family and reasoning capability tests.
- Create `tests/probes/test_openai.py`: OpenAI probe tests.
- Modify `tests/test_audit_plan.py`: routing tests.
- Modify `tests/test_audit_flow.py`: audit integration tests.
- Modify `tests/test_report.py`: report rendering tests.
- Modify `tests/test_models.py`: stable tag tests.
- Modify `tests/test_tag_taxonomy.py`: taxonomy tests.
- Modify `docs/superpowers/plans/2026-05-28-tokenverify-roadmap-todo.md`: mark implementation progress only after each task passes.

---

### Task 1: Add Stable OpenAI Tags

**Files:**
- Modify: `src/tokenverify/models.py`
- Test: `tests/test_models.py`

- [ ] **Step 1: Write failing tag tests**

Append to `tests/test_models.py`:

```python
def test_openai_audit_tag_values_are_stable():
    assert EvidenceTag.OPENAI_CHAT_COMPLETION_SHAPE_MATCH.value == "OPENAI_CHAT_COMPLETION_SHAPE_MATCH"
    assert EvidenceTag.OPENAI_CHAT_COMPLETION_SHAPE_MISMATCH.value == "OPENAI_CHAT_COMPLETION_SHAPE_MISMATCH"
    assert EvidenceTag.NON_OPENAI_PROVIDER_SHAPE_DETECTED.value == "NON_OPENAI_PROVIDER_SHAPE_DETECTED"
    assert EvidenceTag.OPENAI_MODEL_CLAIM_MATCH.value == "OPENAI_MODEL_CLAIM_MATCH"
    assert EvidenceTag.OPENAI_MODEL_CLAIM_MISMATCH.value == "OPENAI_MODEL_CLAIM_MISMATCH"
    assert EvidenceTag.CROSS_PROVIDER_MODEL_LEAKED.value == "CROSS_PROVIDER_MODEL_LEAKED"
    assert EvidenceTag.OPENAI_STREAM_SEQUENCE_MATCH.value == "OPENAI_STREAM_SEQUENCE_MATCH"
    assert EvidenceTag.OPENAI_STREAM_SEQUENCE_MISMATCH.value == "OPENAI_STREAM_SEQUENCE_MISMATCH"
    assert EvidenceTag.OPENAI_REASONING_CAPABILITY_MATCH.value == "OPENAI_REASONING_CAPABILITY_MATCH"
    assert EvidenceTag.OPENAI_REASONING_CAPABILITY_MISMATCH.value == "OPENAI_REASONING_CAPABILITY_MISMATCH"
    assert EvidenceTag.OPENAI_OFFICIAL_CHANNEL_MATCH.value == "OPENAI_OFFICIAL_CHANNEL_MATCH"
    assert EvidenceTag.OPENAI_OFFICIAL_CHANNEL_MISMATCH.value == "OPENAI_OFFICIAL_CHANNEL_MISMATCH"
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/test_models.py::test_openai_audit_tag_values_are_stable -v
```

Expected: FAIL because the enum values do not exist.

- [ ] **Step 3: Add enum values**

In `src/tokenverify/models.py`, add the enum values exactly as asserted in the test.

- [ ] **Step 4: Run tests to verify pass**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/test_models.py::test_openai_audit_tag_values_are_stable -v
```

Expected: PASS.

---

### Task 2: Add OpenAI Model Capability Table

**Files:**
- Create: `src/tokenverify/openai_capabilities.py`
- Test: `tests/test_openai_capabilities.py`

- [ ] **Step 1: Write failing capability tests**

Create `tests/test_openai_capabilities.py`:

```python
from tokenverify.openai_capabilities import OpenAIModelFamily, lookup_openai_model_capability


def test_gpt_5_family_is_reasoning_capable():
    capability = lookup_openai_model_capability("gpt-5.1")

    assert capability.family == OpenAIModelFamily.GPT_5
    assert capability.is_known is True
    assert capability.supports_reasoning_effort is True
    assert capability.confidence == "high"


def test_gpt_4_family_is_known_without_reasoning_effort():
    capability = lookup_openai_model_capability("openai/gpt-4.1-2025-04-14")

    assert capability.family == OpenAIModelFamily.GPT_4_1
    assert capability.is_known is True
    assert capability.supports_reasoning_effort is False


def test_o_series_is_reasoning_capable_but_conservative():
    capability = lookup_openai_model_capability("o3-mini")

    assert capability.family == OpenAIModelFamily.O_SERIES
    assert capability.supports_reasoning_effort is True
    assert "conservative" in capability.confidence_reason


def test_unknown_openai_looking_model_is_neutral():
    capability = lookup_openai_model_capability("gpt-unknown-future")

    assert capability.family == OpenAIModelFamily.UNKNOWN_OPENAI
    assert capability.is_known is False
    assert capability.supports_reasoning_effort is None
    assert capability.confidence == "low"
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/test_openai_capabilities.py -v
```

Expected: FAIL because `tokenverify.openai_capabilities` does not exist.

- [ ] **Step 3: Implement capability module**

Create `src/tokenverify/openai_capabilities.py`:

```python
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class OpenAIModelFamily(str, Enum):
    GPT_5 = "gpt_5"
    GPT_4_1 = "gpt_4_1"
    GPT_4O = "gpt_4o"
    O_SERIES = "o_series"
    UNKNOWN_OPENAI = "unknown_openai"
    NON_OPENAI = "non_openai"


@dataclass(frozen=True)
class OpenAIModelCapability:
    model: str
    family: OpenAIModelFamily
    is_known: bool
    supports_reasoning_effort: bool | None
    confidence: str
    confidence_reason: str


def lookup_openai_model_capability(model: str) -> OpenAIModelCapability:
    normalized = _normalize_model(model)
    if normalized.startswith("gpt-5"):
        return OpenAIModelCapability(model, OpenAIModelFamily.GPT_5, True, True, "high", "Matched known OpenAI GPT-5 family.")
    if normalized.startswith("gpt-4-1"):
        return OpenAIModelCapability(model, OpenAIModelFamily.GPT_4_1, True, False, "high", "Matched known OpenAI GPT-4.1 family.")
    if normalized.startswith("gpt-4o"):
        return OpenAIModelCapability(model, OpenAIModelFamily.GPT_4O, True, False, "high", "Matched known OpenAI GPT-4o family.")
    if normalized.startswith("o1") or normalized.startswith("o3") or normalized.startswith("o4"):
        return OpenAIModelCapability(model, OpenAIModelFamily.O_SERIES, True, True, "medium", "Matched o-series reasoning family with conservative Chat Completions assumptions.")
    if normalized.startswith("gpt-"):
        return OpenAIModelCapability(model, OpenAIModelFamily.UNKNOWN_OPENAI, False, None, "low", "Unknown OpenAI-looking model.")
    return OpenAIModelCapability(model, OpenAIModelFamily.NON_OPENAI, False, None, "high", "Model name does not look like an OpenAI model family.")


def _normalize_model(model: str) -> str:
    normalized = model.strip().lower()
    if "/" in normalized:
        normalized = normalized.rsplit("/", 1)[-1]
    return normalized.replace(".", "-")
```

- [ ] **Step 4: Run tests to verify pass**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/test_openai_capabilities.py -v
```

Expected: PASS.

---

### Task 3: Add OpenAI Probe Functions

**Files:**
- Create: `src/tokenverify/probes/openai.py`
- Test: `tests/probes/test_openai.py`

- [ ] **Step 1: Write failing probe tests**

Create `tests/probes/test_openai.py`:

```python
from tokenverify.models import ProviderEvent
from tokenverify.probes import openai as probes


def test_chat_completion_shape_match():
    result = probes.evaluate_openai_chat_completion_response(
        {"object": "chat.completion", "model": "gpt-5.1", "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]}
    )

    assert result.status == "passed"
    assert "OPENAI_CHAT_COMPLETION_SHAPE_MATCH" in result.evidence[0].tags


def test_non_openai_shape_detected():
    result = probes.evaluate_openai_chat_completion_response(
        {"type": "message", "role": "assistant", "content": [{"type": "text", "text": "ok"}]}
    )

    assert result.status == "failed"
    assert "NON_OPENAI_PROVIDER_SHAPE_DETECTED" in result.evidence[0].tags


def test_openai_model_claim_match_and_cross_provider_mismatch():
    match = probes.evaluate_openai_model_claim("gpt-5.1", {"model": "gpt-5.1-2026-02-01"})
    mismatch = probes.evaluate_openai_model_claim("gpt-5.1", {"model": "anthropic/claude-sonnet-4.5"})
    downgrade = probes.evaluate_openai_model_claim("gpt-5.1", {"model": "gpt-4o-2024-05-13"})

    assert "OPENAI_MODEL_CLAIM_MATCH" in match.evidence[0].tags
    assert "CROSS_PROVIDER_MODEL_LEAKED" in mismatch.evidence[0].tags
    assert downgrade.status == "failed"
    assert "OPENAI_MODEL_CLAIM_MISMATCH" in downgrade.evidence[0].tags


def test_openai_reasoning_capability_match_and_mismatch():
    passed = probes.evaluate_openai_reasoning_capability(
        "gpt-5.1",
        accepted_parameters=["reasoning_effort"],
        rejected_parameters=[],
        reasoning_tokens=8,
        is_trivial_prompt=False,
    )
    failed = probes.evaluate_openai_reasoning_capability("gpt-5.1", accepted_parameters=[], rejected_parameters=["reasoning_effort"])

    assert passed.status == "passed"
    assert "OPENAI_REASONING_CAPABILITY_MATCH" in passed.evidence[0].tags
    assert failed.status == "failed"
    assert "OPENAI_REASONING_CAPABILITY_MISMATCH" in failed.evidence[0].tags


def test_openai_reasoning_tokens_zero_handling():
    result_trivial = probes.evaluate_openai_reasoning_capability(
        "gpt-5.1",
        accepted_parameters=["reasoning_effort"],
        rejected_parameters=[],
        reasoning_tokens=0,
        is_trivial_prompt=True,
    )
    result_hard = probes.evaluate_openai_reasoning_capability(
        "gpt-5.1",
        accepted_parameters=["reasoning_effort"],
        rejected_parameters=[],
        reasoning_tokens=0,
        is_trivial_prompt=False,
    )

    assert result_trivial.status == "warning"
    assert result_hard.status == "failed"
    assert "OPENAI_REASONING_CAPABILITY_MISMATCH" in result_hard.evidence[0].tags


def test_openai_stream_sequence_match_and_mismatch():
    match = probes.evaluate_openai_streaming_features(
        [ProviderEvent(0.0, "chat.completion.chunk", text_length=2, data={"object": "chat.completion.chunk", "finish_reason": "stop"})]
    )
    mismatch = probes.evaluate_openai_streaming_features(
        [ProviderEvent(0.0, "message_start", data={"type": "message_start"})]
    )

    assert "OPENAI_STREAM_SEQUENCE_MATCH" in match.evidence[0].tags
    assert mismatch.status == "failed"
    assert "OPENAI_STREAM_SEQUENCE_MISMATCH" in mismatch.evidence[0].tags


def test_openai_channel_probe_distinguishes_official_and_relay():
    official = probes.evaluate_openai_channel(
        base_url="https://api.openai.com/v1",
        channel_claim="official",
        response_headers={"x-request-id": "req_123"},
    )
    relay = probes.evaluate_openai_channel(
        base_url="https://relay.example/v1",
        channel_claim="official",
        response_headers={"x-openrouter-provider": "openai"},
    )

    assert "OPENAI_OFFICIAL_CHANNEL_MATCH" in official.evidence[0].tags
    relay_tags = {tag for item in relay.evidence for tag in item.tags}
    assert "OPENAI_OFFICIAL_CHANNEL_MISMATCH" in relay_tags
    assert "RELAY_HEADER_SUSPECT" in relay_tags


def test_openai_official_host_with_relay_headers_is_not_accepted_as_clean_official():
    result = probes.evaluate_openai_channel(
        base_url="https://api.openai.com/v1",
        channel_claim="official",
        response_headers={"server": "nginx", "x-openrouter-provider": "openai"},
        error_message='{"error":{"message":"upstream failed","type":"server_error"}}',
    )

    tags = {tag for item in result.evidence for tag in item.tags}
    assert result.status == "warning"
    assert "RELAY_HEADER_SUSPECT" in tags
    assert "OPENAI_OFFICIAL_CHANNEL_MISMATCH" in tags
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/probes/test_openai.py -v
```

Expected: FAIL because `tokenverify.probes.openai` does not exist.

- [ ] **Step 3: Implement probe module**

Implement only enough logic for the tests, using existing `EvidenceItem`, `ProbeResult`, `EvidenceTag`, `RiskTag`, and `calculate_streaming_metrics`.

Required functions:

```python
def evaluate_openai_chat_completion_response(response: dict) -> ProbeResult: ...
def evaluate_openai_model_claim(claimed_model: str, response: dict) -> ProbeResult: ...
def evaluate_openai_reasoning_capability(
    model: str,
    accepted_parameters: list[str],
    rejected_parameters: list[str],
    reasoning_tokens: int | None = None,
    is_trivial_prompt: bool = False,
) -> ProbeResult: ...
def evaluate_openai_streaming_features(events: list[ProviderEvent]) -> ProbeResult: ...
def evaluate_openai_channel(base_url: str, channel_claim: str, response_headers: dict[str, str] | None = None, error_message: str | None = None) -> ProbeResult: ...
```

Implementation details:

- `evaluate_openai_model_claim` must distinguish same-family aliases from structured downgrade. `gpt-5.x` claimed with observed `gpt-4o-*` must return strong failed evidence tagged `OPENAI_MODEL_CLAIM_MISMATCH`.
- Cross-provider observed model names such as `claude-*`, `deepseek-*`, `gemini-*`, `qwen-*`, or `doubao-*` must return strong failed evidence tagged `CROSS_PROVIDER_MODEL_LEAKED`.
- `evaluate_openai_reasoning_capability` must not fail trivial prompts only because `reasoning_tokens == 0`.
- For non-trivial reasoning probes against reasoning-capable models, accepted `reasoning_effort` plus missing or zero `reasoning_tokens` must return strong failed evidence tagged `OPENAI_REASONING_CAPABILITY_MISMATCH`.
- `evaluate_openai_channel` must treat `channel_claim="official"` with a non-`api.openai.com` host as strong failed evidence tagged `OPENAI_OFFICIAL_CHANNEL_MISMATCH`.
- `evaluate_openai_channel` must treat relay headers on `api.openai.com` as channel inconsistency/risk evidence, but must not fail solely because `server: cloudflare` is absent.

- [ ] **Step 4: Run tests to verify pass**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/probes/test_openai.py -v
```

Expected: PASS.

---

### Task 4: Route OpenAI Claims Through Audit Plan

**Files:**
- Modify: `src/tokenverify/audit_plan.py`
- Test: `tests/test_audit_plan.py`

- [ ] **Step 1: Write failing routing test**

Append to `tests/test_audit_plan.py`:

```python
def test_audit_plan_routes_openai_compatible_claim():
    plan = build_audit_plan(Claim(provider="openai", api_shape="openai-compatible", model="gpt-5.1"))

    assert plan.path == "openai_openai_compatible"
    assert plan.provider == "openai"
    assert plan.api_shape == "openai-compatible"
    assert "openai_chat_completions_shape" in plan.probe_names
    assert "messages_protocol" not in plan.probe_names
```

- [ ] **Step 2: Run test to verify failure**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/test_audit_plan.py::test_audit_plan_routes_openai_compatible_claim -v
```

Expected: FAIL because OpenAI claims are still out of scope.

- [ ] **Step 3: Add OpenAI plan path**

In `src/tokenverify/audit_plan.py`, add an OpenAI-compatible probe tuple and route:

```python
_OPENAI_COMPATIBLE_PROBES = (
    "openai_chat_completions_shape",
    "openai_model_claim_consistency",
    "openai_reasoning_capability",
    "openai_channel_risk",
    "openai_compatible_streaming",
)
```

Return `AuditPlan(path="openai_openai_compatible", provider="openai", api_shape="openai-compatible", probe_names=_OPENAI_COMPATIBLE_PROBES)`.

- [ ] **Step 4: Run test to verify pass**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/test_audit_plan.py -v
```

Expected: PASS.

---

### Task 5: Integrate OpenAI Audit Flow With Mocked Observations

**Files:**
- Modify: `src/tokenverify/audit.py`
- Test: `tests/test_audit_flow.py`

- [ ] **Step 1: Write failing audit flow test**

Append to `tests/test_audit_flow.py`:

```python
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
            ProviderEvent(0.0, "chat.completion.chunk", text_length=2, data={"object": "chat.completion.chunk", "finish_reason": "stop"})
        ],
    )

    result = run_audit(runtime_config, observations=observations)

    assert result.target_summary["claimed_provider"] == "openai"
    probe_names = [probe.name for probe in result.probe_results]
    assert "openai_chat_completions_shape" in probe_names
    assert "openai_model_claim_consistency" in probe_names
    assert "openai_channel_risk" in probe_names
    assert "OPENAI_OFFICIAL_CHANNEL_MATCH" in result.verdict.tags


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
```

- [ ] **Step 2: Run test to verify failure**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/test_audit_flow.py::test_openai_compatible_claim_uses_openai_probe_path -v
```

Expected: FAIL because `run_audit` does not route to an OpenAI audit path.

- [ ] **Step 3: Implement audit path**

In `src/tokenverify/audit.py`, add `_run_openai_compatible_audit(runtime_config, observations)` that:

- Uses mocked `AuditObservations` when supplied.
- Evaluates OpenAI Chat Completions shape.
- Evaluates OpenAI model claim.
- Evaluates OpenAI reasoning capability only when accepted/rejected parameter observations are available, or returns a neutral/skipped probe.
- Evaluates OpenAI channel risk from base URL, `channel_claim`, headers, and errors.
- Evaluates OpenAI streaming features when stream events exist.
- Reuses `_result(...)` and `score_probe_results(...)`.
- Does not hand-edit rating inside the audit path. Instead, update `src/tokenverify/scoring.py` so `CROSS_PROVIDER_MODEL_LEAKED` and existing `CROSS_PROVIDER_REASONING_LEAKED` are highest-priority hard-fail tags: if either tag appears in any probe evidence, final rating must be `Rating.LOW_TRUST` and authenticity score must remain in the low-trust range.

- [ ] **Step 4: Run test to verify pass**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/test_audit_flow.py::test_openai_compatible_claim_uses_openai_probe_path -v
```

Expected: PASS.

---

### Task 6: Render OpenAI Probe Sections

**Files:**
- Modify: `src/tokenverify/report.py`
- Test: `tests/test_report.py`

- [ ] **Step 1: Write failing report test**

Append to `tests/test_report.py`:

```python
def test_markdown_renders_openai_probe_sections():
    result = replace(
        audit_result(),
        probe_results=[
            ProbeResult("openai_chat_completions_shape", "passed", [EvidenceItem("openai_chat_shape", "strong", True, "shape")]),
            ProbeResult("openai_model_claim_consistency", "passed", [EvidenceItem("openai_model_claim", "strong", True, "model")]),
            ProbeResult("openai_reasoning_capability", "skipped", []),
            ProbeResult("openai_channel_risk", "passed", [EvidenceItem("openai_official_channel", "strong", True, "official")]),
            ProbeResult("openai_compatible_streaming", "passed", [], metrics=StreamingMetrics(0.2, 1.0, [0.1], [2], 2.0, False)),
        ],
    )

    markdown = render_markdown(result)

    assert "## OpenAI Chat Completions Shape Probe" in markdown
    assert "## OpenAI Model Claim Consistency Probe" in markdown
    assert "## OpenAI Reasoning Capability Probe" in markdown
    assert "## OpenAI Channel Risk Probe" in markdown
    assert "## OpenAI-Compatible Streaming Metrics" in markdown
```

- [ ] **Step 2: Run test to verify failure**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/test_report.py::test_markdown_renders_openai_probe_sections -v
```

Expected: FAIL because report ordering/titles do not include OpenAI probe names.

- [ ] **Step 3: Add report titles and order**

Add OpenAI probe names to `PROBE_TITLES` and add an OpenAI-specific order tuple in `src/tokenverify/report.py`.

- [ ] **Step 4: Run test to verify pass**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/test_report.py::test_markdown_renders_openai_probe_sections -v
```

Expected: PASS.

---

### Task 6A: Add Cross-Provider Hard-Fail Scoring Guard

**Files:**
- Modify: `src/tokenverify/scoring.py`
- Test: `tests/test_scoring.py`

- [ ] **Step 1: Write failing scoring tests**

Append to `tests/test_scoring.py`:

```python
def test_cross_provider_model_leak_forces_low_trust_even_with_other_positive_evidence():
    rating, _, verdict = score_probe_results(
        [
            ProbeResult(
                "openai_chat_completions_shape",
                "passed",
                [EvidenceItem("openai_chat_shape", "strong", True, "shape", tags=["OPENAI_CHAT_COMPLETION_SHAPE_MATCH"])],
            ),
            ProbeResult(
                "openai_model_claim_consistency",
                "failed",
                [EvidenceItem("openai_model_claim", "strong", False, "cross provider", tags=["CROSS_PROVIDER_MODEL_LEAKED"])],
            ),
        ]
    )

    assert rating == Rating.LOW_TRUST
    assert verdict.rating == Rating.LOW_TRUST
    assert verdict.authenticity_score <= 39


def test_cross_provider_reasoning_leak_forces_low_trust_even_with_other_positive_evidence():
    rating, _, verdict = score_probe_results(
        [
            ProbeResult(
                "messages_protocol",
                "passed",
                [EvidenceItem("anthropic_messages_shape", "strong", True, "shape", tags=["ANTHROPIC_NATIVE_SHAPE_MATCH"])],
            ),
            ProbeResult(
                "reasoning_leakage",
                "failed",
                [EvidenceItem("reasoning", "strong", False, "leak", tags=["CROSS_PROVIDER_REASONING_LEAKED"])],
            ),
        ]
    )

    assert rating == Rating.LOW_TRUST
    assert verdict.authenticity_score <= 39
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/test_scoring.py::test_cross_provider_model_leak_forces_low_trust_even_with_other_positive_evidence tests/test_scoring.py::test_cross_provider_reasoning_leak_forces_low_trust_even_with_other_positive_evidence -v
```

Expected: FAIL until the hard-fail tag guard is implemented.

- [ ] **Step 3: Implement scoring guard**

In `src/tokenverify/scoring.py`, add a helper:

```python
def _has_hard_fail_tag(probe_results: list[ProbeResult]) -> bool:
    hard_fail_tags = {"CROSS_PROVIDER_MODEL_LEAKED", "CROSS_PROVIDER_REASONING_LEAKED"}
    return any(tag in hard_fail_tags for result in probe_results for item in result.evidence for tag in item.tags)
```

After inconclusive operational-error handling and after counting evidence, force:

```python
if _has_hard_fail_tag(probe_results):
    rating = Rating.LOW_TRUST
```

Keep authenticity scoring inside the existing low-trust range by reusing `_authenticity_score(rating, breakdown)`.

- [ ] **Step 4: Run tests to verify pass**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/test_scoring.py -v
```

Expected: PASS.

---

### Task 7: Update Tag Taxonomy And Probe Categories

**Files:**
- Modify: `src/tokenverify/tag_taxonomy.py`
- Modify: `src/tokenverify/probes/categories.py`
- Test: `tests/test_tag_taxonomy.py`
- Test: `tests/probes/test_categories.py`

- [ ] **Step 1: Write failing taxonomy/category tests**

Append to `tests/test_tag_taxonomy.py`:

```python
def test_openai_tags_are_classified_for_dashboard_taxonomy():
    assert classify_tag(EvidenceTag.OPENAI_CHAT_COMPLETION_SHAPE_MATCH.value) == TagTaxonomyCategory.AUTHENTICITY
    assert classify_tag(EvidenceTag.OPENAI_OFFICIAL_CHANNEL_MISMATCH.value) == TagTaxonomyCategory.RISK
    assert classify_tag(EvidenceTag.CROSS_PROVIDER_MODEL_LEAKED.value) == TagTaxonomyCategory.CROSS_PROVIDER_LEAKAGE
```

Append to `tests/probes/test_categories.py`:

```python
def test_openai_probe_names_map_to_categories():
    assert categorize_probe("openai_chat_completions_shape") == ProbeCategory.PROTOCOL
    assert categorize_probe("openai_reasoning_capability") == ProbeCategory.CAPABILITY
    assert categorize_probe("openai_compatible_streaming") == ProbeCategory.STREAM
    assert categorize_probe("openai_channel_risk") == ProbeCategory.CHANNEL_RISK
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/test_tag_taxonomy.py tests/probes/test_categories.py -v
```

Expected: FAIL because OpenAI tags/probes are not categorized.

- [ ] **Step 3: Implement taxonomy/category updates**

Add OpenAI probe names to `_CATEGORY_BY_PROBE_NAME`.

Update `tag_taxonomy()` so:

- OpenAI shape/model/reasoning/channel match tags classify as authenticity.
- `OPENAI_OFFICIAL_CHANNEL_MISMATCH` classifies as risk.
- `CROSS_PROVIDER_MODEL_LEAKED` classifies as cross-provider leakage.

- [ ] **Step 4: Run tests to verify pass**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/test_tag_taxonomy.py tests/probes/test_categories.py -v
```

Expected: PASS.

---

### Task 8: Add Example Config And Roadmap Updates

**Files:**
- Create: `examples/openai-compatible-audit.yaml`
- Modify: `docs/superpowers/plans/2026-05-28-tokenverify-roadmap-todo.md`
- Test: `tests/test_config.py`

- [ ] **Step 1: Write failing example config test**

Append to `tests/test_config.py`:

```python
def test_openai_compatible_example_config_loads():
    config = load_runtime_config(Path("examples/openai-compatible-audit.yaml"))

    assert config.endpoint.claim.provider == "openai"
    assert config.endpoint.claim.api_shape == "openai-compatible"
    assert config.endpoint.claim.channel_claim == "official"
```

- [ ] **Step 2: Run test to verify failure**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/test_config.py::test_openai_compatible_example_config_loads -v
```

Expected: FAIL because the example file does not exist.

- [ ] **Step 3: Add example config**

Create `examples/openai-compatible-audit.yaml`:

```yaml
selected_endpoint: openai
output_path: reports/openai-compatible-audit.md

endpoints:
  - name: openai
    base_url: https://api.openai.com/v1
    provider: openai
    api_shape: openai-compatible
    model: gpt-5.1
    channel_claim: official
    api_key: ${OPENAI_API_KEY}

raw_logs:
  enabled: false
```

- [ ] **Step 4: Update roadmap TODO**

In `docs/superpowers/plans/2026-05-28-tokenverify-roadmap-todo.md`, mark completed subitems only after their tests pass:

```markdown
- [ ] OpenAI official / OpenAI-compatible model auditing.
  - [x] Spec.
  - [x] Implementation plan.
  - [x] Tests.
  - [x] Implementation.
```

- [ ] **Step 5: Run test to verify pass**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/test_config.py::test_openai_compatible_example_config_loads -v
```

Expected: PASS.

---

### Task 9: Full Verification

**Files:**
- No code edits.

- [ ] **Step 1: Run full test suite**

Run:

```bash
PYTHONPATH=src python3 -m pytest -v
```

Expected: PASS, with only explicitly deselected real-network tests skipped.

- [ ] **Step 2: Run whitespace check**

Run:

```bash
git diff --check
```

Expected: no output and exit code 0.

- [ ] **Step 3: Inspect roadmap state**

Run:

```bash
sed -n '90,130p' docs/superpowers/plans/2026-05-28-tokenverify-roadmap-todo.md
```

Expected: OpenAI spec/plan/tests/implementation are checked only if all prior tasks are complete and verified.

## Self-Review Notes

- Spec coverage: provider routing, Chat Completions shape, model claim, streaming, reasoning capability, channel risk, report rendering, tests, and safety policy are covered.
- Explicit non-goals: Responses API, non-OpenAI providers, live-network tests, dashboard, batch, and JSON output remain out of scope.
- Type consistency: task names use `openai_chat_completions_shape`, `openai_model_claim_consistency`, `openai_reasoning_capability`, `openai_channel_risk`, and `openai_compatible_streaming` consistently.
