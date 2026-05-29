# DeepSeek Official And Compatible Model Audit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a mocked, test-covered audit path for endpoints claiming DeepSeek models through a Chat Completions-compatible API shape.

**Architecture:** Reuse the existing OpenAI-compatible HTTP client and repeat-sampling collection path. Add DeepSeek-specific model capability classification, focused probes, audit-plan routing, report rendering, and example configuration without implementing unrelated providers or live-network tests.

**Tech Stack:** Python 3.11+, dataclasses, enums, httpx MockTransport, pytest, existing TokenVerify CLI/report/scoring model.

---

## Execution Rules

- Implement one task at a time with TDD: write failing tests, verify failure, implement, verify pass.
- Do not implement Gemini, Seed, Qwen, Doubao, dashboard, batch mode, JSON output, or DeepSeek non-chat endpoints.
- Do not run real-network tests.
- Do not commit unless the user explicitly asks.
- Use `PYTHONPATH=src python3 -m pytest ...` for verification.
- Keep strong authenticity assertions separate from heuristic channel-risk observations.
- Use existing OpenAI-compatible provider HTTP code; do not duplicate client transport logic.

## File Structure

- Modify `src/tokenverify/models.py`: add stable DeepSeek evidence tags.
- Create `src/tokenverify/deepseek_capabilities.py`: classify DeepSeek model families and reasoning support.
- Create `src/tokenverify/probes/deepseek.py`: DeepSeek shape, model claim, R1 reasoning content, streaming, and channel probes.
- Modify `src/tokenverify/audit_plan.py`: route `Claim(provider="deepseek", api_shape="openai-compatible", ...)`.
- Modify `src/tokenverify/audit.py`: run the new DeepSeek audit path using existing OpenAI-compatible observation collection.
- Modify `src/tokenverify/report.py`: render DeepSeek probe sections and plain-language DeepSeek summary.
- Modify `src/tokenverify/tag_taxonomy.py`: classify new DeepSeek tags.
- Modify `src/tokenverify/probes/categories.py`: categorize DeepSeek probe names.
- Create `examples/deepseek-compatible-audit.yaml`: example DeepSeek official-compatible config.
- Create `tests/test_deepseek_capabilities.py`: model family and reasoning capability tests.
- Create `tests/probes/test_deepseek.py`: DeepSeek probe tests.
- Modify `tests/test_audit_plan.py`: routing tests.
- Modify `tests/test_audit_flow.py`: audit integration tests.
- Modify `tests/test_report.py`: report rendering tests.
- Modify `tests/test_models.py`: stable tag tests.
- Modify `tests/test_tag_taxonomy.py`: taxonomy tests.
- Modify `tests/probes/test_categories.py`: category tests.
- Modify `tests/test_config.py`: example config load test.
- Modify `docs/superpowers/plans/2026-05-28-tokenverify-roadmap-todo.md`: mark implementation progress only after each task passes.

---

### Task 1: Add Stable DeepSeek Tags

**Files:**
- Modify: `src/tokenverify/models.py`
- Test: `tests/test_models.py`

- [ ] **Step 1: Write failing tag tests**

Append to `tests/test_models.py`:

```python
def test_deepseek_audit_tag_values_are_stable():
    assert EvidenceTag.DEEPSEEK_CHAT_COMPLETION_SHAPE_MATCH.value == "DEEPSEEK_CHAT_COMPLETION_SHAPE_MATCH"
    assert EvidenceTag.DEEPSEEK_CHAT_COMPLETION_SHAPE_MISMATCH.value == "DEEPSEEK_CHAT_COMPLETION_SHAPE_MISMATCH"
    assert EvidenceTag.NON_DEEPSEEK_PROVIDER_SHAPE_DETECTED.value == "NON_DEEPSEEK_PROVIDER_SHAPE_DETECTED"
    assert EvidenceTag.DEEPSEEK_MODEL_CLAIM_MATCH.value == "DEEPSEEK_MODEL_CLAIM_MATCH"
    assert EvidenceTag.DEEPSEEK_MODEL_CLAIM_MISMATCH.value == "DEEPSEEK_MODEL_CLAIM_MISMATCH"
    assert EvidenceTag.DEEPSEEK_REASONING_CONTENT_MATCH.value == "DEEPSEEK_REASONING_CONTENT_MATCH"
    assert EvidenceTag.DEEPSEEK_REASONING_CONTENT_MISSING.value == "DEEPSEEK_REASONING_CONTENT_MISSING"
    assert EvidenceTag.DEEPSEEK_STREAM_SEQUENCE_MATCH.value == "DEEPSEEK_STREAM_SEQUENCE_MATCH"
    assert EvidenceTag.DEEPSEEK_STREAM_SEQUENCE_MISMATCH.value == "DEEPSEEK_STREAM_SEQUENCE_MISMATCH"
    assert EvidenceTag.DEEPSEEK_STREAM_REASONING_MATCH.value == "DEEPSEEK_STREAM_REASONING_MATCH"
    assert EvidenceTag.DEEPSEEK_STREAM_REASONING_MISSING.value == "DEEPSEEK_STREAM_REASONING_MISSING"
    assert EvidenceTag.DEEPSEEK_OFFICIAL_CHANNEL_MATCH.value == "DEEPSEEK_OFFICIAL_CHANNEL_MATCH"
    assert EvidenceTag.DEEPSEEK_OFFICIAL_CHANNEL_MISMATCH.value == "DEEPSEEK_OFFICIAL_CHANNEL_MISMATCH"
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/test_models.py::test_deepseek_audit_tag_values_are_stable -v
```

Expected: FAIL because the enum values do not exist.

- [ ] **Step 3: Add enum values**

In `src/tokenverify/models.py`, add the enum values exactly as asserted in the test.

- [ ] **Step 4: Run tests to verify pass**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/test_models.py::test_deepseek_audit_tag_values_are_stable -v
```

Expected: PASS.

---

### Task 2: Add DeepSeek Model Capability Table

**Files:**
- Create: `src/tokenverify/deepseek_capabilities.py`
- Test: `tests/test_deepseek_capabilities.py`

- [ ] **Step 1: Write failing capability tests**

Create `tests/test_deepseek_capabilities.py`:

```python
from tokenverify.deepseek_capabilities import DeepSeekModelFamily, lookup_deepseek_model_capability


def test_deepseek_r1_family_requires_reasoning_content():
    capability = lookup_deepseek_model_capability("deepseek-r1")

    assert capability.family == DeepSeekModelFamily.R1
    assert capability.is_known is True
    assert capability.expects_reasoning_content is True
    assert capability.confidence == "high"


def test_deepseek_reasoner_alias_maps_to_r1():
    capability = lookup_deepseek_model_capability("deepseek-reasoner")

    assert capability.family == DeepSeekModelFamily.R1
    assert capability.expects_reasoning_content is True


def test_deepseek_chat_family_does_not_require_reasoning_content():
    capability = lookup_deepseek_model_capability("deepseek-chat")

    assert capability.family == DeepSeekModelFamily.CHAT
    assert capability.is_known is True
    assert capability.expects_reasoning_content is False


def test_unknown_deepseek_looking_model_is_neutral():
    capability = lookup_deepseek_model_capability("deepseek-future-9")

    assert capability.family == DeepSeekModelFamily.UNKNOWN_DEEPSEEK
    assert capability.is_known is False
    assert capability.expects_reasoning_content is None


def test_non_deepseek_model_is_classified_as_non_deepseek():
    capability = lookup_deepseek_model_capability("gpt-4o")

    assert capability.family == DeepSeekModelFamily.NON_DEEPSEEK
    assert capability.is_known is False
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/test_deepseek_capabilities.py -v
```

Expected: FAIL because `tokenverify.deepseek_capabilities` does not exist.

- [ ] **Step 3: Implement capability module**

Create `src/tokenverify/deepseek_capabilities.py`:

```python
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class DeepSeekModelFamily(str, Enum):
    R1 = "r1"
    CHAT = "chat"
    UNKNOWN_DEEPSEEK = "unknown_deepseek"
    NON_DEEPSEEK = "non_deepseek"


@dataclass(frozen=True)
class DeepSeekModelCapability:
    model: str
    family: DeepSeekModelFamily
    is_known: bool
    expects_reasoning_content: bool | None
    confidence: str
    confidence_reason: str


def lookup_deepseek_model_capability(model: str) -> DeepSeekModelCapability:
    normalized = _normalize_model(model)
    if normalized.startswith("deepseek-r1") or normalized == "deepseek-reasoner":
        return DeepSeekModelCapability(model, DeepSeekModelFamily.R1, True, True, "high", "Matched known DeepSeek R1/reasoner family.")
    if normalized.startswith("deepseek-chat") or normalized.startswith("deepseek-v3"):
        return DeepSeekModelCapability(model, DeepSeekModelFamily.CHAT, True, False, "high", "Matched known DeepSeek chat/V3 family.")
    if normalized.startswith("deepseek-"):
        return DeepSeekModelCapability(model, DeepSeekModelFamily.UNKNOWN_DEEPSEEK, False, None, "low", "Unknown DeepSeek-looking model.")
    return DeepSeekModelCapability(model, DeepSeekModelFamily.NON_DEEPSEEK, False, None, "high", "Model name does not look like a DeepSeek model family.")


def _normalize_model(model: str) -> str:
    normalized = model.strip().lower()
    if "/" in normalized:
        normalized = normalized.rsplit("/", 1)[-1]
    return normalized.replace("_", "-")
```

- [ ] **Step 4: Run tests to verify pass**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/test_deepseek_capabilities.py -v
```

Expected: PASS.

---

### Task 3: Add DeepSeek Probe Functions

**Files:**
- Create: `src/tokenverify/probes/deepseek.py`
- Test: `tests/probes/test_deepseek.py`

- [ ] **Step 1: Write failing probe tests**

Create `tests/probes/test_deepseek.py`:

```python
from tokenverify.models import ProviderEvent
from tokenverify.probes import deepseek as probes


def test_deepseek_chat_completion_shape_match():
    result = probes.evaluate_deepseek_chat_completion_response(
        {"model": "deepseek-chat", "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]}
    )

    assert result.status == "passed"
    assert "DEEPSEEK_CHAT_COMPLETION_SHAPE_MATCH" in result.evidence[0].tags


def test_non_deepseek_shape_detected():
    result = probes.evaluate_deepseek_chat_completion_response(
        {"type": "message", "role": "assistant", "content": [{"type": "text", "text": "ok"}]}
    )

    assert result.status == "failed"
    assert "NON_DEEPSEEK_PROVIDER_SHAPE_DETECTED" in result.evidence[0].tags


def test_deepseek_model_claim_match_and_cross_provider_mismatch():
    match = probes.evaluate_deepseek_model_claim("deepseek-r1", {"model": "deepseek-reasoner"})
    mismatch = probes.evaluate_deepseek_model_claim("deepseek-r1", {"model": "gpt-4o"})
    downgrade = probes.evaluate_deepseek_model_claim("deepseek-r1", {"model": "deepseek-chat"})

    assert "DEEPSEEK_MODEL_CLAIM_MATCH" in match.evidence[0].tags
    assert "CROSS_PROVIDER_MODEL_LEAKED" in mismatch.evidence[0].tags
    assert downgrade.status == "failed"
    assert "DEEPSEEK_MODEL_CLAIM_MISMATCH" in downgrade.evidence[0].tags


def test_r1_reasoning_content_match_and_missing():
    match = probes.evaluate_deepseek_reasoning_content(
        "deepseek-r1",
        {"choices": [{"message": {"reasoning_content": "work", "content": "answer"}, "finish_reason": "stop"}]},
        is_trivial_prompt=False,
    )
    missing = probes.evaluate_deepseek_reasoning_content(
        "deepseek-r1",
        {"choices": [{"message": {"content": "answer"}, "finish_reason": "stop"}]},
        is_trivial_prompt=False,
    )
    chat = probes.evaluate_deepseek_reasoning_content(
        "deepseek-chat",
        {"choices": [{"message": {"content": "answer"}, "finish_reason": "stop"}]},
        is_trivial_prompt=False,
    )

    assert match.status == "passed"
    assert "DEEPSEEK_REASONING_CONTENT_MATCH" in match.evidence[0].tags
    assert missing.status == "failed"
    assert "DEEPSEEK_REASONING_CONTENT_MISSING" in missing.evidence[0].tags
    assert chat.status == "skipped"


def test_deepseek_stream_sequence_and_reasoning_delta():
    result = probes.evaluate_deepseek_streaming_features(
        "deepseek-r1",
        [
            ProviderEvent(0.0, "chat.completion.chunk", data={"choices": [{"delta": {"reasoning_content": "work"}, "finish_reason": None}]}),
            ProviderEvent(0.1, "chat.completion.chunk", data={"choices": [{"delta": {"content": "answer"}, "finish_reason": "stop"}]}),
        ],
    )

    assert result.status == "passed"
    tags = [tag for item in result.evidence for tag in item.tags]
    assert "DEEPSEEK_STREAM_SEQUENCE_MATCH" in tags
    assert "DEEPSEEK_STREAM_REASONING_MATCH" in tags


def test_deepseek_stream_sequence_interleaved_is_suspect():
    result = probes.evaluate_deepseek_streaming_features(
        "deepseek-r1",
        [
            ProviderEvent(0.0, "chat.completion.chunk", data={"choices": [{"delta": {"content": "answer"}}]}),
            ProviderEvent(0.1, "chat.completion.chunk", data={"choices": [{"delta": {"reasoning_content": "fake_thinking"}}]}),
        ],
    )

    assert result.status == "warning"
    tags = [tag for item in result.evidence for tag in item.tags]
    assert "SYNTHETIC_THINKING_SUSPECT" in tags


def test_deepseek_channel_probe_distinguishes_official_and_relay():
    official = probes.evaluate_deepseek_channel("https://api.deepseek.com/v1", "official", response_headers={})
    relay = probes.evaluate_deepseek_channel("https://relay.example/v1", "official", response_headers={"server": "nginx"})

    assert official.status == "passed"
    assert "DEEPSEEK_OFFICIAL_CHANNEL_MATCH" in official.evidence[0].tags
    assert relay.status == "failed"
    assert "DEEPSEEK_OFFICIAL_CHANNEL_MISMATCH" in relay.evidence[0].tags
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/probes/test_deepseek.py -v
```

Expected: FAIL because `tokenverify.probes.deepseek` does not exist.

- [ ] **Step 3: Implement probe module**

Create `src/tokenverify/probes/deepseek.py` with:

- `evaluate_deepseek_chat_completion_response(response: dict) -> ProbeResult`
- `evaluate_deepseek_model_claim(claimed_model: str, response: dict) -> ProbeResult`
- `evaluate_deepseek_reasoning_content(model: str, response: dict, is_trivial_prompt: bool) -> ProbeResult`
- `evaluate_deepseek_streaming_features(model: str, events: list[ProviderEvent]) -> ProbeResult`
- `evaluate_deepseek_channel(base_url: str, channel_claim: str, response_headers: dict[str, str] | None = None, error_message: str | None = None) -> ProbeResult`

Implementation rules:

- Use `lookup_deepseek_model_capability`.
- Reuse `calculate_streaming_metrics`.
- Treat non-DeepSeek observed model names as `CROSS_PROVIDER_MODEL_LEAKED`.
- Treat R1 claim with chat/V3 observed model as `DEEPSEEK_MODEL_CLAIM_MISMATCH`.
- Treat missing R1 `reasoning_content` as strong failure only for non-trivial R1 probes.
- Treat `deepseek-chat` missing reasoning content as skipped.
- Implement an R1 streaming state machine: `reasoning_content` deltas may precede `content` deltas, but `reasoning_content` after `content`, repeated reasoning/content interleaving, or a delta containing both fields must emit `SYNTHETIC_THINKING_SUSPECT`.
- Treat `channel_claim="official"` with host other than `api.deepseek.com` as strong failure.
- Treat relay markers in headers/errors as weak `RELAY_HEADER_SUSPECT` unless official host mismatch already produced strong failure.

- [ ] **Step 4: Run tests to verify pass**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/probes/test_deepseek.py -v
```

Expected: PASS.

---

### Task 4: Add Audit Plan Routing And Probe Categories

**Files:**
- Modify: `src/tokenverify/audit_plan.py`
- Modify: `src/tokenverify/probes/categories.py`
- Test: `tests/test_audit_plan.py`
- Test: `tests/probes/test_categories.py`

- [ ] **Step 1: Write failing routing and category tests**

Append to `tests/test_audit_plan.py`:

```python
def test_audit_plan_routes_deepseek_compatible_claim():
    plan = build_audit_plan(Claim(provider="deepseek", api_shape="openai-compatible", model="deepseek-r1"))

    assert plan.path == "deepseek_openai_compatible"
    assert plan.probes == (
        "deepseek_chat_completions_shape",
        "deepseek_model_claim_consistency",
        "deepseek_reasoning_content",
        "deepseek_channel_risk",
        "deepseek_compatible_streaming",
    )
```

Append to `tests/probes/test_categories.py`:

```python
def test_deepseek_probe_names_map_to_categories():
    assert categorize_probe("deepseek_chat_completions_shape") == ProbeCategory.PROTOCOL
    assert categorize_probe("deepseek_model_claim_consistency") == ProbeCategory.PROTOCOL
    assert categorize_probe("deepseek_reasoning_content") == ProbeCategory.CAPABILITY
    assert categorize_probe("deepseek_compatible_streaming") == ProbeCategory.STREAM
    assert categorize_probe("deepseek_channel_risk") == ProbeCategory.CHANNEL_RISK
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/test_audit_plan.py::test_audit_plan_routes_deepseek_compatible_claim tests/probes/test_categories.py::test_deepseek_probe_names_map_to_categories -v
```

Expected: FAIL because DeepSeek routing and categories do not exist.

- [ ] **Step 3: Implement routing and categories**

In `src/tokenverify/audit_plan.py`, add:

```python
_DEEPSEEK_COMPATIBLE_PROBES = (
    "deepseek_chat_completions_shape",
    "deepseek_model_claim_consistency",
    "deepseek_reasoning_content",
    "deepseek_channel_risk",
    "deepseek_compatible_streaming",
)
```

Then route:

```python
if provider == "deepseek" and api_shape == "openai-compatible":
    return AuditPlan("deepseek_openai_compatible", _DEEPSEEK_COMPATIBLE_PROBES)
```

In `src/tokenverify/probes/categories.py`, map:

```python
"deepseek_chat_completions_shape": ProbeCategory.PROTOCOL,
"deepseek_model_claim_consistency": ProbeCategory.PROTOCOL,
"deepseek_reasoning_content": ProbeCategory.CAPABILITY,
"deepseek_compatible_streaming": ProbeCategory.STREAM,
"deepseek_channel_risk": ProbeCategory.CHANNEL_RISK,
```

- [ ] **Step 4: Run tests to verify pass**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/test_audit_plan.py::test_audit_plan_routes_deepseek_compatible_claim tests/probes/test_categories.py::test_deepseek_probe_names_map_to_categories -v
```

Expected: PASS.

---

### Task 5: Add DeepSeek Audit Flow

**Files:**
- Modify: `src/tokenverify/audit.py`
- Modify: `src/tokenverify/scoring.py`
- Test: `tests/test_audit_flow.py`
- Test: `tests/test_scoring.py`

- [ ] **Step 1: Write failing audit flow tests**

Append to `tests/test_audit_flow.py`:

```python
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
```

Append to `tests/test_scoring.py`:

```python
def test_deepseek_reasoning_content_missing_forces_low_trust_even_with_other_positive_evidence():
    rating, breakdown, verdict = score_probe_results(
        [
            ProbeResult(
                "deepseek_chat_completions_shape",
                "passed",
                [
                    EvidenceItem(
                        "deepseek_chat_shape",
                        "strong",
                        True,
                        "shape",
                        tags=["DEEPSEEK_CHAT_COMPLETION_SHAPE_MATCH"],
                    )
                ],
            ),
            ProbeResult(
                "deepseek_reasoning_content",
                "failed",
                [
                    EvidenceItem(
                        "deepseek_reasoning_content",
                        "strong",
                        False,
                        "missing",
                        tags=["DEEPSEEK_REASONING_CONTENT_MISSING"],
                    )
                ],
            ),
        ]
    )

    assert rating == Rating.LOW_TRUST
    assert verdict.authenticity_score <= 39
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/test_audit_flow.py::test_deepseek_compatible_claim_uses_deepseek_probe_path tests/test_audit_flow.py::test_deepseek_r1_missing_reasoning_content_lowers_trust tests/test_scoring.py::test_deepseek_reasoning_content_missing_forces_low_trust_even_with_other_positive_evidence -v
```

Expected: FAIL because `run_audit` does not handle `deepseek_openai_compatible` and scoring does not hard-fail `DEEPSEEK_REASONING_CONTENT_MISSING`.

- [ ] **Step 3: Implement DeepSeek audit path**

In `src/tokenverify/audit.py`:

- Import DeepSeek probe functions.
- Route `plan.path == "deepseek_openai_compatible"` to `_run_deepseek_compatible_audit`.
- Reuse `_collect_openai_compatible_observations(runtime_config, repeat_count=repeat_count)` when observations are absent.
- In `_run_deepseek_compatible_audit`, add probe results in this order:
  - `evaluate_deepseek_chat_completion_response`
  - `evaluate_deepseek_model_claim`
  - `evaluate_deepseek_reasoning_content`
  - `evaluate_deepseek_channel`
  - `evaluate_repeated_run_variance` when repeat samples exist
  - `evaluate_deepseek_streaming_features` when stream events exist

In `src/tokenverify/scoring.py`, extend the existing hard-fail tag set to include:

```python
"DEEPSEEK_REASONING_CONTENT_MISSING"
```

This must force `Rating.LOW_TRUST` even when other strong evidence passes.

- [ ] **Step 4: Run tests to verify pass**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/test_audit_flow.py::test_deepseek_compatible_claim_uses_deepseek_probe_path tests/test_audit_flow.py::test_deepseek_r1_missing_reasoning_content_lowers_trust tests/test_scoring.py::test_deepseek_reasoning_content_missing_forces_low_trust_even_with_other_positive_evidence -v
```

Expected: PASS.

---

### Task 6: Add Report Rendering And Tag Taxonomy

**Files:**
- Modify: `src/tokenverify/report.py`
- Modify: `src/tokenverify/tag_taxonomy.py`
- Test: `tests/test_report.py`
- Test: `tests/test_tag_taxonomy.py`

- [ ] **Step 1: Write failing report and taxonomy tests**

Append to `tests/test_report.py`:

```python
def test_markdown_renders_deepseek_probe_sections():
    result = replace(
        audit_result(),
        target_summary={
            "base_url_host": "api.deepseek.com",
            "model": "deepseek-r1",
            "endpoint": "deepseek",
            "claimed_provider": "deepseek",
            "claimed_api_shape": "openai-compatible",
            "claimed_channel": "official",
        },
        probe_results=[
            ProbeResult("deepseek_chat_completions_shape", "passed", [EvidenceItem("deepseek_chat_shape", "strong", True, "shape")]),
            ProbeResult("deepseek_model_claim_consistency", "passed", [EvidenceItem("deepseek_model_claim", "strong", True, "model")]),
            ProbeResult("deepseek_reasoning_content", "passed", [EvidenceItem("deepseek_reasoning_content", "strong", True, "reasoning")]),
            ProbeResult("deepseek_channel_risk", "passed", [EvidenceItem("deepseek_official_channel", "strong", True, "official")]),
            ProbeResult("deepseek_compatible_streaming", "passed", [], metrics=StreamingMetrics(0.2, 1.0, [0.1], [2], 2.0, False)),
        ],
    )

    markdown = render_markdown(result)

    assert "## DeepSeek Chat Completions Shape Probe" in markdown
    assert "## DeepSeek Model Claim Consistency Probe" in markdown
    assert "## DeepSeek R1 Reasoning Content Probe" in markdown
    assert "## DeepSeek Channel Risk Probe" in markdown
    assert "## DeepSeek-Compatible Streaming Metrics" in markdown


def test_plain_language_summary_translates_deepseek_missing_reasoning_objectively():
    result = replace(
        audit_result(),
        target_summary={
            "base_url_host": "api.deepseek.com",
            "model": "deepseek-r1",
            "endpoint": "deepseek",
            "claimed_provider": "deepseek",
            "claimed_api_shape": "openai-compatible",
            "claimed_channel": "official",
        },
        probe_results=[
            ProbeResult(
                "deepseek_reasoning_content",
                "failed",
                [
                    EvidenceItem(
                        "deepseek_reasoning_content",
                        "strong",
                        False,
                        "missing",
                        tags=["DEEPSEEK_REASONING_CONTENT_MISSING"],
                    )
                ],
            )
        ],
        verdict=Verdict(
            rating=Rating.LOW_TRUST,
            authenticity_score=39,
            risk_score=0,
            tags=["DEEPSEEK_REASONING_CONTENT_MISSING"],
        ),
    )

    markdown = render_markdown(result)

    assert "推理能力缺失：声明为 DeepSeek R1，但未检测到原生 reasoning_content 字段，疑似被路由到不支持 R1 推理能力的模型或兼容层。" in markdown
    assert "阉割" not in markdown
    assert "挂羊头卖狗肉" not in markdown
```

Append to `tests/test_tag_taxonomy.py`:

```python
def test_deepseek_tags_are_classified_for_dashboard_taxonomy():
    assert classify_tag(EvidenceTag.DEEPSEEK_CHAT_COMPLETION_SHAPE_MATCH.value) == TagTaxonomyCategory.AUTHENTICITY
    assert classify_tag(EvidenceTag.DEEPSEEK_REASONING_CONTENT_MISSING.value) == TagTaxonomyCategory.AUTHENTICITY
    assert classify_tag(EvidenceTag.DEEPSEEK_OFFICIAL_CHANNEL_MISMATCH.value) == TagTaxonomyCategory.RISK
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/test_report.py::test_markdown_renders_deepseek_probe_sections tests/test_report.py::test_plain_language_summary_translates_deepseek_missing_reasoning_objectively tests/test_tag_taxonomy.py::test_deepseek_tags_are_classified_for_dashboard_taxonomy -v
```

Expected: FAIL because DeepSeek report sections and taxonomy classifications do not exist.

- [ ] **Step 3: Implement report and taxonomy support**

In `src/tokenverify/report.py`:

- Add DeepSeek probe titles.
- Add `DEEPSEEK_PROBE_ORDER`.
- Update `_probe_sections_for_result` to prefer DeepSeek order when DeepSeek probe names appear.
- Add `DEEPSEEK_OFFICIAL_CHANNEL_MISMATCH` to channel risk wording in the plain-language channel profile if needed.
- Add a plain-language translation for `DEEPSEEK_REASONING_CONTENT_MISSING` exactly as:

```text
推理能力缺失：声明为 DeepSeek R1，但未检测到原生 reasoning_content 字段，疑似被路由到不支持 R1 推理能力的模型或兼容层。
```

- Keep this summary wording objective and do not include terms such as `阉割` or `挂羊头卖狗肉`.

In `src/tokenverify/tag_taxonomy.py`:

- Classify `DEEPSEEK_OFFICIAL_CHANNEL_MISMATCH` as risk.
- Keep DeepSeek shape/model/reasoning/stream tags as authenticity.
- Keep `CROSS_PROVIDER_MODEL_LEAKED` in cross-provider leakage.

- [ ] **Step 4: Run tests to verify pass**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/test_report.py::test_markdown_renders_deepseek_probe_sections tests/test_report.py::test_plain_language_summary_translates_deepseek_missing_reasoning_objectively tests/test_tag_taxonomy.py::test_deepseek_tags_are_classified_for_dashboard_taxonomy -v
```

Expected: PASS.

---

### Task 7: Add Example Config And Roadmap Updates

**Files:**
- Create: `examples/deepseek-compatible-audit.yaml`
- Modify: `tests/test_config.py`
- Modify: `docs/superpowers/plans/2026-05-28-tokenverify-roadmap-todo.md`

- [ ] **Step 1: Write failing example config test**

Append to `tests/test_config.py`:

```python
def test_deepseek_compatible_example_config_loads():
    config = load_runtime_config(Path("examples/deepseek-compatible-audit.yaml"))

    assert config.endpoint.claim.provider == "deepseek"
    assert config.endpoint.claim.api_shape == "openai-compatible"
    assert config.endpoint.claim.channel_claim == "official"
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/test_config.py::test_deepseek_compatible_example_config_loads -v
```

Expected: FAIL because the example config does not exist.

- [ ] **Step 3: Add example config**

Create `examples/deepseek-compatible-audit.yaml`:

```yaml
selected_endpoint: deepseek-official
output: reports/deepseek-compatible-audit.md
raw_logs:
  enabled: false
  path: null
endpoints:
  - name: deepseek-official
    base_url: https://api.deepseek.com/v1
    provider: deepseek
    api_shape: openai-compatible
    model: deepseek-r1
    channel_claim: official
    api_key_env: DEEPSEEK_API_KEY
```

- [ ] **Step 4: Run tests to verify pass**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/test_config.py::test_deepseek_compatible_example_config_loads -v
```

Expected: PASS.

- [ ] **Step 5: Update roadmap**

In `docs/superpowers/plans/2026-05-28-tokenverify-roadmap-todo.md`, mark DeepSeek auditing `Tests` and `Implementation` only after implementation tests pass. Mark `Spec` and `Implementation plan` after this plan is accepted.

---

### Task 8: Final Verification

**Files:**
- No code files beyond prior tasks.

- [ ] **Step 1: Run full test suite**

Run:

```bash
PYTHONPATH=src python3 -m pytest -v
```

Expected: all tests pass, with any intentionally deselected tests unchanged.

- [ ] **Step 2: Run whitespace check**

Run:

```bash
git diff --check
```

Expected: no output.

- [ ] **Step 3: Inspect worktree**

Run:

```bash
git status --short --branch
```

Expected: changed files match the DeepSeek implementation scope and existing branch work.

## Self-Review

- Spec coverage: Tasks cover tags, capabilities, probes, routing, audit flow, report rendering, taxonomy, example config, roadmap update, and verification.
- Placeholder scan: No placeholder markers or "similar to" implementation gaps remain.
- Type consistency: Probe names, tag names, and helper names are consistent across tasks.
- Scope check: The plan does not implement Gemini, Seed, Qwen, Doubao, dashboard, batch mode, JSON output, or live-network tests.
