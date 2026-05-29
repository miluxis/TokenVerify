# TokenVerify Evidence, Claims, and Risk Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement structured claims, verdict scores/tags, and separated Markdown report zones for authenticity assertions and heuristic risk profile.

**Architecture:** Keep the current Claude-native audit flow intact while enriching the shared dataclasses and scoring output. Configuration normalizes endpoint metadata into a `Claim`, probes attach stable tags to evidence, scoring returns a `Verdict`, and report rendering separates strong authenticity assertions from weak risk inference.

**Tech Stack:** Python 3.11+, dataclasses, pytest, existing `tokenverify` package modules.

---

## Execution Rules

- Implement one task at a time.
- After each task, stop for user review before continuing.
- Do not add provider adapters for OpenAI, DeepSeek, Gemini, Seed, Qwen, or Doubao in this plan.
- Do not change raw logging behavior except where report rendering references existing fields.
- Do not commit changes unless the user explicitly approves a commit checkpoint.
- Use `PYTHONPATH=src python3 -m pytest ...` for verification.

## File Structure

- Modify `src/tokenverify/models.py`: add `Claim`, `Verdict`, tag enums, score fields, and backwards-compatible defaults.
- Modify `src/tokenverify/config.py`: normalize endpoint config into a `Claim`, including `api_shape` inference from URL/path hints.
- Modify `src/tokenverify/scoring.py`: return a structured `Verdict` while keeping current score breakdown behavior available.
- Modify `src/tokenverify/audit.py`: pass normalized claim into `AuditResult`, attach `Verdict`, and keep existing target summary.
- Modify `src/tokenverify/probes/messages.py`: emit evidence tags for Anthropic-native and OpenAI-compatible response shapes.
- Modify `src/tokenverify/probes/thinking.py`: emit thinking tags and detect cross-provider reasoning leakage.
- Modify `src/tokenverify/probes/streaming.py`: add risk evidence for synthetic streams with debounce-safe semantics.
- Modify `src/tokenverify/report.py`: render `Overall Verdict`, `Authenticity Assertions`, and `Heuristic Risk Profile`.
- Modify `tests/test_models.py`: cover stable tag and dataclass behavior.
- Modify `tests/test_config.py`: cover claim normalization and `api_shape` inference.
- Modify `tests/test_scoring.py`: cover separate authenticity/risk scoring and debounce behavior.
- Modify `tests/probes/test_messages.py`: cover evidence tags on protocol shape results.
- Modify `tests/probes/test_thinking.py`: cover `CROSS_PROVIDER_REASONING_LEAKED`.
- Modify `tests/probes/test_streaming.py`: cover synthetic stream risk evidence.
- Modify `tests/test_report.py`: cover new Markdown section separation and wording.
- Modify `README.md`: update the report description after tests pass.

---

### Task 1: Add Claim, Verdict, And Tag Models

**Files:**
- Modify: `src/tokenverify/models.py`
- Test: `tests/test_models.py`

- [x] **Step 1: Write failing model tests**

Add these tests to `tests/test_models.py`:

```python
from tokenverify.models import Claim, EvidenceTag, Rating, RiskTag, Verdict


def test_claim_defaults_to_anthropic_native_when_no_shape_hint_exists():
    claim = Claim(model="claude-sonnet-4-5")

    assert claim.provider == "anthropic"
    assert claim.api_shape == "native"
    assert claim.model == "claude-sonnet-4-5"
    assert claim.channel_claim == "unknown"
    assert claim.region_claim is None


def test_verdict_exposes_authenticity_and_risk_scores_separately():
    verdict = Verdict(
        rating=Rating.MEDIUM_TRUST,
        authenticity_score=78,
        risk_score=42,
        tags=[EvidenceTag.EXTENDED_THINKING_MATCH.value, RiskTag.STREAM_UNIFORMITY_SUSPECT.value],
    )

    assert verdict.rating == Rating.MEDIUM_TRUST
    assert verdict.authenticity_score == 78
    assert verdict.risk_score == 42
    assert "EXTENDED_THINKING_MATCH" in verdict.tags
    assert "STREAM_UNIFORMITY_SUSPECT" in verdict.tags


def test_tag_values_are_stable_for_dashboard_rules():
    assert EvidenceTag.CROSS_PROVIDER_REASONING_LEAKED.value == "CROSS_PROVIDER_REASONING_LEAKED"
    assert RiskTag.TTFT_VARIANCE_HIGH.value == "TTFT_VARIANCE_HIGH"
```

- [x] **Step 2: Run tests to verify failure**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/test_models.py -v
```

Expected: FAIL because `Claim`, `Verdict`, `EvidenceTag`, and `RiskTag` are not defined.

- [x] **Step 3: Implement models**

In `src/tokenverify/models.py`, add these enums and dataclasses after `Rating`:

```python
class EvidenceTag(str, Enum):
    ANTHROPIC_NATIVE_SHAPE_MATCH = "ANTHROPIC_NATIVE_SHAPE_MATCH"
    ANTHROPIC_NATIVE_SHAPE_MISMATCH = "ANTHROPIC_NATIVE_SHAPE_MISMATCH"
    OPENAI_COMPATIBLE_SHAPE_DETECTED = "OPENAI_COMPATIBLE_SHAPE_DETECTED"
    GENERIC_PROXY_ERROR_DETECTED = "GENERIC_PROXY_ERROR_DETECTED"
    ERROR_SCHEMA_MATCH = "ERROR_SCHEMA_MATCH"
    ERROR_SCHEMA_MISMATCH = "ERROR_SCHEMA_MISMATCH"
    STREAM_EVENT_SEQUENCE_MATCH = "STREAM_EVENT_SEQUENCE_MATCH"
    STREAM_EVENT_SEQUENCE_MISMATCH = "STREAM_EVENT_SEQUENCE_MISMATCH"
    EXTENDED_THINKING_MATCH = "EXTENDED_THINKING_MATCH"
    EXTENDED_THINKING_MISSING = "EXTENDED_THINKING_MISSING"
    EXTENDED_THINKING_REJECTED = "EXTENDED_THINKING_REJECTED"
    EXTENDED_THINKING_IGNORED = "EXTENDED_THINKING_IGNORED"
    MODEL_CAPABILITY_MATCH = "MODEL_CAPABILITY_MATCH"
    MODEL_CAPABILITY_MISMATCH = "MODEL_CAPABILITY_MISMATCH"
    CROSS_PROVIDER_REASONING_LEAKED = "CROSS_PROVIDER_REASONING_LEAKED"


class RiskTag(str, Enum):
    STREAM_UNIFORMITY_SUSPECT = "STREAM_UNIFORMITY_SUSPECT"
    SYNTHETIC_STREAM_SUSPECT = "SYNTHETIC_STREAM_SUSPECT"
    TTFT_VARIANCE_HIGH = "TTFT_VARIANCE_HIGH"
    THROUGHPUT_ANOMALY = "THROUGHPUT_ANOMALY"
    CONCURRENT_POOL_SUSPECT = "CONCURRENT_POOL_SUSPECT"
    WEB_REVERSE_SUSPECT = "WEB_REVERSE_SUSPECT"
    UNSTABLE_RELAY_SUSPECT = "UNSTABLE_RELAY_SUSPECT"
    HOSTED_BY_AWS = "HOSTED_BY_AWS"
    HOSTED_BY_AZURE = "HOSTED_BY_AZURE"
    HOSTED_BY_UNKNOWN_PROXY = "HOSTED_BY_UNKNOWN_PROXY"


@dataclass(frozen=True)
class Claim:
    model: str
    provider: str = "anthropic"
    api_shape: str = "native"
    channel_claim: str = "unknown"
    region_claim: str | None = None


@dataclass(frozen=True)
class Verdict:
    rating: Rating
    authenticity_score: int
    risk_score: int
    tags: list[str] = field(default_factory=list)
```

Then update existing dataclasses:

```python
@dataclass(frozen=True)
class EndpointConfig:
    name: str
    base_url: str
    model: str
    api_key: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    claim: Claim | None = None
```

```python
@dataclass(frozen=True)
class EvidenceItem:
    key: str
    weight: str
    passed: bool | None
    message: str
    details: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
```

```python
@dataclass(frozen=True)
class AuditResult:
    target_summary: dict[str, Any]
    probe_results: list[ProbeResult]
    rating: Rating
    score_breakdown: dict[str, int]
    verdict: Verdict | None = None
    claim: Claim | None = None
    report_warnings: list[str] = field(default_factory=list)
    raw_log_path: Path | None = None
    redacted_config: dict[str, Any] = field(default_factory=dict)
    extension_probe_results: list[ProbeResult] = field(default_factory=list)
```

- [x] **Step 4: Run model tests**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/test_models.py -v
```

Expected: PASS.

- [x] **Step 5: Review checkpoint**

Stop and report the changed files and test result. Continue only after user approval.

---

### Task 2: Normalize Composite Claim From Configuration

**Files:**
- Modify: `src/tokenverify/config.py`
- Test: `tests/test_config.py`

- [x] **Step 1: Write failing config tests**

Add these tests to `tests/test_config.py`:

```python
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
```

- [x] **Step 2: Run tests to verify failure**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/test_config.py -v
```

Expected: FAIL because `EndpointConfig.claim` is not populated by config loading.

- [x] **Step 3: Implement claim normalization**

In `src/tokenverify/config.py`, update imports:

```python
from tokenverify.models import Claim, EndpointConfig, RuntimeConfig
```

Add helper functions near `_optional_path`:

```python
def _build_claim(data: dict[str, Any], model: str, base_url: str) -> Claim:
    provider = str(data.get("provider") or "anthropic")
    api_shape = str(data.get("api_shape") or _infer_api_shape(base_url))
    return Claim(
        provider=provider,
        api_shape=api_shape,
        model=model,
        channel_claim=str(data.get("channel_claim") or "unknown"),
        region_claim=str(data["region_claim"]) if data.get("region_claim") else None,
    )


def _infer_api_shape(base_url: str) -> str:
    lower = base_url.lower().rstrip("/")
    if "/v1/chat/completions" in lower:
        return "openai-compatible"
    if lower.endswith("/v1") and "anthropic.com" not in lower:
        return "openai-compatible"
    return "native"
```

Update `_build_endpoint` before returning:

```python
    normalized_base_url = str(base_url).rstrip("/")
    normalized_model = str(model)
    claim = _build_claim(data, normalized_model, normalized_base_url)
    return EndpointConfig(
        name=name,
        base_url=normalized_base_url,
        model=normalized_model,
        api_key=api_key,
        headers=dict(data.get("headers") or {}),
        claim=claim,
    )
```

Update `effective["endpoint"]` in `load_runtime_config`:

```python
            "claim": {
                "provider": endpoint.claim.provider if endpoint.claim else "anthropic",
                "api_shape": endpoint.claim.api_shape if endpoint.claim else "native",
                "model": endpoint.claim.model if endpoint.claim else endpoint.model,
                "channel_claim": endpoint.claim.channel_claim if endpoint.claim else "unknown",
                "region_claim": endpoint.claim.region_claim if endpoint.claim else None,
            },
```

- [x] **Step 4: Run config tests**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/test_config.py -v
```

Expected: PASS.

- [x] **Step 5: Review checkpoint**

Stop and report the changed files and test result. Continue only after user approval.

---

### Task 3: Emit Evidence And Risk Tags From Probes

**Files:**
- Modify: `src/tokenverify/probes/messages.py`
- Modify: `src/tokenverify/probes/thinking.py`
- Modify: `src/tokenverify/probes/streaming.py`
- Test: `tests/probes/test_messages.py`
- Test: `tests/probes/test_thinking.py`
- Test: `tests/probes/test_streaming.py`

- [x] **Step 1: Write failing probe tag tests**

Add this test to `tests/probes/test_messages.py`:

```python
def test_messages_response_emits_shape_tags():
    native = evaluate_messages_response({"type": "message", "role": "assistant", "content": [{"type": "text"}]})
    openai_like = evaluate_messages_response({"choices": [{"message": {"content": "ok"}}]})

    assert "ANTHROPIC_NATIVE_SHAPE_MATCH" in native.evidence[0].tags
    assert "OPENAI_COMPATIBLE_SHAPE_DETECTED" in openai_like.evidence[0].tags
```

Add this test to `tests/probes/test_thinking.py`:

```python
def test_cross_provider_reasoning_leak_is_strong_failure():
    result = evaluate_thinking_outcome(
        model="claude-sonnet-4-5",
        response={"choices": [{"delta": {"reasoning_content": "hidden reasoning"}}]},
    )

    assert result.status == "failed"
    assert result.evidence[0].passed is False
    assert "CROSS_PROVIDER_REASONING_LEAKED" in result.evidence[0].tags
```

Add this test to `tests/probes/test_streaming.py`:

```python
def test_synthetic_stream_probe_emits_risk_tags():
    events = [
        ProviderEvent(0.0, "message_start"),
        ProviderEvent(0.01, "content_block_delta", text_length=20),
        ProviderEvent(0.02, "content_block_delta", text_length=20),
        ProviderEvent(0.03, "content_block_delta", text_length=20),
        ProviderEvent(0.04, "content_block_delta", text_length=20),
        ProviderEvent(0.05, "content_block_delta", text_length=20),
    ]

    result = evaluate_streaming_features(events)

    assert result.status == "warning"
    assert result.evidence[0].weight == "weak"
    assert result.evidence[0].passed is False
    assert "SYNTHETIC_STREAM_SUSPECT" in result.evidence[0].tags
    assert "STREAM_UNIFORMITY_SUSPECT" in result.evidence[0].tags
```

- [x] **Step 2: Run probe tests to verify failure**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/probes/test_messages.py tests/probes/test_thinking.py tests/probes/test_streaming.py -v
```

Expected: FAIL because tags and `evaluate_streaming_features` are not implemented.

- [x] **Step 3: Implement message probe tags**

In `src/tokenverify/probes/messages.py`, import `EvidenceTag`:

```python
from tokenverify.models import EvidenceItem, EvidenceTag, ProbeResult
```

For native pass evidence, add:

```python
tags=[EvidenceTag.ANTHROPIC_NATIVE_SHAPE_MATCH.value],
```

For non-native failure evidence, add:

```python
tags=[
    EvidenceTag.OPENAI_COMPATIBLE_SHAPE_DETECTED.value
    if looks_openai
    else EvidenceTag.ANTHROPIC_NATIVE_SHAPE_MISMATCH.value
],
```

- [x] **Step 4: Implement reasoning leakage detection**

In `src/tokenverify/probes/thinking.py`, import `EvidenceTag`:

```python
from tokenverify.models import EvidenceItem, EvidenceTag, ProbeResult
```

At the start of `evaluate_thinking_outcome`, after capability lookup, add:

```python
    if response and _contains_cross_provider_reasoning(response):
        return ProbeResult(
            name="extended_thinking",
            status="failed",
            evidence=[
                EvidenceItem(
                    key="cross_provider_reasoning_leaked",
                    weight="strong",
                    passed=False,
                    message="Response exposed provider-specific reasoning content that contradicts the claimed Claude boundary.",
                    tags=[EvidenceTag.CROSS_PROVIDER_REASONING_LEAKED.value],
                )
            ],
        )
```

Add helper:

```python
def _contains_cross_provider_reasoning(response: dict) -> bool:
    choices = response.get("choices")
    if isinstance(choices, list):
        for choice in choices:
            if not isinstance(choice, dict):
                continue
            delta = choice.get("delta")
            message = choice.get("message")
            if isinstance(delta, dict) and "reasoning_content" in delta:
                return True
            if isinstance(message, dict) and "reasoning_content" in message:
                return True
    return False
```

Add tags to existing Extended Thinking evidence:

```python
tags=[EvidenceTag.EXTENDED_THINKING_REJECTED.value]
```

for expected rejection, and:

```python
tags=[EvidenceTag.EXTENDED_THINKING_MATCH.value]
```

for observed thinking block, and:

```python
tags=[EvidenceTag.EXTENDED_THINKING_MISSING.value]
```

for expected thinking missing.

- [x] **Step 5: Implement streaming probe wrapper**

In `src/tokenverify/probes/streaming.py`, import `EvidenceItem`, `ProbeResult`, and `RiskTag`:

```python
from tokenverify.models import EvidenceItem, ProbeResult, ProviderEvent, RiskTag, StreamingMetrics
```

Add:

```python
def evaluate_streaming_features(events: list[ProviderEvent]) -> ProbeResult:
    metrics = calculate_streaming_metrics(events)
    evidence: list[EvidenceItem] = []
    if metrics.is_synthetic_stream:
        evidence.append(
            EvidenceItem(
                key="synthetic_stream_heuristic",
                weight="weak",
                passed=False,
                message="Stream chunks were uniformly sized and emitted in a short burst; this is a heuristic risk indicator, not proof of provider forgery.",
                tags=[RiskTag.SYNTHETIC_STREAM_SUSPECT.value, RiskTag.STREAM_UNIFORMITY_SUSPECT.value],
            )
        )
    return ProbeResult(
        name="streaming_features",
        status="warning" if metrics.is_synthetic_stream else "passed",
        evidence=evidence,
        metrics=metrics,
    )
```

- [x] **Step 6: Run probe tests**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/probes/test_messages.py tests/probes/test_thinking.py tests/probes/test_streaming.py -v
```

Expected: PASS.

- [x] **Step 7: Review checkpoint**

Stop and report the changed files and test result. Continue only after user approval.

---

### Task 4: Return Structured Verdict With Separate Scores

**Files:**
- Modify: `src/tokenverify/scoring.py`
- Modify: `src/tokenverify/audit.py`
- Test: `tests/test_scoring.py`
- Test: `tests/test_audit_flow.py`

- [x] **Step 1: Write failing scoring tests**

Add these tests to `tests/test_scoring.py`:

```python
def test_score_probe_results_returns_structured_verdict():
    rating, breakdown, verdict = score_probe_results(
        [
            ProbeResult(
                "messages_protocol",
                "passed",
                [EvidenceItem("anthropic_messages_shape", "strong", True, "ok", tags=["ANTHROPIC_NATIVE_SHAPE_MATCH"])],
            ),
            ProbeResult(
                "extended_thinking",
                "passed",
                [EvidenceItem("extended_thinking_expected", "strong", True, "ok", tags=["EXTENDED_THINKING_MATCH"])],
            ),
        ]
    )

    assert rating == Rating.HIGH_TRUST
    assert verdict.rating == Rating.HIGH_TRUST
    assert verdict.authenticity_score >= 90
    assert verdict.risk_score == 0
    assert "ANTHROPIC_NATIVE_SHAPE_MATCH" in verdict.tags


def test_high_risk_does_not_automatically_lower_authenticity_rating():
    rating, breakdown, verdict = score_probe_results(
        [
            ProbeResult("messages_protocol", "passed", [strong_evidence("anthropic_messages_shape", True)]),
            ProbeResult("extended_thinking", "passed", [strong_evidence("extended_thinking_expected", True)]),
            ProbeResult(
                "streaming_features",
                "warning",
                [
                    EvidenceItem(
                        "synthetic_stream_heuristic",
                        "weak",
                        False,
                        "synthetic stream suspected",
                        tags=["SYNTHETIC_STREAM_SUSPECT", "STREAM_UNIFORMITY_SUSPECT"],
                    )
                ],
            ),
        ]
    )

    assert rating == Rating.HIGH_TRUST
    assert verdict.rating == Rating.HIGH_TRUST
    assert verdict.authenticity_score >= 90
    assert verdict.risk_score > 0


def test_single_network_timeout_is_inconclusive_without_risk_score_spike():
    rating, breakdown, verdict = score_probe_results(
        [ProbeResult("streaming_features", "error", errors=["stream timeout after 5 seconds"])]
    )

    assert rating == Rating.INCONCLUSIVE
    assert verdict.rating == Rating.INCONCLUSIVE
    assert verdict.risk_score == 0
    assert "TTFT_VARIANCE_HIGH" not in verdict.tags
```

Update existing unpacking in `tests/test_scoring.py` from:

```python
rating, breakdown = score_probe_results(...)
```

to:

```python
rating, breakdown, verdict = score_probe_results(...)
```

where needed.

- [x] **Step 2: Run scoring tests to verify failure**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/test_scoring.py -v
```

Expected: FAIL because `score_probe_results` returns two values.

- [x] **Step 3: Implement structured verdict scoring**

In `src/tokenverify/scoring.py`, update imports:

```python
from tokenverify.models import ProbeResult, Rating, Verdict
```

Change function signature:

```python
def score_probe_results(probe_results: list[ProbeResult]) -> tuple[Rating, dict[str, int], Verdict]:
```

Inside the function, if inconclusive:

```python
    if _is_inconclusive(probe_results):
        verdict = Verdict(rating=Rating.INCONCLUSIVE, authenticity_score=0, risk_score=0, tags=_collect_tags(probe_results))
        return Rating.INCONCLUSIVE, breakdown, verdict
```

After computing breakdown and rating, add:

```python
    authenticity_score = _authenticity_score(rating, breakdown)
    risk_score = _risk_score(probe_results)
    verdict = Verdict(
        rating=rating,
        authenticity_score=authenticity_score,
        risk_score=risk_score,
        tags=_collect_tags(probe_results),
    )
    return rating, breakdown, verdict
```

Add helpers:

```python
def _is_inconclusive(probe_results: list[ProbeResult]) -> bool:
    if not probe_results:
        return True
    inconclusive_markers = (
        "authentication",
        "authorization",
        "quota",
        "model-not-found",
        "service unavailable",
        "rate limit",
        "too many requests",
        "try again later",
        "timeout",
        "timed out",
        "disconnect",
        "connection reset",
        "network",
    )
    for result in probe_results:
        joined_errors = " ".join(result.errors).lower()
        if result.status == "error" and any(marker in joined_errors for marker in inconclusive_markers):
            return True
    return False


def _authenticity_score(rating: Rating, breakdown: dict[str, int]) -> int:
    if rating == Rating.INCONCLUSIVE:
        return 0
    score = 50
    score += min(breakdown["strong_passed"] * 25, 50)
    score -= min(breakdown["strong_failed"] * 50, 100)
    if rating == Rating.HIGH_TRUST:
        return max(score, 90)
    if rating == Rating.MEDIUM_TRUST:
        return max(min(score, 89), 50)
    if rating == Rating.LOW_TRUST:
        return min(score, 39)
    return 0


def _risk_score(probe_results: list[ProbeResult]) -> int:
    weak_failures = 0
    for result in probe_results:
        for item in result.evidence:
            if item.weight == "weak" and item.passed is False:
                weak_failures += 1
    return min(weak_failures * 25, 100)


def _collect_tags(probe_results: list[ProbeResult]) -> list[str]:
    tags: list[str] = []
    for result in probe_results:
        for item in result.evidence:
            for tag in item.tags:
                if tag not in tags:
                    tags.append(tag)
    return tags
```

- [x] **Step 4: Update audit integration**

In `src/tokenverify/audit.py`, update imports:

```python
from tokenverify.probes.streaming import evaluate_streaming_features
```

Replace streaming probe construction with:

```python
        probe_results.append(evaluate_streaming_features(observations.stream_events))
```

Update scoring calls:

```python
        rating, breakdown, verdict = score_probe_results(probe_results)
        return _result(runtime_config, probe_results, rating, breakdown, verdict)
```

and:

```python
    rating, breakdown, verdict = score_probe_results(probe_results)
    return _result(runtime_config, probe_results, rating, breakdown, verdict)
```

Update `_result` signature:

```python
def _result(runtime_config, probe_results: list[ProbeResult], rating, breakdown: dict[str, int], verdict) -> AuditResult:
```

Add:

```python
    claim = runtime_config.endpoint.claim
```

Return `AuditResult` with:

```python
        verdict=verdict,
        claim=claim,
```

and include claim fields in `target_summary`:

```python
            "claimed_provider": claim.provider if claim else "anthropic",
            "claimed_api_shape": claim.api_shape if claim else "native",
            "claimed_model": claim.model if claim else runtime_config.endpoint.model,
            "claimed_channel": claim.channel_claim if claim else "unknown",
            "claimed_region": claim.region_claim if claim else None,
```

- [x] **Step 5: Run scoring and audit flow tests**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/test_scoring.py tests/test_audit_flow.py -v
```

Expected: PASS after updating test unpacking and any direct `AuditResult` constructors that need `verdict` or `claim` defaults.

- [x] **Step 6: Review checkpoint**

Stop and report the changed files and test result. Continue only after user approval.

---

### Task 5: Render Separated Markdown Report Zones

**Files:**
- Modify: `src/tokenverify/report.py`
- Test: `tests/test_report.py`

- [x] **Step 1: Write failing report tests**

Add these tests to `tests/test_report.py`:

```python
def test_markdown_separates_authenticity_assertions_from_risk_profile():
    markdown = render_markdown(audit_result())

    assert "## Authenticity Assertions" in markdown
    assert "## Heuristic Risk Profile" in markdown
    assert markdown.index("## Authenticity Assertions") < markdown.index("## Heuristic Risk Profile")


def test_risk_profile_uses_score_language_not_probability_or_accusation():
    markdown = render_markdown(audit_result())

    assert "Risk score" in markdown
    assert "probability" not in markdown.lower()
    assert "风险概率" not in markdown
    assert "定罪" not in markdown
```

Update `audit_result()` in `tests/test_report.py` to pass a verdict:

```python
from tokenverify.models import AuditResult, EvidenceItem, ProbeResult, Rating, StreamingMetrics, Verdict
```

and:

```python
verdict=Verdict(
    rating=Rating.MEDIUM_TRUST,
    authenticity_score=78,
    risk_score=25,
    tags=["ANTHROPIC_NATIVE_SHAPE_MATCH", "SYNTHETIC_STREAM_SUSPECT"],
),
```

- [x] **Step 2: Run report tests to verify failure**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/test_report.py -v
```

Expected: FAIL because the new report sections do not exist.

- [x] **Step 3: Implement Overall Verdict rendering**

In `src/tokenverify/report.py`, replace the current `Overall Rating` block with:

```python
    verdict = result.verdict
    lines.extend(
        [
            "",
            "## Overall Verdict",
            "",
            f"- Rating: **{result.rating.value}**",
            f"- Authenticity score: {verdict.authenticity_score if verdict else 'n/a'}",
            f"- Risk score: {verdict.risk_score if verdict else 'n/a'}",
            f"- Tags: {', '.join(verdict.tags) if verdict and verdict.tags else 'None'}",
            "",
            "Authenticity score measures how well the endpoint matches the claimed provider/API/model behavior.",
            "Risk score measures heuristic channel-health and relay-risk symptoms.",
            "",
            "## Evidence Score Breakdown",
        ]
    )
```

- [x] **Step 4: Implement Authenticity Assertions rendering**

Add helper:

```python
def _authenticity_assertions_section(probes: list[ProbeResult]) -> list[str]:
    lines = ["", "## Authenticity Assertions"]
    assertions = [
        item
        for probe in probes
        for item in probe.evidence
        if item.weight == "strong" or item.weight == "neutral"
    ]
    if not assertions:
        return lines + ["", "- No strong authenticity assertions were produced."]
    lines.append("")
    for item in assertions:
        state = "pass" if item.passed is True else "fail" if item.passed is False else "neutral"
        tags = f" Tags: {', '.join(item.tags)}." if item.tags else ""
        lines.append(f"- `{item.key}` ({item.weight}, {state}): {item.message}{tags}")
    return lines
```

Call it before probe detail sections:

```python
    lines.extend(_authenticity_assertions_section(result.probe_results))
```

- [x] **Step 5: Implement Heuristic Risk Profile rendering**

Update imports:

```python
from tokenverify.models import AuditResult, ProbeResult, RiskTag, StreamingMetrics
```

Add helper:

```python
def _heuristic_risk_section(result: AuditResult) -> list[str]:
    risk_items = [
        item
        for probe in result.probe_results
        for item in probe.evidence
        if item.weight == "weak"
    ]
    verdict = result.verdict
    lines = [
        "",
        "## Heuristic Risk Profile",
        "",
        f"- Risk score: {verdict.risk_score if verdict else 'n/a'}",
    ]
    known_risk_tags = {tag.value for tag in RiskTag}
    risk_tags = [tag for tag in (verdict.tags if verdict else []) if tag in known_risk_tags]
    lines.append(f"- Risk tags: {', '.join(risk_tags) if risk_tags else 'None'}")
    lines.append("- These signals are heuristic channel-risk indicators. They can raise operational concern, but they do not by themselves prove provider forgery or unauthorized routing.")
    if risk_items:
        for item in risk_items:
            state = "pass" if item.passed is True else "fail" if item.passed is False else "neutral"
            tags = f" Tags: {', '.join(item.tags)}." if item.tags else ""
            lines.append(f"- `{item.key}` ({state}): {item.message}{tags}")
    else:
        lines.append("- No heuristic risk indicators were produced.")
    return lines
```

Call it after authenticity assertions:

```python
    lines.extend(_heuristic_risk_section(result))
```

- [x] **Step 6: Run report tests**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/test_report.py -v
```

Expected: PASS.

- [x] **Step 7: Review checkpoint**

Stop and report the changed files and test result. Continue only after user approval.

---

### Task 6: Update Documentation And Run Full Verification

**Files:**
- Modify: `README.md`
- Verify: full test suite

- [x] **Step 1: Update README report description**

In `README.md`, update `Report Ratings` to explain:

```markdown
The Markdown report separates two kinds of conclusions:

- `Authenticity Assertions`: protocol, error schema, model capability, and thinking/reasoning block evidence that can support strong authenticity judgments.
- `Heuristic Risk Profile`: timing, streaming regularity, synthetic stream, pooling, and channel-health symptoms. These produce a 0-100 risk score, not a probability and not a direct accusation.
```

Add to the report ratings section:

```markdown
The report also includes:

- `authenticity_score`: 0-100, derived from strong evidence against the configured claim.
- `risk_score`: 0-100, derived from weak channel-health heuristics.
- `tags`: stable labels such as `ANTHROPIC_NATIVE_SHAPE_MATCH`, `CROSS_PROVIDER_REASONING_LEAKED`, or `SYNTHETIC_STREAM_SUSPECT` for future dashboard and routing use.
```

- [x] **Step 2: Run focused tests**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/test_models.py tests/test_config.py tests/test_scoring.py tests/test_report.py tests/probes/test_messages.py tests/probes/test_thinking.py tests/probes/test_streaming.py -v
```

Expected: PASS.

- [x] **Step 3: Run full test suite**

Run:

```bash
PYTHONPATH=src python3 -m pytest -v
```

Expected: PASS, with real-network tests skipped unless explicitly enabled by the existing test configuration.

- [x] **Step 4: Generate an example report with mocked or existing config if tests support it**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/test_audit_flow.py tests/test_cli.py -v
```

Expected: PASS.

- [x] **Step 5: Final review checkpoint**

Stop and report:

- Files changed.
- Tests run and results.
- Any behavior intentionally left out of scope, especially non-Claude providers and dashboard/JSON output.

Continue to commit or PR work only if the user explicitly asks.

---

## Plan Self-Review

Spec coverage:

- Markdown visual separation is covered by Task 5.
- Composite `Claim` is covered by Tasks 1 and 2.
- `Verdict` with rating, scores, and tags is covered by Tasks 1 and 4.
- Evidence tags and risk tags are covered by Tasks 1, 3, and 4.
- `CROSS_PROVIDER_REASONING_LEAKED` is covered by Tasks 1 and 3.
- `api_shape` fallback inference is covered by Task 2.
- Risk-score debounce semantics are covered by Task 3 and Task 4 through weak evidence treatment and no direct risk increase for network errors.
- DeepSeek priority is documented in the spec and deliberately not implemented in this plan.

Placeholder scan:

- This plan contains no `TBD`, `TODO`, or "implement later" placeholders.
- All test commands are explicit.
- Each code-changing task includes concrete code snippets and expected test outcomes.

Execution handoff:

- Because the user requested review after each step, implement this plan sequentially with review checkpoints.
- Use subagent-driven development only after the user approves this plan and approves entering implementation.
