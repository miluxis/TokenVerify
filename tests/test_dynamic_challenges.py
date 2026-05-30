from pathlib import Path

import httpx
from typer.testing import CliRunner

from tokenverify.audit import run_audit
from tokenverify.cli import app
from tokenverify.config import load_runtime_config
from tokenverify.dynamic_challenges import (
    ChallengePackError,
    evaluate_verifier,
    generate_variables,
    load_challenge_pack,
    load_default_challenge_pack,
    run_dynamic_challenges,
    safe_eval_expression,
    select_challenges,
)
from tokenverify.models import Rating
from tokenverify.providers.openai_compatible import OpenAICompatibleProviderAdapter
from tokenverify.report import render_markdown


def write_config(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "audit.yaml"
    path.write_text(content, encoding="utf-8")
    return path


def test_loads_local_pack_and_filters_by_level(tmp_path):
    pack_path = tmp_path / "pack.yaml"
    pack_path.write_text(
        """
id: local-pack
version: "2026.05"
challenges:
  - id: basic-exact
    category: arithmetic
    level: basic
    prompt: "Answer with {{x}}."
    variables:
      x:
        type: integer
        min: 1
        max: 9
    verifiers:
      - type: exact_answer
        equals_expression: x
  - id: strict-json
    category: json_shape
    level: strict
    prompt: "Return JSON."
    verifiers:
      - type: required_field
        path: answer
""",
        encoding="utf-8",
    )

    pack = load_challenge_pack(pack_path)

    assert pack.id == "local-pack"
    assert pack.version == "2026.05"
    assert [challenge.id for challenge in select_challenges(pack, "basic")] == ["basic-exact"]
    assert [challenge.id for challenge in select_challenges(pack, "strict")] == ["basic-exact", "strict-json"]


def test_invalid_pack_schema_fails_before_requests(tmp_path):
    pack_path = tmp_path / "bad-pack.yaml"
    pack_path.write_text("id: missing-challenges\nversion: '1'\n", encoding="utf-8")

    try:
        load_challenge_pack(pack_path)
    except ChallengePackError as exc:
        assert "challenges" in str(exc)
    else:
        raise AssertionError("expected ChallengePackError")


def test_deterministic_variables_are_endpoint_scoped_and_reproducible(tmp_path):
    pack_path = tmp_path / "pack.yaml"
    pack_path.write_text(
        """
id: seed-pack
version: "1"
challenges:
  - id: arithmetic
    category: arithmetic
    level: basic
    prompt: "Compute."
    variables:
      a:
        type: integer
        min: 10
        max: 99
      nonce:
        type: hex
        bytes: 4
      color:
        type: choice
        values: [red, blue, green]
    verifiers:
      - type: exact_answer
        equals_expression: a
""",
        encoding="utf-8",
    )
    pack = load_challenge_pack(pack_path)
    challenge = pack.challenges[0]

    first = generate_variables(pack, challenge, "primary")
    second = generate_variables(pack, challenge, "primary")
    different_endpoint = generate_variables(pack, challenge, "secondary")

    assert first == second
    assert first != different_endpoint
    assert 10 <= first["a"] <= 99
    assert len(first["nonce"]) == 8
    assert first["color"] in {"red", "blue", "green"}


def test_deterministic_seed_uses_stable_field_separators(tmp_path):
    first_pack_path = tmp_path / "first.yaml"
    first_pack_path.write_text(
        """
id: tv1
version: "0.1"
challenges:
  - id: c
    category: arithmetic
    level: basic
    prompt: "Compute."
    variables:
      x:
        type: integer
        min: 1
        max: 1000000
    verifiers:
      - type: exact_answer
        equals_expression: x
""",
        encoding="utf-8",
    )
    second_pack_path = tmp_path / "second.yaml"
    second_pack_path.write_text(
        """
id: tv
version: "10.1"
challenges:
  - id: c
    category: arithmetic
    level: basic
    prompt: "Compute."
    variables:
      x:
        type: integer
        min: 1
        max: 1000000
    verifiers:
      - type: exact_answer
        equals_expression: x
""",
        encoding="utf-8",
    )
    first_pack = load_challenge_pack(first_pack_path)
    second_pack = load_challenge_pack(second_pack_path)

    assert generate_variables(first_pack, first_pack.challenges[0], "primary") != generate_variables(
        second_pack,
        second_pack.challenges[0],
        "primary",
    )


def test_safe_expression_evaluator_rejects_code_execution():
    assert safe_eval_expression("a * b + c", {"a": 6, "b": 7, "c": 1}) == 43

    for expression in [
        "__import__('os').system('echo unsafe')",
        "a + (lambda x: x)(b)",
        "a.__class__",
        "values[0]",
    ]:
        try:
            safe_eval_expression(expression, {"a": 1, "b": 2, "values": [1]})
        except ChallengePackError as exc:
            assert "unsupported expression node" in str(exc)
        else:
            raise AssertionError("expected unsafe expression rejection")


def test_malicious_expression_marks_challenge_failed_not_inconclusive(tmp_path):
    pack_path = tmp_path / "pack.yaml"
    pack_path.write_text(
        """
id: malicious-pack
version: "1"
challenges:
  - id: malicious-expression
    category: arithmetic
    level: basic
    prompt: "Reply with 1."
    variables:
      a:
        type: integer
        min: 1
        max: 1
    verifiers:
      - type: exact_answer
        equals_expression: "a.__class__"
""",
        encoding="utf-8",
    )

    class StaticAdapter:
        def create_probe_response(self, model, prompt, max_tokens=64):
            return {"choices": [{"message": {"content": "1"}}]}

    results = run_dynamic_challenges(
        pack=load_challenge_pack(pack_path),
        level="basic",
        endpoint_name="primary",
        model="gpt-5.1",
        adapter=StaticAdapter(),
    )

    assert results[0].status == "failed"
    assert results[0].verifier_results[0].status == "failed"


def test_local_verifiers_cover_exact_fields_json_shape_and_stream_ordering():
    variables = {"a": 6, "b": 7, "c": 1}

    exact = evaluate_verifier({"type": "exact_answer", "equals_expression": "a * b + c"}, "43", [], variables)
    required = evaluate_verifier({"type": "required_field", "path": "answer"}, '{"answer": 43}', [], variables)
    forbidden = evaluate_verifier({"type": "forbidden_field", "path": "debug"}, '{"answer": 43}', [], variables)
    schema = evaluate_verifier(
        {
            "type": "json_schema",
            "schema": {
                "type": "object",
                "required": ["answer"],
                "properties": {"answer": {"type": "integer"}},
            },
        },
        '{"answer": 43}',
        [],
        variables,
    )
    stream = evaluate_verifier(
        {"type": "stream_ordering", "sequence": ["start", "delta", "stop"]},
        "",
        [
            {"event_type": "start"},
            {"event_type": "delta"},
            {"event_type": "stop"},
        ],
        variables,
    )

    assert [exact.status, required.status, forbidden.status, schema.status, stream.status] == [
        "passed",
        "passed",
        "passed",
        "passed",
        "passed",
    ]
    assert exact.message == "Passed: Structure match & Local math verified."


def test_stream_ordering_reasoning_before_content_ignores_empty_initial_chunks():
    result = evaluate_verifier(
        {"type": "stream_ordering", "mode": "reasoning_before_content"},
        "",
        [
            {"event_type": "chat.completion.chunk", "data": {"choices": [{"delta": {"content": ""}}]}},
            {"event_type": "chat.completion.chunk", "data": {"choices": [{"delta": {"reasoning_content": "work"}}]}},
            {"event_type": "chat.completion.chunk", "data": {"choices": [{"delta": {"content": "answer"}}]}},
        ],
        {},
    )

    assert result.status == "passed"
    assert result.message == "Passed: Structure match & Local math verified."


def test_verifier_failure_uses_sanitized_neutral_message():
    result = evaluate_verifier({"type": "exact_answer", "value": "43"}, "42", [], {})

    assert result.status == "failed"
    assert result.message == "Failed: Output failed to validate against local constraints."


def test_default_baseline_pack_is_public_and_basic():
    pack = load_default_challenge_pack()

    assert pack.id == "tokenverify-baseline"
    assert pack.version
    assert select_challenges(pack, "basic")
    assert "api_key" not in str(pack).lower()
    assert "secret" not in str(pack).lower()


def test_no_key_dynamic_challenges_are_auxiliary_and_do_not_change_score(tmp_path):
    config_path = write_config(
        tmp_path,
        """
selected_endpoint: primary
endpoints:
  - name: primary
    base_url: https://relay.example/v1
    provider: openai
    api_shape: openai-compatible
    model: gpt-5.1
""",
    )
    runtime_config = load_runtime_config(config_path)
    base_result = run_audit(runtime_config)

    result = run_audit(runtime_config, challenge_level="basic")

    assert result.rating == base_result.rating == Rating.INCONCLUSIVE
    assert result.score_breakdown == base_result.score_breakdown
    assert result.verdict.authenticity_score == base_result.verdict.authenticity_score
    assert result.dynamic_challenge_results
    assert {challenge.status for challenge in result.dynamic_challenge_results} <= {"skipped", "inconclusive"}


def test_mocktransport_executes_challenge_without_public_network(tmp_path):
    pack_path = tmp_path / "pack.yaml"
    pack_path.write_text(
        """
id: mock-pack
version: "1"
challenges:
  - id: exact-response
    category: arithmetic
    level: basic
    prompt: "Reply with exactly 43."
    verifiers:
      - type: exact_answer
        value: "43"
""",
        encoding="utf-8",
    )

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url == "https://relay.example/v1/chat/completions"
        return httpx.Response(
            200,
            json={"model": "gpt-5.1", "choices": [{"message": {"content": "43"}}]},
        )

    adapter = OpenAICompatibleProviderAdapter(
        base_url="https://relay.example/v1",
        api_key="TOKEN_PLACEHOLDER",
        transport=httpx.MockTransport(handler),
    )

    results = run_dynamic_challenges(
        pack=load_challenge_pack(pack_path),
        level="basic",
        endpoint_name="primary",
        model="gpt-5.1",
        adapter=adapter,
    )

    assert len(results) == 1
    assert results[0].status == "passed"


def test_cli_accepts_challenge_pack_and_level_without_lowering_score(tmp_path, monkeypatch):
    config_path = write_config(
        tmp_path,
        """
selected_endpoint: primary
output: audit.md
endpoints:
  - name: primary
    base_url: https://relay.example/v1
    provider: openai
    api_shape: openai-compatible
    model: gpt-5.1
""",
    )
    pack_path = tmp_path / "pack.yaml"
    pack_path.write_text(
        """
id: cli-pack
version: "1"
challenges:
  - id: cli-basic
    category: arithmetic
    level: basic
    prompt: "Reply with 1."
    verifiers:
      - type: exact_answer
        value: "1"
""",
        encoding="utf-8",
    )
    output_path = tmp_path / "out.md"
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "audit",
            "--config",
            str(config_path),
            "--output",
            str(output_path),
            "--challenge-pack",
            str(pack_path),
            "--challenge-level",
            "basic",
        ],
    )

    assert result.exit_code == 3
    markdown = output_path.read_text(encoding="utf-8")
    assert "## Dynamic Challenge Results" in markdown
    assert "cli-basic" in markdown
    assert "Reply with 1" not in markdown


def test_cli_rejects_invalid_challenge_level(tmp_path):
    config_path = write_config(
        tmp_path,
        """
selected_endpoint: primary
endpoints:
  - name: primary
    base_url: https://relay.example/v1
    model: claude-sonnet-4-5
""",
    )
    runner = CliRunner()

    result = runner.invoke(app, ["audit", "--config", str(config_path), "--challenge-level", "extreme"])

    assert result.exit_code == 2
    assert "--challenge-level must be basic, standard, or strict" in result.output


def test_report_sanitizes_dynamic_challenge_outputs(tmp_path):
    config_path = write_config(
        tmp_path,
        """
selected_endpoint: primary
endpoints:
  - name: primary
    base_url: https://api.anthropic.com
    model: claude-sonnet-4-5
""",
    )
    runtime_config = load_runtime_config(config_path)
    result = run_audit(runtime_config, challenge_level="basic")
    markdown = render_markdown(result)

    assert "## Dynamic Challenge Results" in markdown
    assert "prompt" not in markdown.lower()
    assert "{{" not in markdown
    assert "challenge_hash" in markdown
