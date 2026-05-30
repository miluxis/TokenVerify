from __future__ import annotations

import ast
import hashlib
import json
import operator
import random
import re
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from tokenverify.models import ChallengeVerifierResult, DynamicChallengeResult, ProviderEvent


LEVELS = {"basic": 0, "standard": 1, "strict": 2}


class ChallengePackError(ValueError):
    pass


class ChallengeValidationError(ChallengePackError):
    pass


@dataclass(frozen=True)
class Challenge:
    id: str
    category: str
    level: str
    prompt: str
    variables: dict[str, dict[str, Any]] = field(default_factory=dict)
    verifiers: list[dict[str, Any]] = field(default_factory=list)
    max_tokens: int = 64
    stream: bool = False


@dataclass(frozen=True)
class ChallengePack:
    id: str
    version: str
    challenges: list[Challenge]


def load_default_challenge_pack() -> ChallengePack:
    path = resources.files("tokenverify").joinpath("challenge_baseline.yaml")
    return _pack_from_mapping(yaml.safe_load(path.read_text(encoding="utf-8")) or {}, source=str(path))


def load_challenge_pack(path: str | Path) -> ChallengePack:
    pack_path = Path(path)
    data = yaml.safe_load(pack_path.read_text(encoding="utf-8")) or {}
    return _pack_from_mapping(data, source=str(pack_path))


def select_challenges(pack: ChallengePack, level: str) -> list[Challenge]:
    normalized = _normalize_level(level)
    maximum = LEVELS[normalized]
    return [challenge for challenge in pack.challenges if LEVELS[challenge.level] <= maximum]


def generate_variables(pack: ChallengePack, challenge: Challenge, endpoint_name: str) -> dict[str, Any]:
    variables: dict[str, Any] = {}
    for name, spec in challenge.variables.items():
        rng = random.Random(_seed_for(pack.id, pack.version, challenge.id, name, endpoint_name))
        variable_type = str(spec.get("type") or "")
        if variable_type == "integer":
            minimum = int(spec.get("min", 0))
            maximum = int(spec.get("max", 100))
            variables[name] = rng.randint(minimum, maximum)
        elif variable_type in {"hex", "nonce"}:
            byte_count = int(spec.get("bytes", 8))
            variables[name] = "".join(f"{rng.randrange(256):02x}" for _ in range(byte_count))
        elif variable_type == "choice":
            values = list(spec.get("values") or [])
            if not values:
                raise ChallengePackError(f"Variable {name} choice values must not be empty.")
            variables[name] = values[rng.randrange(len(values))]
        else:
            raise ChallengePackError(f"Unsupported variable type for {name}: {variable_type}")
    return variables


def safe_eval_expression(expression: str, variables: dict[str, Any]) -> int | float:
    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError as exc:
        raise ChallengePackError(f"unsupported expression: {expression}") from exc
    _ExpressionWhitelist().visit(tree)
    return _eval_ast(tree.body, variables)


def evaluate_verifier(
    verifier: dict[str, Any],
    assistant_text: str,
    stream_events: list[ProviderEvent] | list[dict[str, Any]],
    variables: dict[str, Any],
) -> ChallengeVerifierResult:
    verifier_type = str(verifier.get("type") or "")
    try:
        if verifier_type == "exact_answer":
            expected = _expected_value(verifier, variables)
            passed = assistant_text.strip() == str(expected)
            return _verifier_result(verifier_type, passed)
        if verifier_type == "required_field":
            payload = _json_object(assistant_text)
            passed = _path_exists(payload, str(verifier.get("path") or ""))
            return _verifier_result(verifier_type, passed)
        if verifier_type == "forbidden_field":
            payload = _json_object(assistant_text)
            passed = not _path_exists(payload, str(verifier.get("path") or ""))
            return _verifier_result(verifier_type, passed)
        if verifier_type == "json_schema":
            payload = _json_object(assistant_text)
            passed = _matches_schema(payload, dict(verifier.get("schema") or {}))
            return _verifier_result(verifier_type, passed)
        if verifier_type == "stream_ordering":
            if verifier.get("mode") == "reasoning_before_content":
                passed = _reasoning_before_content(stream_events)
                return _verifier_result(verifier_type, passed)
            expected = [str(item) for item in verifier.get("sequence") or []]
            observed = [_event_type(event) for event in stream_events]
            passed = _contains_ordered_subsequence(observed, expected)
            return _verifier_result(verifier_type, passed)
    except (ChallengePackError, json.JSONDecodeError, TypeError, ValueError) as exc:
        return ChallengeVerifierResult(verifier_type or "unknown", "failed", _failure_message())
    raise ChallengePackError(f"Unsupported verifier type: {verifier_type}")


def run_dynamic_challenges(
    pack: ChallengePack,
    level: str,
    endpoint_name: str,
    model: str,
    adapter=None,
) -> list[DynamicChallengeResult]:
    results: list[DynamicChallengeResult] = []
    for challenge in select_challenges(pack, level):
        challenge_hash = _challenge_hash(pack, challenge)
        if adapter is None:
            results.append(
                DynamicChallengeResult(
                    challenge_id=challenge.id,
                    category=challenge.category,
                    level=challenge.level,
                    challenge_hash=challenge_hash,
                    status="skipped",
                    warning="API key is required for dynamic challenge execution.",
                )
            )
            continue

        try:
            variables = generate_variables(pack, challenge, endpoint_name)
            prompt = _render_prompt(challenge.prompt, variables)
            if challenge.stream:
                events = adapter.stream_probe_events(model=model, prompt=prompt, max_tokens=challenge.max_tokens)
                assistant_text = ""
            else:
                response = adapter.create_probe_response(model=model, prompt=prompt, max_tokens=challenge.max_tokens)
                events = []
                assistant_text = _assistant_text(response)
            verifier_results = [
                evaluate_verifier(verifier, assistant_text, events, variables) for verifier in challenge.verifiers
            ]
            status = "passed" if verifier_results and all(item.status == "passed" for item in verifier_results) else "failed"
            results.append(
                DynamicChallengeResult(
                    challenge_id=challenge.id,
                    category=challenge.category,
                    level=challenge.level,
                    challenge_hash=challenge_hash,
                    status=status,
                    verifier_results=verifier_results,
                )
            )
        except Exception as exc:
            results.append(
                DynamicChallengeResult(
                    challenge_id=challenge.id,
                    category=challenge.category,
                    level=challenge.level,
                    challenge_hash=challenge_hash,
                    status="inconclusive",
                    warning=_sanitize_message(str(exc)),
                )
            )
    return results


def _pack_from_mapping(data: Any, source: str) -> ChallengePack:
    if not isinstance(data, dict):
        raise ChallengePackError(f"Challenge pack root must be a mapping: {source}")
    pack_id = str(data.get("id") or "")
    version = str(data.get("version") or "")
    raw_challenges = data.get("challenges")
    if not pack_id:
        raise ChallengePackError("Challenge pack must define id.")
    if not version:
        raise ChallengePackError("Challenge pack must define version.")
    if not isinstance(raw_challenges, list) or not raw_challenges:
        raise ChallengePackError("Challenge pack must define non-empty challenges.")
    return ChallengePack(
        id=pack_id,
        version=version,
        challenges=[_challenge_from_mapping(item) for item in raw_challenges],
    )


def _challenge_from_mapping(data: Any) -> Challenge:
    if not isinstance(data, dict):
        raise ChallengePackError("Challenge entries must be mappings.")
    challenge_id = str(data.get("id") or "")
    category = str(data.get("category") or "")
    level = _normalize_level(str(data.get("level") or "basic"))
    prompt = str(data.get("prompt") or "")
    verifiers = data.get("verifiers") or []
    if not challenge_id:
        raise ChallengePackError("Challenge must define id.")
    if not category:
        raise ChallengePackError(f"Challenge {challenge_id} must define category.")
    if not prompt:
        raise ChallengePackError(f"Challenge {challenge_id} must define prompt.")
    if not isinstance(verifiers, list) or not verifiers:
        raise ChallengePackError(f"Challenge {challenge_id} must define non-empty verifiers.")
    variables = data.get("variables") or {}
    if not isinstance(variables, dict):
        raise ChallengePackError(f"Challenge {challenge_id} variables must be a mapping.")
    return Challenge(
        id=challenge_id,
        category=category,
        level=level,
        prompt=prompt,
        variables=dict(variables),
        verifiers=[dict(item) for item in verifiers],
        max_tokens=int(data.get("max_tokens", 64)),
        stream=bool(data.get("stream", False)),
    )


def _normalize_level(level: str) -> str:
    normalized = level.strip().lower()
    if normalized not in LEVELS:
        raise ChallengePackError("--challenge-level must be basic, standard, or strict.")
    return normalized


def _seed_for(pack_id: str, version: str, challenge_id: str, variable_name: str, endpoint_name: str) -> int:
    material = "\x1f".join([pack_id, version, challenge_id, variable_name, endpoint_name])
    digest = hashlib.sha256(material.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big")


def _challenge_hash(pack: ChallengePack, challenge: Challenge) -> str:
    material = json.dumps(
        {
            "pack_id": pack.id,
            "version": pack.version,
            "challenge_id": challenge.id,
            "prompt": challenge.prompt,
            "variables": challenge.variables,
            "verifiers": challenge.verifiers,
        },
        ensure_ascii=False,
        sort_keys=True,
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def _render_prompt(prompt: str, variables: dict[str, Any]) -> str:
    rendered = prompt
    for name, value in variables.items():
        rendered = rendered.replace("{{" + name + "}}", str(value))
    return rendered


def _assistant_text(response: dict) -> str:
    if isinstance(response.get("content"), list):
        parts = [item.get("text") for item in response["content"] if isinstance(item, dict)]
        return "".join(part for part in parts if isinstance(part, str))
    choices = response.get("choices")
    if isinstance(choices, list) and choices:
        message = choices[0].get("message") if isinstance(choices[0], dict) else None
        if isinstance(message, dict) and isinstance(message.get("content"), str):
            return message["content"]
    return ""


def _expected_value(verifier: dict[str, Any], variables: dict[str, Any]) -> Any:
    if "equals_expression" in verifier:
        return safe_eval_expression(str(verifier["equals_expression"]), variables)
    if "value" in verifier:
        return verifier["value"]
    raise ChallengePackError("exact_answer requires value or equals_expression.")


def _eval_ast(node: ast.AST, variables: dict[str, Any]) -> int | float:
    binary_ops = {
        ast.Add: operator.add,
        ast.Sub: operator.sub,
        ast.Mult: operator.mul,
        ast.Div: operator.truediv,
        ast.FloorDiv: operator.floordiv,
        ast.Mod: operator.mod,
    }
    unary_ops = {ast.UAdd: operator.pos, ast.USub: operator.neg}
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.Name):
        if node.id not in variables:
            raise ChallengePackError(f"unknown variable in expression: {node.id}")
        value = variables[node.id]
        if not isinstance(value, (int, float)):
            raise ChallengePackError(f"non-numeric variable in expression: {node.id}")
        return value
    if isinstance(node, ast.BinOp) and type(node.op) in binary_ops:
        return binary_ops[type(node.op)](_eval_ast(node.left, variables), _eval_ast(node.right, variables))
    if isinstance(node, ast.UnaryOp) and type(node.op) in unary_ops:
        return unary_ops[type(node.op)](_eval_ast(node.operand, variables))
    raise ChallengePackError("unsupported expression node")


class _ExpressionWhitelist(ast.NodeVisitor):
    def visit_Expression(self, node: ast.Expression) -> None:
        self.visit(node.body)

    def visit_BinOp(self, node: ast.BinOp) -> None:
        if not isinstance(node.op, (ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod)):
            raise ChallengeValidationError("unsupported expression node")
        self.visit(node.left)
        self.visit(node.right)

    def visit_UnaryOp(self, node: ast.UnaryOp) -> None:
        if not isinstance(node.op, (ast.UAdd, ast.USub)):
            raise ChallengeValidationError("unsupported expression node")
        self.visit(node.operand)

    def visit_Constant(self, node: ast.Constant) -> None:
        if not isinstance(node.value, (int, float)):
            raise ChallengeValidationError("unsupported expression node")

    def visit_Num(self, node: ast.Num) -> None:
        if not isinstance(node.n, (int, float)):
            raise ChallengeValidationError("unsupported expression node")

    def visit_Name(self, node: ast.Name) -> None:
        return None

    def generic_visit(self, node: ast.AST) -> None:
        raise ChallengeValidationError("unsupported expression node")


def _json_object(text: str) -> Any:
    return json.loads(text)


def _path_exists(payload: Any, path: str) -> bool:
    current = payload
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return False
    return True


def _matches_schema(value: Any, schema: dict[str, Any]) -> bool:
    expected_type = schema.get("type")
    if expected_type and not _matches_type(value, str(expected_type)):
        return False
    if isinstance(value, dict):
        for required in schema.get("required") or []:
            if required not in value:
                return False
        properties = schema.get("properties") or {}
        for key, child_schema in properties.items():
            if key in value and not _matches_schema(value[key], dict(child_schema)):
                return False
    if isinstance(value, list) and "items" in schema:
        item_schema = dict(schema["items"])
        return all(_matches_schema(item, item_schema) for item in value)
    return True


def _matches_type(value: Any, expected_type: str) -> bool:
    if expected_type == "object":
        return isinstance(value, dict)
    if expected_type == "array":
        return isinstance(value, list)
    if expected_type == "string":
        return isinstance(value, str)
    if expected_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected_type == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected_type == "boolean":
        return isinstance(value, bool)
    if expected_type == "null":
        return value is None
    raise ChallengePackError(f"Unsupported schema type: {expected_type}")


def _contains_ordered_subsequence(observed: list[str], expected: list[str]) -> bool:
    if not expected:
        return False
    index = 0
    for event_type in observed:
        if event_type == expected[index]:
            index += 1
            if index == len(expected):
                return True
    return False


def _reasoning_before_content(stream_events: list[ProviderEvent] | list[dict[str, Any]]) -> bool:
    saw_reasoning = False
    for event in stream_events:
        delta = _event_delta(event)
        reasoning = delta.get("reasoning_content")
        content = delta.get("content")
        if isinstance(reasoning, str) and reasoning:
            saw_reasoning = True
        if isinstance(content, str) and content:
            return saw_reasoning
    return False


def _event_delta(event: ProviderEvent | dict[str, Any]) -> dict[str, Any]:
    data = event.data if isinstance(event, ProviderEvent) else event.get("data")
    if not isinstance(data, dict):
        return {}
    choices = data.get("choices")
    if isinstance(choices, list) and choices and isinstance(choices[0], dict):
        delta = choices[0].get("delta")
        if isinstance(delta, dict):
            return delta
    delta = data.get("delta")
    return delta if isinstance(delta, dict) else {}


def _event_type(event: ProviderEvent | dict[str, Any]) -> str:
    if isinstance(event, ProviderEvent):
        return event.event_type
    return str(event.get("event_type") or "")


def _verifier_result(verifier_type: str, passed: bool) -> ChallengeVerifierResult:
    return ChallengeVerifierResult(verifier_type, "passed" if passed else "failed", _success_message() if passed else _failure_message())


def _success_message() -> str:
    return "Passed: Structure match & Local math verified."


def _failure_message() -> str:
    return "Failed: Output failed to validate against local constraints."


def _sanitize_message(message: str) -> str:
    return re.sub(r"\s+", " ", message).strip()[:160]
