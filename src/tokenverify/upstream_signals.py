from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from tokenverify.models import AuditResult, EvidenceItem


@dataclass(frozen=True)
class SuspectedUpstreamSignal:
    style: str
    evidence: list[str]
    auxiliary_label: str


def find_suspected_upstream_signals(result: AuditResult) -> list[SuspectedUpstreamSignal]:
    claimed_provider = _claimed_provider(result)
    grouped: dict[str, dict[str, Any]] = {}

    for item in _evidence_items(result):
        text = _item_text(item)
        styles = _styles_from_text(text)
        if "system_fingerprint" in text:
            styles.add("openai")
        if "reasoning_content" in text or "deepseek-r1" in text or "deepseek-reasoner" in text:
            styles.add("deepseek_r1")

        for style in styles:
            if _provider_for_style(style) == claimed_provider:
                continue
            entry = grouped.setdefault(style, {"evidence": [], "weak_only": True})
            entry["evidence"].extend(_evidence_labels(item, text))
            if item.weight != "weak":
                entry["weak_only"] = False

    signals = []
    for style, data in grouped.items():
        evidence = _dedupe(data["evidence"])
        label = "辅助提示" if data["weak_only"] else "辅助解释"
        signals.append(SuspectedUpstreamSignal(_style_label(style), evidence, label))
    return signals


def _claimed_provider(result: AuditResult) -> str:
    if result.claim:
        return result.claim.provider.lower()
    return str(result.target_summary.get("claimed_provider") or "").lower()


def _evidence_items(result: AuditResult) -> list[EvidenceItem]:
    return [item for probe in result.probe_results for item in probe.evidence]


def _item_text(item: EvidenceItem) -> str:
    parts: list[str] = [item.key, item.message, *item.tags]
    parts.extend(_flatten_detail_values(item.details))
    return " ".join(str(part) for part in parts if part).lower()


def _flatten_detail_values(value: Any) -> list[str]:
    if isinstance(value, dict):
        flattened: list[str] = []
        for key, nested in value.items():
            flattened.append(str(key))
            flattened.extend(_flatten_detail_values(nested))
        return flattened
    if isinstance(value, (list, tuple, set)):
        flattened = []
        for nested in value:
            flattened.extend(_flatten_detail_values(nested))
        return flattened
    if value is None:
        return []
    return [str(value)]


def _styles_from_text(text: str) -> set[str]:
    styles: set[str] = set()
    if "claude" in text or "anthropic" in text:
        styles.add("claude")
    if "system_fingerprint" in text or "gpt-" in text or "o1" in text or "o3" in text or "o4" in text:
        styles.add("openai")
    if "deepseek" in text or "reasoning_content" in text:
        styles.add("deepseek_r1")
    if any(marker in text for marker in ("gemini", "qwen", "doubao", "seed")):
        styles.add("unmodeled")
    return styles


def _provider_for_style(style: str) -> str:
    return {
        "claude": "anthropic",
        "openai": "openai",
        "deepseek_r1": "deepseek",
    }.get(style, "")


def _style_label(style: str) -> str:
    return {
        "claude": "疑似 Claude/Anthropic 风格上游或兼容层",
        "openai": "疑似 OpenAI 风格上游或兼容层",
        "deepseek_r1": "疑似 DeepSeek/R1 风格上游或兼容层",
        "unmodeled": "未建模厂商风格线索",
    }[style]


def _evidence_labels(item: EvidenceItem, text: str) -> list[str]:
    labels = [item.key]
    observed_model = item.details.get("observed_model")
    if observed_model:
        labels.append(str(observed_model))
    observed_fields = item.details.get("observed_fields")
    if isinstance(observed_fields, list):
        labels.extend(str(field) for field in observed_fields)
    if "system_fingerprint" in text:
        labels.append("system_fingerprint")
    if "reasoning_content" in text:
        labels.append("reasoning_content")
    return labels


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    return deduped
