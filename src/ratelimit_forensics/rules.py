from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from .bodies import classify
from .models import Attribution, Window
from .parsers import (
    header_window,
    normalize,
    parse_anthropic,
    parse_ietf,
    parse_openai,
    parse_x_ratelimit,
)
from .redact import redact


class RuleError(ValueError):
    """Attribution rules are missing or malformed."""


@dataclass(frozen=True)
class Rule:
    id: str
    layer: str
    vendor: str | None
    confidence: float
    when: dict[str, Any]
    evidence: tuple[str, ...] = field(default_factory=tuple)


def _parse_rule(raw: Mapping[str, Any]) -> Rule:
    try:
        rule_id = str(raw["id"])
        layer = str(raw["layer"])
        confidence = float(raw["confidence"])
        when = raw["when"]
    except (KeyError, TypeError, ValueError) as exc:
        raise RuleError(f"invalid rule: {raw!r}") from exc
    if not isinstance(when, dict) or not when:
        raise RuleError(f"rule {rule_id} has an empty or non-mapping 'when'")
    if not 0.0 <= confidence <= 1.0:
        raise RuleError(f"rule {rule_id} confidence must be within 0..1")
    evidence = tuple(str(item) for item in raw.get("evidence", []))
    vendor = raw.get("vendor")
    return Rule(rule_id, layer, str(vendor) if vendor else None, confidence, when, evidence)


def load_rules(paths: list[Path] | None = None) -> list[Rule]:
    """Load packaged rules, or every *.yaml file from the given paths."""
    if paths is None:
        text = (
            resources.files("ratelimit_forensics")
            .joinpath("rules/default.yaml")
            .read_text(encoding="utf-8")
        )
        documents = [text]
    else:
        documents = []
        for path in paths:
            candidates = sorted(path.glob("*.yaml")) if path.is_dir() else [path]
            for candidate in candidates:
                documents.append(candidate.read_text(encoding="utf-8"))
    rules: list[Rule] = []
    for document in documents:
        try:
            data = yaml.safe_load(document) or {}
        except yaml.YAMLError as exc:
            raise RuleError(f"invalid YAML: {exc}") from exc
        raw_rules = data.get("rules", []) if isinstance(data, dict) else []
        if not isinstance(raw_rules, list):
            raise RuleError("rules document must contain a 'rules' list")
        rules.extend(_parse_rule(item) for item in raw_rules)
    if not rules:
        raise RuleError("no attribution rules loaded")
    return rules


def _clause_ok(clause: Mapping[str, Any], ctx: dict[str, Any]) -> bool:
    headers: dict[str, str] = ctx["headers"]
    for key, value in clause.items():
        if key == "status":
            if ctx["status"] != int(value):
                return False
        elif key == "header_present":
            names = [str(name).lower() for name in value]
            if not any(name in headers for name in names):
                return False
        elif key == "header_absent":
            names = [str(name).lower() for name in value]
            if any(name in headers for name in names):
                return False
        elif key == "header_equals":
            for name, expected in value.items():
                if headers.get(str(name).lower(), "") != str(expected):
                    return False
        elif key == "header_matches":
            for name, pattern in value.items():
                if not re.search(str(pattern), headers.get(str(name).lower(), ""), re.IGNORECASE):
                    return False
        elif key == "body_kind":
            if ctx["body_kind"] not in [str(item) for item in value]:
                return False
        elif key == "body_contains":
            lowered = ctx["body"].lower()
            if not any(str(item).lower() in lowered for item in value):
                return False
        elif key == "retry_after_present":
            if bool(headers.get("retry-after")) is not bool(value):
                return False
        else:
            return False
    return True


def _rule_matches(rule: Rule, ctx: dict[str, Any]) -> bool:
    when = rule.when
    clauses = when.get("all")
    if isinstance(clauses, list):
        return all(_clause_ok(clause, ctx) for clause in clauses if isinstance(clause, dict))
    return _clause_ok(when, ctx)


def _specificity(rule: Rule) -> int:
    when = rule.when
    raw_clauses = when.get("all")
    clauses: list[Any] = raw_clauses if isinstance(raw_clauses, list) else [when]
    total = 0
    for clause in clauses:
        if isinstance(clause, dict):
            for key in (
                "status",
                "header_present",
                "header_absent",
                "header_equals",
                "header_matches",
                "body_kind",
                "body_contains",
            ):
                value = clause.get(key)
                if isinstance(value, (list, dict)):
                    total += len(value)
                elif value is not None:
                    total += 1
    return total


def _conflicts(headers: dict[str, str], body_kind: str, winner: Rule) -> list[str]:
    out: list[str] = []
    h = normalize(headers)
    xr = parse_x_ratelimit(headers)
    remaining = xr.get("remaining")
    if (
        isinstance(remaining, int)
        and remaining > 0
        and winner.layer in {"edge-cdn", "gateway", "upstream"}
    ):
        out.append(
            f"X-RateLimit-Remaining={remaining} contradicts a 429 attributed to {winner.layer} "
            "(the app counter says requests remain)"
        )
    if parse_openai(headers) and parse_anthropic(headers):
        out.append("both OpenAI and Anthropic rate-limit header families are present")
    server = h.get("server", "").lower()
    if "cloudflare" in server and body_kind in {"openai", "anthropic", "google"}:
        out.append("server header says Cloudflare but the body names an upstream provider")
    return out


def _extra_evidence(headers: dict[str, str], winner: Rule) -> list[str]:
    out: list[str] = []
    h = normalize(headers)
    xr = parse_x_ratelimit(headers)
    has_counters = any(name in h for name in ("ratelimit-limit", "x-ratelimit-limit"))
    if winner.vendor == "cloudflare" and not has_counters:
        out.append("RateLimit-* counters are absent (typical of an edge-layer 429)")
    if xr.get("remaining") == 0:
        out.append("X-RateLimit-Remaining=0 confirms exhaustion at the app layer")
    if "retry-after" in h:
        out.append("Retry-After is present")
    return out


def _policy(headers: dict[str, str]) -> str | None:
    policies = parse_ietf(headers)
    if not policies:
        return None
    exhausted = [item for item in policies if item.get("remaining") == 0]
    chosen = exhausted[0] if exhausted else policies[0]
    parts = [f"policy {chosen['policy']}"]
    if chosen.get("quota") is not None:
        parts.append(f"quota={chosen['quota']}")
    if chosen.get("window_seconds") is not None:
        parts.append(f"window={chosen['window_seconds']}s")
    return ", ".join(parts)


def evaluate(
    rules: list[Rule],
    status: int,
    headers: Mapping[str, str],
    body: str = "",
    now: datetime | None = None,
) -> Attribution:
    normalized = normalize(dict(headers))
    clean_body, _ = redact(body or "")
    body_kind = classify(clean_body)
    ctx = {"status": status, "headers": normalized, "body": clean_body, "body_kind": body_kind}

    matches = [rule for rule in rules if _rule_matches(rule, ctx)]
    parsed = {
        "x_ratelimit": parse_x_ratelimit(normalized),
        "openai": parse_openai(normalized),
        "anthropic": parse_anthropic(normalized),
        "ietf": parse_ietf(normalized),
        "body_kind": body_kind,
        "status": status,
    }

    if not matches:
        return Attribution(
            layer="unknown",
            vendor=None,
            confidence=0.0,
            evidence=["no attribution rule matched the captured response"],
            window=header_window(normalized, now=now),
            insufficient_evidence=True,
            parsed=parsed,
        )

    matches.sort(key=lambda rule: (rule.confidence, _specificity(rule)), reverse=True)
    winner = matches[0]
    confidence = winner.confidence
    evidence = list(winner.evidence)
    evidence.append(f"matched rule '{winner.id}'")
    evidence.extend(_extra_evidence(normalized, winner))

    conflicts = _conflicts(normalized, body_kind, winner)
    if conflicts:
        confidence = max(0.3, round(confidence - 0.1 * len(conflicts), 3))
        evidence.append("conflicting evidence lowered the confidence")

    insufficient = confidence < 0.5 or winner.layer == "unknown"
    if insufficient:
        evidence.append("evidence is too weak for a confident attribution")

    return Attribution(
        layer=winner.layer,
        vendor=winner.vendor,
        confidence=confidence,
        evidence=evidence,
        policy=_policy(normalized),
        window=header_window(normalized, now=now),
        conflicts=conflicts,
        insufficient_evidence=insufficient,
        parsed=parsed,
    )


def analyze(
    headers: Mapping[str, str],
    body: str = "",
    status: int = 429,
    rules: list[Rule] | None = None,
    now: datetime | None = None,
) -> Attribution:
    return evaluate(rules if rules is not None else load_rules(), status, headers, body, now=now)


__all__ = ["Rule", "RuleError", "analyze", "evaluate", "load_rules", "Window"]
