from __future__ import annotations

import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any

from .models import Window


def normalize(headers: dict[str, str]) -> dict[str, str]:
    return {str(k).strip().lower(): str(v).strip() for k, v in headers.items()}


def _int(value: str | None) -> int | None:
    if value is None:
        return None
    cleaned = value.strip().replace(",", "")
    if not re.fullmatch(r"-?\d+", cleaned):
        return None
    return int(cleaned)


def parse_x_ratelimit(headers: dict[str, str]) -> dict[str, Any]:
    """Parse the legacy X-RateLimit-* family (GitHub, Cloudflare, many apps)."""
    h = normalize(headers)
    parsed = {
        "limit": _int(h.get("x-ratelimit-limit")),
        "remaining": _int(h.get("x-ratelimit-remaining")),
        "reset": _int(h.get("x-ratelimit-reset")),
        "used": _int(h.get("x-ratelimit-used")),
        "resource": h.get("x-ratelimit-resource"),
    }
    if all(value is None for key, value in parsed.items() if key != "resource"):
        return {}
    return parsed


def parse_openai(headers: dict[str, str]) -> dict[str, dict[str, int | None]]:
    """Parse OpenAI's dual-dimension request/token counters."""
    h = normalize(headers)
    out: dict[str, dict[str, int | None]] = {}
    for dimension in ("requests", "tokens"):
        values = {
            "limit": _int(h.get(f"x-ratelimit-limit-{dimension}")),
            "remaining": _int(h.get(f"x-ratelimit-remaining-{dimension}")),
            "reset": _int(h.get(f"x-ratelimit-reset-{dimension}")),
        }
        if any(value is not None for value in values.values()):
            out[dimension] = values
    return out


def parse_anthropic(headers: dict[str, str]) -> dict[str, dict[str, int | str | None]]:
    h = normalize(headers)
    out: dict[str, dict[str, int | str | None]] = {}
    for dimension in ("requests", "tokens", "input-tokens", "output-tokens"):
        values = {
            "limit": _int(h.get(f"anthropic-ratelimit-{dimension}-limit")),
            "remaining": _int(h.get(f"anthropic-ratelimit-{dimension}-remaining")),
            "reset": h.get(f"anthropic-ratelimit-{dimension}-reset"),
        }
        if any(value is not None for value in values.values()):
            out[dimension] = values
    return out


def _split_policies(value: str) -> list[str]:
    """Split a structured header list on commas that sit outside quotes."""
    parts: list[str] = []
    current: list[str] = []
    in_quotes = False
    for char in value:
        if char == '"':
            in_quotes = not in_quotes
            current.append(char)
        elif char == "," and not in_quotes:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    if current:
        parts.append("".join(current).strip())
    return [part for part in parts if part]


def _parse_policy_segment(segment: str) -> tuple[str | None, dict[str, str]]:
    name: str | None = None
    params: dict[str, str] = {}
    for piece in segment.split(";"):
        piece = piece.strip()
        if not piece:
            continue
        if "=" in piece:
            key, _, raw = piece.partition("=")
            params[key.strip().lower()] = raw.strip().strip('"')
        elif name is None:
            name = piece.strip().strip('"')
    return name, params


def parse_ietf(headers: dict[str, str]) -> list[dict[str, Any]]:
    """Parse IETF draft RateLimit / RateLimit-Policy structured fields."""
    h = normalize(headers)
    policies: dict[str, dict[str, Any]] = {}
    order: list[str] = []

    def slot(name: str) -> dict[str, Any]:
        if name not in policies:
            policies[name] = {
                "policy": name,
                "remaining": None,
                "delta_seconds": None,
                "quota": None,
                "window_seconds": None,
            }
            order.append(name)
        return policies[name]

    for segment in _split_policies(h.get("ratelimit", "")):
        name, params = _parse_policy_segment(segment)
        if name is None or not params:
            continue
        entry = slot(name)
        if "r" in params:
            entry["remaining"] = _int(params["r"])
        if "t" in params:
            entry["delta_seconds"] = _int(params["t"])

    for segment in _split_policies(h.get("ratelimit-policy", "")):
        name, params = _parse_policy_segment(segment)
        if name is None:
            continue
        entry = slot(name)
        if "q" in params:
            entry["quota"] = _int(params["q"])
        if "w" in params:
            entry["window_seconds"] = _int(params["w"])

    return [policies[name] for name in order]


def parse_retry_after(value: str | None, now: datetime | None = None) -> Window | None:
    if value is None:
        return None
    raw = value.strip()
    if not raw:
        return None
    if re.fullmatch(r"\d+(?:\.\d+)?", raw):
        return Window(reset_seconds=float(raw), unit="delta-seconds", source="Retry-After")
    try:
        when = parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        return None
    if when is None:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    reference = now or datetime.now(timezone.utc)
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=timezone.utc)
    return Window(
        reset_seconds=max(0.0, (when - reference).total_seconds()),
        unit="http-date",
        source="Retry-After",
    )


def header_window(headers: dict[str, str], now: datetime | None = None) -> Window | None:
    """Pick the most direct reset signal available in the captured headers."""
    window = parse_retry_after(normalize(headers).get("retry-after"), now=now)
    if window is not None:
        return window
    for policy in parse_ietf(headers):
        if policy.get("delta_seconds") is not None:
            return Window(
                reset_seconds=float(policy["delta_seconds"]),
                unit="delta-seconds",
                source=f"RateLimit (policy {policy['policy']})",
            )
    return None
