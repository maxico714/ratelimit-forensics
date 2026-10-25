from __future__ import annotations

import json
import re


def classify(body: str) -> str:
    """Classify a response body into a vendor-neutral kind for rule matching."""
    text = (body or "").strip()
    if not text:
        return "empty"

    lowered = text.lower()

    if "error 1015" in lowered or "error code: 1015" in lowered:
        return "cloudflare-1015"
    if "cloudflare" in lowered and "rate limited" in lowered:
        return "cloudflare-1015"

    if "resource_exhausted" in lowered or "quota exceeded" in lowered:
        return "google"

    if (
        re.search(r'"type"\s*:\s*"rate_limit_exceeded"', lowered)
        or "rate limit reached for" in lowered
    ):
        return "openai"

    if (
        re.search(r'"type"\s*:\s*"rate_limit_error"', lowered)
        or "number of requests has exceeded" in lowered
    ):
        return "anthropic"

    if lowered.startswith("<!doctype html") or lowered.startswith("<html"):
        return "html"

    if text.startswith("{"):
        try:
            json.loads(text)
        except json.JSONDecodeError:
            return "json-invalid"
        if "rate limit" in lowered or "too many requests" in lowered:
            return "generic-json"
        return "json-other"

    if "too many requests" in lowered or "rate limit" in lowered:
        return "text"
    return "other"
