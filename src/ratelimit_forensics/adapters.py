from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Any

from .models import Captured


class ParseError(ValueError):
    """The captured response cannot be read."""


_STATUS_LINE = re.compile(r"^HTTP/\d(?:\.\d)?\s+(\d{3})\b")


def parse_http_response(text: str, default_status: int = 429) -> Captured:
    """Parse an HTTP response (headers required, status line optional)."""
    if text.startswith("\ufeff"):
        text = text[1:]
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = normalized.split("\n")
    status = default_status
    index = 0
    if lines and _STATUS_LINE.match(lines[0].strip()):
        status = int(_STATUS_LINE.match(lines[0].strip()).group(1))  # type: ignore[union-attr]
        index = 1

    headers: dict[str, str] = {}
    seen_header = False
    while index < len(lines):
        line = lines[index]
        if not line.strip():
            index += 1
            break
        if ":" not in line:
            raise ParseError(f"line {index + 1} is not a header: {line[:40]!r}")
        name, _, value = line.partition(":")
        name = name.strip()
        if not name:
            raise ParseError(f"line {index + 1} has an empty header name")
        value = value.strip()
        key = name.lower()
        headers[key] = f"{headers[key]}, {value}" if key in headers else value
        seen_header = True
        index += 1

    if not seen_header:
        raise ParseError("no HTTP response headers found")

    body = "\n".join(lines[index:])
    return Captured(status=status, headers=headers, body=body)


def parse_har(payload: str | bytes | dict[str, Any]) -> Captured:
    if isinstance(payload, (str, bytes)):
        try:
            data: Any = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise ParseError(f"invalid HAR JSON: {exc}") from exc
    else:
        data = payload
    try:
        entries = data["log"]["entries"]
    except (KeyError, TypeError) as exc:
        raise ParseError("invalid HAR: missing log.entries") from exc
    if not isinstance(entries, list):
        raise ParseError("invalid HAR: log.entries is not a list")

    for entry in entries:
        try:
            response = entry["response"]
            status = int(response["status"])
        except (KeyError, TypeError, ValueError):
            continue
        if status != 429:
            continue
        headers: dict[str, str] = {}
        for header in response.get("headers", []) or []:
            name = str(header.get("name", "")).strip().lower()
            if name:
                headers[name] = str(header.get("value", "")).strip()
        content = response.get("content", {}) or {}
        body = content.get("text", "") or ""
        if content.get("encoding") == "base64" and body:
            try:
                body = base64.b64decode(body).decode("utf-8", errors="replace")
            except (binascii.Error, ValueError) as exc:
                raise ParseError(f"invalid base64 response body: {exc}") from exc
        return Captured(status=429, headers=headers, body=str(body))
    raise ParseError("no 429 response found in HAR")


_LOG_429 = re.compile(r"\s429\s")


def parse_access_log_line(line: str) -> tuple[str, ...]:
    """Return evidence notes from a single access-log line; never raises."""
    raw = (line or "").strip()
    if not raw or not _LOG_429.search(raw):
        return ()
    notes = [f"access log records a 429: {raw[:200]}"]
    lowered = raw.lower()
    for marker in ("cloudflare", "envoy", "nginx", "apache"):
        if marker in lowered:
            notes.append(f"access log mentions {marker}")
            break
    return tuple(notes)
