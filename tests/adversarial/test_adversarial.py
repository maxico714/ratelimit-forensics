import json
import random
import time
from pathlib import Path

from ratelimit_forensics.adapters import parse_har, parse_http_response
from ratelimit_forensics.redact import assert_clean, redact
from ratelimit_forensics.rules import analyze

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def test_secret_in_captured_log_never_survives():
    raw = (FIXTURES / "openai_429.txt").read_text(encoding="utf-8")
    raw += "\nAuthorization: Bearer sk-live-abcdefghijklmnop\n"
    clean, _ = redact(raw)
    assert_clean(clean)
    assert "sk-live-abcdefghijklmnop" not in clean


def test_ambiguous_headers_are_insufficient():
    result = analyze({"retry-after": "10"}, body="")
    assert result.insufficient_evidence is True
    assert result.layer == "unknown"


def test_conflicting_status_and_body_is_reported():
    captured = parse_http_response(
        "HTTP/1.1 429 Too Many Requests\nServer: cloudflare\n\n"
        '{"error": {"type": "rate_limit_exceeded"}}'
    )
    result = analyze(captured.headers, captured.body, captured.status)
    assert result.layer == "upstream"
    assert any("Cloudflare" in note for note in result.conflicts)
    assert result.confidence < 0.9


def test_retry_after_parsing_holds_across_many_values():
    from datetime import datetime, timedelta, timezone

    from ratelimit_forensics.parsers import parse_retry_after

    random.seed(1234)
    now = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)
    for _ in range(1000):
        seconds = random.randint(0, 86400)
        delta = parse_retry_after(str(seconds), now=now)
        assert delta is not None and delta.reset_seconds == float(seconds)
        target = now + timedelta(seconds=seconds)
        http_date = target.strftime("%a, %d %b %Y %H:%M:%S GMT")
        absolute = parse_retry_after(http_date, now=now)
        assert absolute is not None and absolute.unit == "http-date"
        assert abs((absolute.reset_seconds or 0) - seconds) <= 1


def test_large_har_is_analyzed_within_two_seconds():
    entries = [
        {
            "request": {"method": "GET", "url": f"https://example.com/{i}"},
            "response": {
                "status": 200,
                "headers": [{"name": "content-type", "value": "text/plain"}],
            },
        }
        for i in range(10_000)
    ]
    entries.append(
        {
            "request": {"method": "GET", "url": "https://example.com/limited"},
            "response": {
                "status": 429,
                "headers": [{"name": "Server", "value": "cloudflare"}],
                "content": {"text": "Error 1015 You are being rate limited."},
            },
        }
    )
    payload = json.dumps({"log": {"entries": entries}})
    start = time.perf_counter()
    captured = parse_har(payload)
    result = analyze(captured.headers, captured.body, captured.status)
    elapsed = time.perf_counter() - start
    assert result.vendor == "cloudflare"
    assert elapsed < 2.0, f"analysis took {elapsed:.2f}s"
