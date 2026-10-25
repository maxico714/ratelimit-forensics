from datetime import datetime, timezone

from ratelimit_forensics.parsers import (
    header_window,
    parse_anthropic,
    parse_ietf,
    parse_openai,
    parse_retry_after,
    parse_x_ratelimit,
)


def test_x_ratelimit_full_surface():
    parsed = parse_x_ratelimit(
        {
            "X-RateLimit-Limit": "2000",
            "X-RateLimit-Remaining": "1757",
            "X-RateLimit-Reset": "1792922400",
            "X-RateLimit-Used": "243",
            "X-RateLimit-Resource": "core",
        }
    )
    assert parsed == {
        "limit": 2000,
        "remaining": 1757,
        "reset": 1792922400,
        "used": 243,
        "resource": "core",
    }


def test_x_ratelimit_partial_and_garbage():
    assert parse_x_ratelimit({"x-ratelimit-limit": "abc"}) == {}
    partial = parse_x_ratelimit({"x-ratelimit-limit": "10", "x-ratelimit-remaining": "n/a"})
    assert partial["limit"] == 10
    assert partial["remaining"] is None


def test_openai_dual_dimension():
    parsed = parse_openai(
        {
            "x-ratelimit-limit-requests": "500",
            "x-ratelimit-remaining-tokens": "0",
            "x-ratelimit-reset-tokens": "1s",
        }
    )
    assert parsed["requests"]["limit"] == 500
    assert parsed["tokens"]["remaining"] == 0


def test_anthropic_headers():
    parsed = parse_anthropic({"anthropic-ratelimit-requests-limit": "1000"})
    assert parsed["requests"]["limit"] == 1000
    assert parsed["requests"]["remaining"] is None


def test_ietf_multiple_policies():
    policies = parse_ietf(
        {
            "RateLimit": '"default";r=0;t=30, "burst";r=5;t=60',
            "RateLimit-Policy": '"default";q=100;w=60',
        }
    )
    assert [p["policy"] for p in policies] == ["default", "burst"]
    assert policies[0] == {
        "policy": "default",
        "remaining": 0,
        "delta_seconds": 30,
        "quota": 100,
        "window_seconds": 60,
    }
    assert policies[1]["remaining"] == 5


def test_ietf_malformed_returns_empty():
    assert parse_ietf({"ratelimit": "garbage without policy"}) == []
    assert parse_ietf({}) == []


def test_retry_after_delta_seconds():
    window = parse_retry_after("30")
    assert window is not None
    assert window.reset_seconds == 30.0
    assert window.unit == "delta-seconds"


def test_retry_after_http_date():
    now = datetime(2026, 10, 25, 10, 0, 0, tzinfo=timezone.utc)
    window = parse_retry_after("Sat, 25 Oct 2026 10:01:00 GMT", now=now)
    assert window is not None
    assert window.unit == "http-date"
    assert window.reset_seconds == 60.0


def test_retry_after_invalid_and_missing():
    assert parse_retry_after(None) is None
    assert parse_retry_after("") is None
    assert parse_retry_after("soon") is None


def test_header_window_prefers_retry_after():
    window = header_window({"retry-after": "5", "ratelimit": '"default";r=0;t=30'})
    assert window is not None
    assert window.source == "Retry-After"
    assert window.reset_seconds == 5.0


def test_header_window_falls_back_to_ietf():
    window = header_window({"ratelimit": '"default";r=0;t=30'})
    assert window is not None
    assert window.reset_seconds == 30.0
    assert "RateLimit" in window.source
