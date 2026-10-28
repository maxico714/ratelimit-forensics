from pathlib import Path

import pytest

from ratelimit_forensics.models import Attribution
from ratelimit_forensics.rules import RuleError, analyze, evaluate, load_rules

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _analyze_fixture(name: str) -> Attribution:
    from ratelimit_forensics.adapters import parse_http_response

    captured = parse_http_response((FIXTURES / name).read_text(encoding="utf-8"))
    return analyze(captured.headers, captured.body, captured.status)


def test_cloudflare_body_wins_edge_attribution():
    result = _analyze_fixture("cloudflare_1015.txt")
    assert result.layer == "edge-cdn"
    assert result.vendor == "cloudflare"
    assert result.confidence == pytest.approx(0.92)
    assert result.window is not None
    assert result.window.reset_seconds == 30.0
    assert result.insufficient_evidence is False


def test_openai_body_wins_upstream_attribution():
    result = _analyze_fixture("openai_429.txt")
    assert result.layer == "upstream"
    assert result.vendor == "openai"
    assert result.confidence == pytest.approx(0.9)


def test_conflicting_app_counter_lowers_confidence():
    result = _analyze_fixture("conflicting_layers.txt")
    assert result.layer == "edge-cdn"
    assert result.confidence == pytest.approx(0.82)
    assert any("contradicts" in note for note in result.conflicts)
    assert result.insufficient_evidence is False


def test_ietf_headers_attribute_gateway():
    result = analyze(
        {"RateLimit": '"default";r=0;t=30', "RateLimit-Policy": '"default";q=100;w=60'},
        body="",
    )
    assert result.layer == "gateway"
    assert result.policy is not None and "quota=100" in result.policy
    assert result.window is not None and result.window.reset_seconds == 30.0


def test_generic_json_is_insufficient_evidence():
    result = analyze({"content-type": "application/json"}, body='{"error": "rate limit"}')
    assert result.layer == "unknown"
    assert result.insufficient_evidence is True
    assert result.confidence < 0.5


def test_no_match_is_insufficient():
    result = analyze({}, body="totally unrelated")
    assert result.layer == "unknown"
    assert result.insufficient_evidence is True
    assert result.confidence == 0.0


def test_custom_rules_replace_defaults(tmp_path: Path):
    rules_file = tmp_path / "only.yaml"
    rules_file.write_text(
        "rules:\n"
        "  - id: custom\n"
        "    layer: app\n"
        "    confidence: 0.99\n"
        "    when:\n"
        "      body_contains: [needle]\n"
        "    evidence: [custom rule fired]\n",
        encoding="utf-8",
    )
    rules = load_rules([rules_file])
    hit = evaluate(rules, 429, {}, body="a needle here")
    assert hit.layer == "app"
    assert hit.confidence == pytest.approx(0.99)
    miss = evaluate(rules, 429, {}, body="nothing")
    assert miss.insufficient_evidence is True


def test_bad_rules_file_is_rejected(tmp_path: Path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("rules:\n  - id: broken\n    layer: app\n", encoding="utf-8")
    with pytest.raises(RuleError):
        load_rules([bad])


@pytest.mark.parametrize(
    "when",
    [
        "      all:\n        - status: notanint\n",
        "      all:\n        - body_contains: needle\n",
        "      all:\n        - header_present: server\n",
        "      all:\n        - header_matches: {server: '('}\n",
        "      all:\n        - unknown_predicate: true\n",
        "      all: []\n",
        "      all: [not-a-mapping]\n",
        "      all:\n        - status: 429\n      retry_after_present: true\n",
        "      body_kind: cloudflare-1015\n",
    ],
)
def test_malformed_rule_predicates_are_rejected(tmp_path: Path, when: str):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "rules:\n  - id: broken\n    layer: app\n    confidence: 0.4\n    when:\n" + when,
        encoding="utf-8",
    )
    with pytest.raises(RuleError):
        load_rules([bad])


def test_malformed_evidence_is_rejected(tmp_path: Path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "rules:\n"
        "  - id: broken\n"
        "    layer: app\n"
        "    confidence: 0.4\n"
        "    when: {status: 429}\n"
        "    evidence: one string\n",
        encoding="utf-8",
    )
    with pytest.raises(RuleError):
        load_rules([bad])


def test_packaged_rules_load():
    rules = load_rules()
    assert len(rules) >= 8
    assert any(rule.id == "cloudflare-1015" for rule in rules)
