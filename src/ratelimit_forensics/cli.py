from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .adapters import ParseError, parse_access_log_line, parse_har, parse_http_response
from .redact import RedactionError, assert_clean, redact
from .report import render_json, render_text
from .rules import RuleError, evaluate, load_rules


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ratelimit-forensics",
        description="Attribute a captured HTTP 429 to its enforcing layer. Offline, no network.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    analyze = sub.add_parser("analyze", help="analyze a captured 429 response")
    source = analyze.add_mutually_exclusive_group(required=True)
    source.add_argument("--har", type=Path, help="HAR file containing a 429 entry")
    source.add_argument("--headers", type=Path, help="header block or full HTTP response")
    source.add_argument("--curl-dump", type=Path, help="output of curl -i")
    source.add_argument("--stdin", action="store_true", help="read the response from stdin")
    analyze.add_argument("--json", action="store_true", help="emit JSON instead of text")
    analyze.add_argument("--rules", type=Path, help="custom rules file or directory")
    analyze.add_argument("--log-line", default="", help="one access-log line as a tiebreaker")
    return parser


def _read(args: argparse.Namespace) -> tuple[str, str]:
    if args.stdin:
        return sys.stdin.read(), "stdin"
    if args.har:
        return args.har.read_text(encoding="utf-8", errors="replace"), "har"
    if args.headers:
        return args.headers.read_text(encoding="utf-8", errors="replace"), "headers"
    return args.curl_dump.read_text(encoding="utf-8", errors="replace"), "curl-dump"


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command != "analyze":
        parser.error("unknown command")

    try:
        raw, source = _read(args)
    except OSError as exc:
        print(f"error: cannot read input: {exc}", file=sys.stderr)
        return 2

    try:
        clean, _ = redact(raw)
        assert_clean(clean)
    except RedactionError as exc:
        print(f"error: redaction failed: {exc}", file=sys.stderr)
        return 3

    try:
        captured = parse_har(clean) if source == "har" else parse_http_response(clean)
    except ParseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        rules = load_rules([args.rules] if args.rules else None)
    except (RuleError, OSError) as exc:
        print(f"error: cannot load rules: {exc}", file=sys.stderr)
        return 2

    attribution = evaluate(rules, captured.status, captured.headers, captured.body)
    for note in (*captured.notes, *parse_access_log_line(args.log_line)):
        attribution.evidence.append(note)

    sys.stdout.write(render_json(attribution) if args.json else render_text(attribution))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
