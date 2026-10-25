# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-10-25

### Added
- Offline 429 attribution from HAR, `curl -i` dumps, and header blocks.
- Parsers for `X-RateLimit-*`, IETF `RateLimit`/`RateLimit-Policy`, `Retry-After`
  (delta-seconds and HTTP-date), OpenAI dual-dimension, and Anthropic headers.
- Body classifiers for Cloudflare 1015, OpenAI, Anthropic, Google quota, generic
  JSON, HTML, and text.
- Rules-as-data engine with packaged default rules, custom rule files, evidence
  traces, conflict detection, and an explicit `insufficient_evidence` state.
- Redaction of authorization headers, API keys, and token-shaped values before
  parsing, plus a post-redaction leak check (exit 3 on failure).
- CLI (`analyze`), JSON output, and a Python API (`ratelimit_forensics.analyze`).
- Test suite covering unit, integration, and adversarial cases, including a
  10,000-entry HAR performance check.
