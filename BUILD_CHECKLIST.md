# BUILD CHECKLIST — ratelimit-forensics

Gate 0 = pre-build spikes (do FIRST, record results in EVIDENCE.md). Then unit-by-unit build loop (A5): Expect → Test-fail → Implement → Run → Compare → Mutation-check → Static-checks → Checkpoint.

## Gate 0 — riskiest assumptions (spike before build order)

- [x] **Fixture fidelity spike**: synthetic 429 fixtures (Cloudflare 1015, OpenAI dual-dimension, conflicting app counter) fire the expected attribution rules. Covered by `tests/unit/test_rules.py` and `tests/fixtures/`.
- [x] **Redaction spike**: `Authorization: Bearer sk-…` is redacted before parsing; output and stdout remain clean. Covered by `tests/unit/test_redact.py` and `tests/adversarial/`.
- [x] **Retry-After disambiguation spike**: 1,000 generated delta/HTTP-date cases parse to the same wait window (±1 s). Covered by `tests/adversarial/test_adversarial.py`.
- [x] **Name re-check at G2**: `ratelimit-forensics` returned 404 on PyPI and npm on 2026-10-25.

## Unit build order (one unit at a time, A5 loop)

| # | Unit | Expected (normal / edge / failure) | Command | Status |
|---|---|---|---|---|
| 1 | Redaction engine | strips Bearer/sk-/api_key; empty input → empty; leak check raises | pytest tests/unit/test_redact.py | done |
| 2 | X-RateLimit-* parser | parses Limit/Remaining/Reset/Used; missing fields → partial; garbage → None | pytest tests/unit/test_parsers.py | done |
| 3 | Retry-After parser | delta-seconds → seconds; HTTP-date → seconds; invalid → None | pytest tests/unit/test_parsers.py | done |
| 4 | IETF draft-8 parser | `RateLimit: "policy";r=0;t=5` + RateLimit-Policy; malformed → empty | pytest tests/unit/test_parsers.py | done |
| 5 | Body classifiers | Cloudflare 1015 / OpenAI / Anthropic / Google / generic JSON; unknown → generic kinds | pytest tests/unit/test_bodies.py | done |
| 6 | Rules engine + confidence | YAML rules fire; conflict → lower confidence; no match → insufficient_evidence | pytest tests/unit/test_rules.py | done |
| 7 | Adapters (HAR/headers/curl-dump) | each parses to a common model; bad input → ParseError | pytest tests/unit/test_adapters.py | done |
| 8 | CLI + report | analyze; JSON export; exit codes 0/2/3 | pytest tests/integration/ | done |
| 9 | Adversarial suite | conflicting layers, ambiguous headers, 1,000 date cases, 10k-entry HAR, secret in log | pytest tests/adversarial/ | done |

## Quality gate (before packaging, M8)

- [x] Full suite green locally: 69 tests on Python 3.12.10 (56 at first release; regression tests added during release QA)
- [ ] Full suite green on declared matrix (Windows + Linux, Python 3.10/3.12/3.13) — CI
- [x] L4: fresh copy, `pip install -e ".[dev]"`, tests and CLI quickstart pass
- [x] L5: adversarial suite green
- [x] Static analysis (ruff), strict mypy, wheel build and clean-venv install
- [x] Perf budget: 10,000-entry HAR analyzed in under 2 s (tested)
- [x] Zero network calls by design (offline parser; no client code exists)
- [ ] Secrets scan over full git history (run before publish)
- [x] Manual review of user-facing messages, help text, and error paths

## Doctor-slot scheduling constraint (ADR-006, binding)

- [x] Operator selected this build explicitly (owner instruction 2026-10-25: complete all projects).

## Release

- [x] CHANGELOG (Keep a Changelog) and SemVer version 0.1.0
- [ ] SBOM (generated at release time; not required for the source push)
- [ ] PyPI publish via OIDC trusted publishing (G3 gate — not approved; not attempted)

## Salvage paths (if this build is deferred/killed later)

- R6-A salvage: express-rate-limit maxKeys PR (ledger row 58)
- R6-C salvage: upstream conformance-test pytest-helper (ledger row 60)
