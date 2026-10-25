# ROADMAP — ratelimit-forensics

SemVer from day one. Keep a Changelog format.

## v0.1 Walking skeleton (first build slice)

**Exit criteria:**
- [ ] CLI: `ratelimit-forensics analyze --headers|--har|--curl-dump` works offline
- [ ] Parsers: X-RateLimit-*, RateLimit-* (split + IETF draft-8), Retry-After (delta vs HTTP-date)
- [ ] Body classifiers: Cloudflare error 1015, OpenAI/Anthropic structured errors
- [ ] Attribution: edge/gateway/app/upstream with confidence + evidence trace
- [ ] Rules-as-data: versioned YAML, user-overridable
- [ ] Redaction: secrets stripped before parse
- [ ] "Insufficient evidence" state
- [ ] L1 unit + L2 integration green (synthetic 429 fixtures: local Express/Flask + mocklimit templates vendored)
- [ ] L4: README quickstart from clean clone
- [ ] CI green on Windows + Linux (GitHub Actions)

**Riskiest assumption spiked first:** can local synthetic 429s (Express rate-limit + nginx limit_req in container) reproduce the header drift patterns (GitLab #378212) with enough fidelity for attribution rules to fire? [UNKNOWN → Gate 0 spike]

## v0.5 Core value

**Exit criteria:**
- [ ] OpenAI dual-dimension + Anthropic anthropic-ratelimit-* parsers
- [ ] Google structured-error body classifier
- [ ] Access-log line correlation (tiebreaker)
- [ ] HAR streaming for >50MB files
- [ ] JSON + SARIF export
- [ ] L5 adversarial suite green (malformed headers, HTTP-date Retry-After, conflicting layers, secret-in-log)

## v1.0 Production-ready

**Exit criteria:**
- [ ] Full L4 matrix (Windows + Linux, Python 3.10/3.12)
- [ ] Performance budget verified: 10k-line HAR <2s
- [ ] Security pass: dependency vuln scan, secrets scan (full history), license scan
- [ ] Docs complete: CONTRIBUTING, SECURITY, CODE_OF_CONDUCT, SUPPORT
- [ ] Signed release + SBOM
- [ ] Recurring hook **designed** (proxy/CI/Slack) — implementation may be v1.1 or separate repo if scope explodes

## v1.1+ (post-1.0, parked not promised)

- Recurring hook implementation (proxy mode / GitHub Action / Slack-alert)
- Watch mode on live local traffic (opt-in)
- Prometheus metrics export
- IETF RateLimit-Policy full parsing
- Non-HTTP (gRPC/WebSocket) — only if demand evidence appears

## Risk-first spikes (do before committing to v0.1 build order)

1. **Fixture fidelity spike**: generate synthetic 429s locally (Express + nginx container if available, else pure-Express + Flask); confirm header/body patterns match attribution rules. Record in EVIDENCE.md.
2. **Redaction spike**: verify no secrets leak from a realistic access-log line containing `Authorization: Bearer sk-...` through the full pipeline.
3. **Retry-After disambiguation spike**: property test (Hypothesis) for delta-seconds vs HTTP-date parsing across edge cases.

## Success metrics (measurable)

- Attribution accuracy on fixture matrix ≥90% (L2)
- "Insufficient evidence" fires on 100% of ambiguous cases, 0% wrong-confident verdicts (L5)
- Clean-clone README quickstart works (L4)
- 10k-line HAR <2s (perf budget)
