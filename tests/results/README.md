# Recorded local validation

Recorded at 2026-11-15T07:12:26.924355+00:00. Base revision: `3c383b4`; local `main` includes fetched `origin/main`. Source changes are uncommitted; `validation.json` records exact Go-source hashes.

All **208 Go tests and subtests** passed across 10 test packages, with no skipped individual tests. Packages without their own test files are reported as package-level skips by Go. The race detector also passed.

| Check | Result | Evidence |
|---|---|---|
| Build, formatting, vet, Go tests, race tests, Python orchestration | Passed | [local-checks.log](local-checks.log) |
| Full uncached Go test event stream | Passed | [tests.jsonl](tests.jsonl) |
| OpenSSL interoperability, both directions × three profiles | Passed | `TestOpenSSL` in tests.jsonl |
| GitHub workflow syntax, actionlint v1.7.7 | Passed; no diagnostics | [workflows.log](workflows.log) |
| Static API HTML generation, Pandoc | Passed | [docs.log](docs.log) |
| Performance | 1,365 measured samples | [benchmark.log](benchmark.log), [raw CSV](benchmark/raw.csv), [summary](benchmark/summary.json), [sizes](benchmark/sizes.json), [environment](benchmark/environment.json) |
| Real Docker execution / C01–C05 | Pending | Docker Desktop WSL integration unavailable |
| Public image digest and remote workflow run URLs | Pending | Publishing was excluded from this local task |
| Public API documentation hosting | Pending | Manual workflow prepared |

The Python orchestration tests run the real local CLI through a Docker command adapter. They validate expected statuses, deployment gates, and secret cleanup; they do not substitute for real container/registry evidence.

## Test packages

| Package | Passed tests/subtests |
|---|---|
| `signer/tests/bundle` | 19 |
| `signer/tests/crypto` | 29 |
| `signer/tests/integration` | 11 |
| `signer/tests/interoperability` | 4 |
| `signer/tests/jsonx` | 9 |
| `signer/tests/manifest` | 44 |
| `signer/tests/sbom` | 6 |
| `signer/tests/signing` | 1 |
| `signer/tests/trust` | 26 |
| `signer/tests/verifier` | 59 |

## Benchmark excerpt

At 1 MiB, times below are milliseconds shown as median / nearest-rank P95. Read the complete raw data and environment before comparing algorithms.

| Profile | Keygen (5 samples) | Manifest sign | Manifest verify | CLI sign | CLI verify |
|---|---|---|---|---|---|
| `rsa-pss-sha256` | 214.4560 / 630.1465 | 3.0534 / 3.8198 | 0.1441 / 0.2269 | 9.8337 / 10.7135 | 6.0275 / 6.7441 |
| `ecdsa-p256-sha256` | 0.0188 / 0.1194 | 0.0370 / 0.0897 | 0.0805 / 0.0983 | 5.5768 / 6.2010 | 5.3380 / 6.1722 |
| `ed25519` | 0.0186 / 1.1265 | 0.0218 / 0.0295 | 0.0504 / 0.0565 | 6.0505 / 7.3409 | 5.2727 / 5.8588 |

These local measurements include system noise and do not establish general performance rankings. The methodology is documented in [TESTING.md](../../docs/TESTING.md#benchmarks).
