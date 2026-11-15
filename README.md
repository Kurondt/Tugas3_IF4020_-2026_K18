# JARsign

Software release signing and verification tool for IF4020 Kriptografi — Chapter 3
(Penandatanganan dan Verifikasi Software Release). JARsign signs release manifests
with RSA-PSS, ECDSA P-256, or Ed25519, stores manifest + signature in a JSON bundle,
and verifies artifacts against a user-managed trust store. The flow adapts Sigstore
Cosign blob signing.

## Status — contracts, not implementations

This repository currently contains the **shared skeleton** only:

- data contracts: types, JSON tags, constants, patterns, and error values for every package,
- command wiring: `internal/cli` + `cmd/JARsign` are fully implemented and call the
  package functions with the right parameters,
- per-area test packages (`tests/crypto`, `tests/manifest`, `tests/bundle`, `tests/trust`,
  `tests/verifier`, `tests/integration`) and committed fixtures in `tests/fixture/testdata`.

Every implementation body is a stub that returns `contract.ErrNotImplemented`
(defined in `internal/contract`). Running any command therefore ends cleanly:

```sh
$ JARsign verify ...
verify: not implemented   # exit code 2
```

Each member implements their own packages (see the ownership table in
`docs/CONTRACTS.md`) until their package's tests pass. Do not change exported
signatures — the CLI wiring and all tests depend on them.

## Tech stack

- Go 1.27 (standard library only — `crypto/rsa`, `crypto/ecdsa`, `crypto/ed25519`,
  `crypto/x509`, `encoding/json`, `encoding/base64`, `encoding/pem`; no external dependencies).
- Distribution: distroless container image, linux/amd64.

## Library mapping (spec Tabel 2.5)

Guidance for the member implementing `internal/crypto`:

| Profile | Library call |
|---|---|
| `rsa-pss-sha256` | `rsa.SignPSS` / `rsa.VerifyPSS` with `PSSOptions{SaltLength: 32}`; SHA-256 applied once by the caller (`digestSHA256` in `internal/crypto`) |
| `ecdsa-p256-sha256` | `ecdsa.Sign` / `ecdsa.Verify` on the SHA-256 digest; DER→`r||s` conversion done in `internal/crypto/ecdsa.go` |
| `ed25519` | `ed25519.Sign` / `ed25519.Verify` on raw manifest bytes (RFC 8032 PureEdDSA) |
| Key formats | `x509.MarshalPKCS8PrivateKey` / `x509.MarshalPKIXPublicKey` + `encoding/pem` |
| keyid | `hex_lower(sha256(DER SPKI))` via `keys.Fingerprint` |

## Repository layout

```
cmd/JARsign        CLI entry point
internal/crypto    algorithm profiles, Signer/Verifier, key generation
internal/keys      PEM PKCS8/SPKI file IO, fingerprint/keyid
internal/jsonx     strict JSON decoding (duplicates, types, exact fields)
internal/manifest  release manifest contract + canonical serialization
internal/bundle    bundle contract + strict base64
internal/trust     trust store contract, add/remove/list, atomic save
internal/signing   sign command flow
internal/verifier  verification pipeline, statuses, result JSON
internal/cli       subcommand routing, one param struct per command
tests/crypto       crypto + keys tests (member A)
tests/manifest     manifest tests (member B)
tests/bundle       bundle tests (member B)
tests/trust        trust store tests (member C)
tests/verifier     verification pipeline tests (member D)
tests/integration  CLI end-to-end tests (member D)
tests/fixture      committed test fixtures
ci                 demo key + trust store for the consumer pipeline
docs/CONTRACTS.md  module contracts and task ownership
```

## Build and test

```sh
make build          # bin/JARsign
make test           # go test ./... — fails with "not implemented" until stubs are filled in
make test-race
make docker-build   # local image build
```

## CLI usage

```sh
JARsign keygen --algorithm ed25519 --out keys/publisher
JARsign trust add --key keys/publisher.pub.pem --package contoh-app --store trust.json
JARsign trust list --store trust.json
JARsign trust remove --keyid <fingerprint> --store trust.json
JARsign sign --file contoh-app.zip --package contoh-app --version 1.0.0 \
  --key keys/publisher.key.pem --out release.json
JARsign verify --file contoh-app.zip --bundle release.json --trust-store trust.json \
  --package contoh-app --version 1.0.0 --json
JARsign --help
JARsign --version
```

`verify --json` prints one JSON object (`valid`, `status`, `message`, `algorithm`,
`keyid`, `package`, `version`) to stdout; exit code `0` only for `OK`, `1` for a
rejected verification, `2` for usage/I-O errors. `--force` is the documented
explicit option for overwriting existing key or bundle files.

## Container usage

```sh
docker pull ghcr.io/kurondt/jarsign:1.0.0   # or pin by digest, see below
docker run --rm --network none \
  --user "$(id -u):$(id -g)" \
  -v "$PWD/dist:/input:ro" \
  -v "$PWD/out:/output" \
  -v "$PWD/ci/trust.json:/trust.json:ro" \
  ghcr.io/kurondt/jarsign:1.0.0 \
  verify --file /input/contoh-app.zip --bundle /output/release.json \
  --trust-store /trust.json --package contoh-app --version 1.0.0 --json
```

| Release | Tag | Digest |
|---|---|---|
| 1.0.0 | `ghcr.io/kurondt/jarsign:1.0.0` | `sha256:9b3719f07978fc3cf43e92fb3b8e1cd8f34f2ba768992871ac2b7487ca26cc68` |

## CI/CD

- `.github/workflows/release-image.yml` — builds and pushes the image on `v*` tags,
  records the digest, and smoke-tests it with `--network none`.
- `.github/workflows/pipeline-consumer.yml` — the consumer pipeline (spec Tabel 2.14):
  prepare → sign with a key from CI secret (`CONSUMER_SIGNING_KEY`) → verify `--json`
  against `ci/trust.json` → simulated deployment marker → negative scenarios C02–C05
  that must keep failing as specified.
- `ci/keys/consumer.key.pem` is **not committed** (see `.gitignore`): per the spec the
  pipeline private key lives in the CI secret mechanism. Put its content into the
  `CONSUMER_SIGNING_KEY` repository secret; the matching public key and trust store
  (`ci/keys/consumer.pub.pem`, `ci/trust.json`) are committed.

## Testing

```sh
go test ./...            # everything
```

Each area has its own test package, so members can test without waiting for each other:

| Member | Area | Run only your tests |
|---|---|---|
| A | crypto + keys | `go test ./tests/crypto` |
| B | manifest + bundle | `go test ./tests/manifest ./tests/bundle` |
| C | trust store | `go test ./tests/trust` |
| D | verify flow + CLI | `go test ./tests/verifier ./tests/integration` |

`tests/crypto`, `tests/manifest`, `tests/bundle`, and `tests/trust` depend only on their
own packages plus committed fixtures. `tests/verifier` and `tests/integration` exercise the
whole pipeline and go green last, when A, B, and C are done. Until a stub is implemented
its tests fail with a clean `not implemented` error — no panics, no compile errors.

- `tests/unit` coverage per spec scenario U01–U14 lives in the per-area packages above;
  see `tests/fixture/README.md` for the fixture↔scenario map. Fixtures are committed
  data — do not delete them.
- `tests/interoperability` — per-algorithm cross-check with an independent
  implementation (planned work, see its README).
- Demo keys under `ci/keys` and `tests/fixture/testdata/keys` are generated for
  this assignment only and are not real credentials.
