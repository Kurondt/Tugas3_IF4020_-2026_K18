# Fixture test data

All files in `testdata/` were generated once during setup and committed.
They exercise the contracts in `docs/API.md` without needing any member's implementation
to run first. Keys are test-only.

## Layout

- `keys/` — three profile key pairs (`ed25519`, `ecdsa_p256`, `rsa_pss_3072`) plus
  `*_other` same-profile pairs for the untrusted-key scenarios, and `keys/bad/`
  (`rsa_2048.key.pem` wrong modulus, `ec_p384.key.pem` wrong curve, `ec_p384.pub.pem`,
  `x25519.pub.pem` wrong type, `legacy_pkcs1.key.pem` wrong PEM label, `corrupted.key.pem`).
- `artifacts/` — `text.txt`, `binary.bin` (512 bytes incl. NULs), `empty.bin`, and
  mutants: `binary_bad_byte.bin` (same size, one bit flipped), `binary_truncated.bin`
  (byte removed), `binary_extended.bin` (byte appended).
- `manifests/` — canonical `valid.json` (ed25519 keyid, binary.bin) plus malformed
  variants listed in `manifest_test.go` (duplicate/extra/null fields, wrong types,
  boolean/float/exponent/leading-zero/`+`/negative/oversize numbers, missing fields,
  BOM, whitespace, trailing newline, `\uXXXX` escapes, bad patterns, oversize file,
  `unsupported_algo.json` which is format-valid but unknown-profile).
- `bundles/` — one valid bundle per profile over `binary.bin`
  (`bundle_ed25519.json`, `bundle_ecdsa_p256_sha256.json`, `bundle_rsa_pss_sha256.json`),
  `bundle_ed25519_second.json` (U14 second signing), `*_other_key.json` (U12: keyid is
  the other key, signed by the other key, absent from every trust store),
  `bundle_ed25519_sig_tampered.json` (U05), `bundle_ed25519_manifest_tampered.json`
  (U04: version `2.0.0`, old signature), `bundle_ecdsa_sig_r_zero.json` (out-of-domain
  r||s), `*_sig_short.json` (wrong lengths), `bundle_reordered.json` and
  `bundle_pretty.json` (U13: reformatted but byte-identical base64 payloads),
  plus malformed base64/field/schema/size variants.
- `trust/` — `trust_full.json` (all three publishers, `contoh-app`),
  `trust_ed25519_only.json`, `trust_other_pkg.json` (U07), `trust_empty.json` (U06),
  and 15 invalid stores (duplicate keyid, extra fields, fingerprint mismatch, bad
  algorithm, algorithm mismatch, empty/wildcard/duplicate packages, bad PEM, bad
  schema, malformed JSON, wrong types, uppercase keyid).

## Scenario mapping (spec Tabel 2.11)

| Scenario | Covered by |
|---|---|
| U01 sign+verify text/binary/empty × 3 algos | `verifier_test.TestVerifyOKForAllProfilesAndArtifactKinds`, fixture bundles |
| U02 change one byte | `binary_bad_byte.bin` → ARTIFACT_MISMATCH |
| U03 add/remove bytes | `binary_truncated.bin`, `binary_extended.bin` |
| U04 changed manifest version | `bundle_ed25519_manifest_tampered.json` |
| U05 flipped signature bit | `bundle_ed25519_sig_tampered.json` |
| U06 empty / removed key | `trust_empty.json` |
| U07 key for other package | `trust_other_pkg.json` |
| U08 wrong expected version | metadata mismatch test |
| U09 renamed artifact | rename test |
| U10 duplicate/typed/base64/oversize | all malformed manifest, bundle, trust fixtures |
| U11 unsupported algorithm | `unsupported_algo.json`, `bundle_unsupported_algo.json` |
| U12 other key, same profile | `*_other_key.json` bundles |
| U13 reformatted bundle JSON | `bundle_reordered.json`, `bundle_pretty.json` (OK) |
| U14 twice-signed manifest | `TestU14BothBundles` (all profiles) + fixed Ed25519 fixtures |

Treat the fixtures as fixed test data; regenerate only if a contract changes.
