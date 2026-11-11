package verifier_test

import (
	"path/filepath"
	"testing"

	"signer/internal/signing"
	"signer/internal/verifier"
)

func signTemp(t *testing.T, profile profileFixture, artifactPath string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "bundle.json")
	if _, err := signing.SignFile(artifactPath, mainPackage, testVersion, fixturePath("keys", profile.key+".key.pem"), out, false); err != nil {
		t.Fatalf("sign %s with %s: %v", artifactPath, profile.key, err)
	}
	return out
}

func verifyPaths(t *testing.T, artifactPath string, bundlePath string, trustPath string, pkg string, version string) verifier.Result {
	t.Helper()
	result, err := verifier.Run(verifier.Request{
		ArtifactPath:   artifactPath,
		BundlePath:     bundlePath,
		TrustStorePath: trustPath,
		Package:        pkg,
		Version:        version,
	})
	if err != nil {
		t.Fatalf("verify run failed unexpectedly: %v", err)
	}
	return result
}

func verifyFixture(t *testing.T, artifactName string, bundleName string, trustName string, pkg string, version string) verifier.Result {
	t.Helper()
	return verifyPaths(t, fixturePath("artifacts", artifactName), fixturePath("bundles", bundleName), fixturePath("trust", trustName), pkg, version)
}

func TestVerifyOKForAllProfilesAndArtifactKinds(t *testing.T) {
	for _, profile := range profiles {
		t.Run(profile.name, func(t *testing.T) {
			for _, artifact := range []string{"text.txt", "binary.bin", "empty.bin"} {
				bundlePath := signTemp(t, profile, fixturePath("artifacts", artifact))
				result := verifyPaths(t, fixturePath("artifacts", artifact), bundlePath, fixturePath("trust", "trust_full.json"), mainPackage, testVersion)
				expectStatus(t, result, string(verifier.StatusOK), true)
			}
		})
	}
}

func TestVerifyFixtureBundles(t *testing.T) {
	for _, profile := range profiles {
		t.Run(profile.name, func(t *testing.T) {
			result := verifyFixture(t, "binary.bin", profile.bundle, "trust_full.json", mainPackage, testVersion)
			expectStatus(t, result, string(verifier.StatusOK), true)
			if result.Algorithm == nil || *result.Algorithm != profile.algorithm {
				t.Fatalf("unexpected algorithm field: %v", result.Algorithm)
			}
			if result.KeyID == nil || len(*result.KeyID) != 64 {
				t.Fatalf("unexpected keyid field: %v", result.KeyID)
			}
		})
	}
}

func TestInputErrors(t *testing.T) {
	cases := []struct {
		name     string
		artifact string
		bundle   string
		trust    string
	}{
		{"missing artifact", filepath.Join(t.TempDir(), "gone.bin"), "bundle_ed25519.json", "trust_full.json"},
		{"missing bundle", "binary.bin", "nope.json", "trust_full.json"},
		{"missing trust store", "binary.bin", "bundle_ed25519.json", "nope.json"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			result := verifyFixture(t, testCase.artifact, testCase.bundle, testCase.trust, mainPackage, testVersion)
			expectStatus(t, result, string(verifier.StatusInputError), false)
			if result.Algorithm != nil {
				t.Fatal("algorithm must be null on INPUT_ERROR")
			}
			if result.Package != nil || result.Version != nil || result.KeyID != nil {
				t.Fatal("manifest fields must be null on INPUT_ERROR")
			}
		})
	}
}

func TestArtifactTampering(t *testing.T) {
	mutated := []string{"binary_bad_byte.bin", "binary_truncated.bin", "binary_extended.bin"}
	for _, name := range mutated {
		t.Run(name, func(t *testing.T) {
			copyPath := tempArtifactNamed(t, fixturePath("artifacts", name), "binary.bin")
			result := verifyPaths(t, copyPath, fixturePath("bundles", "bundle_ed25519.json"), fixturePath("trust", "trust_full.json"), mainPackage, testVersion)
			expectStatus(t, result, string(verifier.StatusArtifactMismatch), false)
		})
	}
}

func TestManifestTampering(t *testing.T) {
	result := verifyFixture(t, "binary.bin", "bundle_ed25519_manifest_tampered.json", "trust_full.json", mainPackage, otherVersion)
	expectStatus(t, result, string(verifier.StatusInvalidSignature), false)
}

func TestSignatureTampering(t *testing.T) {
	result := verifyFixture(t, "binary.bin", "bundle_ed25519_sig_tampered.json", "trust_full.json", mainPackage, testVersion)
	expectStatus(t, result, string(verifier.StatusInvalidSignature), false)
}

func TestSignatureLengthAndDomainErrors(t *testing.T) {
	cases := []string{
		"bundle_ecdsa_sig_r_zero.json",
		"bundle_ed25519_sig_short.json",
		"bundle_rsa_sig_short.json",
		"bundle_empty_signature.json",
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			result := verifyFixture(t, "binary.bin", name, "trust_full.json", mainPackage, testVersion)
			expectStatus(t, result, string(verifier.StatusInvalidSignature), false)
		})
	}
}

func TestEmptyTrustStore(t *testing.T) {
	result := verifyFixture(t, "binary.bin", "bundle_ed25519.json", "trust_empty.json", mainPackage, testVersion)
	expectStatus(t, result, string(verifier.StatusKeyNotTrusted), false)
}

func TestMinimalTrustStoreSuffices(t *testing.T) {
	result := verifyFixture(t, "binary.bin", "bundle_ed25519.json", "trust_ed25519_only.json", mainPackage, testVersion)
	expectStatus(t, result, string(verifier.StatusOK), true)
}

func TestKeyNotAllowedForPackage(t *testing.T) {
	result := verifyFixture(t, "binary.bin", "bundle_ed25519.json", "trust_other_pkg.json", mainPackage, testVersion)
	expectStatus(t, result, string(verifier.StatusKeyNotTrusted), false)
}

func TestMetadataVersionMismatch(t *testing.T) {
	result := verifyFixture(t, "binary.bin", "bundle_ed25519.json", "trust_full.json", mainPackage, otherVersion)
	expectStatus(t, result, string(verifier.StatusMetadataMismatch), false)
}

func TestMetadataPackageMismatch(t *testing.T) {
	result := verifyFixture(t, "binary.bin", "bundle_ed25519.json", "trust_full.json", otherPackage, testVersion)
	expectStatus(t, result, string(verifier.StatusKeyNotTrusted), false)
}

func TestRenamedArtifact(t *testing.T) {
	renamed := tempArtifactNamed(t, fixturePath("artifacts", "binary.bin"), "renamed.bin")
	result := verifyPaths(t, renamed, fixturePath("bundles", "bundle_ed25519.json"), fixturePath("trust", "trust_full.json"), mainPackage, testVersion)
	expectStatus(t, result, string(verifier.StatusMetadataMismatch), false)
}

func TestUnsupportedAlgorithm(t *testing.T) {
	result := verifyFixture(t, "binary.bin", "bundle_unsupported_algo.json", "trust_full.json", mainPackage, testVersion)
	expectStatus(t, result, string(verifier.StatusUnsupportedAlgorithm), false)
}

func TestSigningWithUntrustedKey(t *testing.T) {
	cases := []string{
		"bundle_ed25519_other_key.json",
		"bundle_ecdsa_p256_sha256_other_key.json",
		"bundle_rsa_pss_sha256_other_key.json",
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			result := verifyFixture(t, "binary.bin", name, "trust_full.json", mainPackage, testVersion)
			expectStatus(t, result, string(verifier.StatusKeyNotTrusted), false)
		})
	}
}

func TestReformattedBundlesStillVerify(t *testing.T) {
	for _, name := range []string{"bundle_reordered.json", "bundle_pretty.json"} {
		t.Run(name, func(t *testing.T) {
			result := verifyFixture(t, "binary.bin", name, "trust_full.json", mainPackage, testVersion)
			expectStatus(t, result, string(verifier.StatusOK), true)
		})
	}
}

func TestSecondSignatureVerifies(t *testing.T) {
	result := verifyFixture(t, "binary.bin", "bundle_ed25519_second.json", "trust_full.json", mainPackage, testVersion)
	expectStatus(t, result, string(verifier.StatusOK), true)
}

func TestSignThenVerifyChangedVersionMetadata(t *testing.T) {
	bundlePath := signTemp(t, profiles[0], fixturePath("artifacts", "binary.bin"))
	result := verifyPaths(t, fixturePath("artifacts", "binary.bin"), bundlePath, fixturePath("trust", "trust_full.json"), mainPackage, otherVersion)
	expectStatus(t, result, string(verifier.StatusMetadataMismatch), false)
}
