package verifier_test

import (
	"os"
	"path/filepath"
	"testing"

	"signer/internal/verifier"
)

const testdataDir = "../fixture/testdata"

const (
	mainPackage  = "contoh-app"
	otherPackage = "other-app"
	testVersion  = "1.0.0"
	otherVersion = "2.0.0"
)

type profileFixture struct {
	name      string
	algorithm string
	bundle    string
	key       string
}

var profiles = []profileFixture{
	{"ed25519", "ed25519", "bundle_ed25519.json", "ed25519"},
	{"ecdsa-p256", "ecdsa-p256-sha256", "bundle_ecdsa_p256_sha256.json", "ecdsa_p256"},
	{"rsa-pss", "rsa-pss-sha256", "bundle_rsa_pss_sha256.json", "rsa_pss_3072"},
}

func fixturePath(elements ...string) string {
	return filepath.Join(testdataDir, filepath.Join(elements...))
}

func tempArtifactNamed(t *testing.T, source string, targetName string) string {
	t.Helper()
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("read %s: %v", source, err)
	}
	path := filepath.Join(t.TempDir(), targetName)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func exitCodeFor(status string) int {
	switch status {
	case string(verifier.StatusOK):
		return 0
	case string(verifier.StatusInputError):
		return 2
	default:
		return 1
	}
}

func expectStatus(t *testing.T, result verifier.Result, status string, valid bool) {
	t.Helper()
	if result.Status != status {
		t.Fatalf("expected status %s, got %s (%s)", status, result.Status, result.Message)
	}
	if result.Valid != valid {
		t.Fatalf("expected valid=%v, got %v", valid, result.Valid)
	}
	if result.ExitCode() != exitCodeFor(status) {
		t.Fatalf("unexpected exit code %d for status %s", result.ExitCode(), result.Status)
	}
}
