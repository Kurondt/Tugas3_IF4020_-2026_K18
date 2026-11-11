package integration

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"

	"signer/internal/cli"
)

func runCLI(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	code := cli.Main(args, stdout, stderr)
	return stdout.String(), stderr.String(), code
}

func TestHelpAndVersion(t *testing.T) {
	if _, _, code := runCLI(t, "--help"); code != 0 {
		t.Fatalf("expected --help exit 0, got %d", code)
	}
	if _, _, code := runCLI(t, "--version"); code != 0 {
		t.Fatalf("expected --version exit 0, got %d", code)
	}
	if _, stderr, code := runCLI(t); code != 2 || stderr == "" {
		t.Fatalf("expected no command to exit 2 with usage, got code=%d", code)
	}
	if _, stderr, code := runCLI(t, "bogus"); code != 2 || stderr == "" {
		t.Fatalf("expected unknown command to exit 2, got %d", code)
	}
}

func TestKeygenCommand(t *testing.T) {
	dir := t.TempDir()
	prefix := filepath.Join(dir, "keys", "pub")
	stdout, _, code := runCLI(t, "keygen", "--algorithm", "ed25519", "--out", prefix)
	if code != 0 {
		t.Fatalf("keygen exit %d", code)
	}
	if !bytes.Contains([]byte(stdout), []byte("keyid: ")) {
		t.Fatalf("keygen must print keyid, got %s", stdout)
	}
	_, _, code = runCLI(t, "keygen", "--algorithm", "ed25519", "--out", prefix)
	if code != 2 {
		t.Fatalf("expected overwrite failure exit 2, got %d", code)
	}
	_, _, code = runCLI(t, "keygen", "--algorithm", "ed25519", "--out", prefix, "--force")
	if code != 0 {
		t.Fatalf("expected forced overwrite exit 0, got %d", code)
	}
	_, _, code = runCLI(t, "keygen", "--algorithm", "dsa-sha1", "--out", filepath.Join(dir, "bad"))
	if code != 2 {
		t.Fatalf("expected unsupported algorithm exit 2, got %d", code)
	}
	_, _, code = runCLI(t, "keygen", "--out", filepath.Join(dir, "x"))
	if code != 2 {
		t.Fatalf("expected missing --algorithm exit 2, got %d", code)
	}
}

func TestFullFlowForAllAlgorithms(t *testing.T) {
	for _, algorithm := range []string{"ed25519", "ecdsa-p256-sha256", "rsa-pss-sha256"} {
		t.Run(algorithm, func(t *testing.T) {
			dir := t.TempDir()
			prefix := filepath.Join(dir, "keys", "pub")
			if _, _, code := runCLI(t, "keygen", "--algorithm", algorithm, "--out", prefix); code != 0 {
				t.Fatal("keygen failed")
			}
			if _, _, code := runCLI(t, "trust", "add", "--key", prefix+".pub.pem", "--package", "contoh-app", "--store", filepath.Join(dir, "trust.json")); code != 0 {
				t.Fatal("trust add failed")
			}
			stdout, _, code := runCLI(t, "sign", "--file", "../fixture/testdata/artifacts/text.txt", "--package", "contoh-app", "--version", "1.0.0", "--key", prefix+".key.pem", "--out", filepath.Join(dir, "release.json"))
			if code != 0 {
				t.Fatalf("sign failed: %s", stdout)
			}
			stdout, _, code = runCLI(t, "verify", "--file", "../fixture/testdata/artifacts/text.txt", "--bundle", filepath.Join(dir, "release.json"), "--trust-store", filepath.Join(dir, "trust.json"), "--package", "contoh-app", "--version", "1.0.0", "--json")
			if code != 0 {
				t.Fatalf("verify failed: %s", stdout)
			}
			var result map[string]any
			if err := json.Unmarshal([]byte(stdout), &result); err != nil {
				t.Fatalf("verify --json output is not one JSON object: %v (%s)", err, stdout)
			}
			if result["valid"] != true || result["status"] != "OK" {
				t.Fatalf("unexpected verify result: %s", stdout)
			}
		})
	}
}

func TestSignRejectsBadInputs(t *testing.T) {
	dir := t.TempDir()
	if _, _, code := runCLI(t, "sign", "--file", filepath.Join(dir, "missing.bin"), "--package", "contoh-app", "--version", "1.0.0", "--key", "../fixture/testdata/keys/ed25519.key.pem", "--out", filepath.Join(dir, "b.json")); code != 2 {
		t.Fatalf("expected missing artifact exit 2, got %d", code)
	}
	if _, _, code := runCLI(t, "sign", "--file", "../fixture/testdata/artifacts/text.txt", "--package", "Bad-Package", "--version", "1.0.0", "--key", "../fixture/testdata/keys/ed25519.key.pem", "--out", filepath.Join(dir, "b.json")); code != 2 {
		t.Fatalf("expected invalid package exit 2, got %d", code)
	}
	if _, _, code := runCLI(t, "sign", "--file", "../fixture/testdata/artifacts/text.txt", "--package", "contoh-app", "--version", "1.0.0", "--key", "../fixture/testdata/keys/ed25519.key.pem"); code != 2 {
		t.Fatalf("expected missing --out exit 2, got %d", code)
	}
}

func TestVerifyTamperedArtifactExitCodes(t *testing.T) {
	dir := t.TempDir()
	if _, _, code := runCLI(t, "sign", "--file", "../fixture/testdata/artifacts/binary.bin", "--package", "contoh-app", "--version", "1.0.0", "--key", "../fixture/testdata/keys/ed25519.key.pem", "--out", filepath.Join(dir, "release.json")); code != 0 {
		t.Fatal("sign failed")
	}
	if err := copyTrust(filepath.Join(dir, "trust.json")); err != nil {
		t.Fatalf("copy trust: %v", err)
	}
	stdout, _, code := runCLI(t, "verify", "--file", "../fixture/testdata/artifacts/binary_bad_byte.bin", "--bundle", filepath.Join(dir, "release.json"), "--trust-store", filepath.Join(dir, "trust.json"), "--package", "contoh-app", "--version", "1.0.0", "--json")
	if code != 1 {
		t.Fatalf("expected tampered verify exit 1, got %d", code)
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("invalid JSON: %v (%s)", err, stdout)
	}
	if result["valid"] != false || result["status"] == "OK" {
		t.Fatalf("unexpected tampered result: %s", stdout)
	}
}

func TestTrustCommands(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "trust.json")
	if _, _, code := runCLI(t, "trust", "add", "--key", "../fixture/testdata/keys/ed25519.pub.pem", "--package", "contoh-app", "--store", store); code != 0 {
		t.Fatal("trust add on missing store failed")
	}
	stdout, _, code := runCLI(t, "trust", "add", "--key", "../fixture/testdata/keys/ed25519.pub.pem", "--package", "contoh-app", "--store", store)
	if code != 0 {
		t.Fatal("idempotent trust add failed")
	}
	if !bytes.Contains([]byte(stdout), []byte("unchanged")) {
		t.Fatalf("expected idempotent add status unchanged, got %s", stdout)
	}
	stdout, _, code = runCLI(t, "trust", "add", "--key", "../fixture/testdata/keys/ed25519.pub.pem", "--package", "other-app", "--store", store)
	if code != 0 {
		t.Fatal("package merge add failed")
	}
	if !bytes.Contains([]byte(stdout), []byte("other-app")) {
		t.Fatalf("expected merged package in output, got %s", stdout)
	}
	stdout, _, code = runCLI(t, "trust", "list", "--store", store)
	if code != 0 || !bytes.Contains([]byte(stdout), []byte("ed25519")) {
		t.Fatalf("trust list failed: %s", stdout)
	}
	keyID := firstToken(t, stdout)
	_, _, code = runCLI(t, "trust", "remove", "--keyid", keyID, "--store", store)
	if code != 0 {
		t.Fatal("trust remove failed")
	}
	_, stderr, code := runCLI(t, "trust", "remove", "--keyid", keyID, "--store", store)
	if code != 2 || stderr == "" {
		t.Fatalf("expected missing keyid exit 2, got %d", code)
	}
	_, _, code = runCLI(t, "trust", "list", "--store", store)
	if code != 0 {
		t.Fatal("trust list after remove failed")
	}
	_, _, code = runCLI(t, "trust", "add", "--key", "../fixture/testdata/keys/ed25519.pub.pem", "--package", "Bad", "--store", store)
	if code != 2 {
		t.Fatalf("expected invalid package exit 2, got %d", code)
	}
}

func TestVerifyUsageErrors(t *testing.T) {
	stdout, _, code := runCLI(t, "verify", "--json")
	if code != 2 {
		t.Fatalf("expected missing parameters exit 2, got %d", code)
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("expected JSON INPUT_ERROR result, got %s", stdout)
	}
	if result["status"] != "INPUT_ERROR" {
		t.Fatalf("expected INPUT_ERROR status, got %s", stdout)
	}
	if _, _, code := runCLI(t, "sign", "--bogus", "x"); code != 2 {
		t.Fatalf("expected unknown flag exit 2, got %d", code)
	}
}
