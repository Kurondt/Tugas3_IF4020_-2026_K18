package crypto_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sigcrypto "signer/internal/crypto"
	"signer/internal/keys"
)

func TestGenerateAndSaveRoundtrip(t *testing.T) {
	for _, algorithm := range sigcrypto.ProfileNames() {
		t.Run(string(algorithm), func(t *testing.T) {
			dir := t.TempDir()
			prefix := filepath.Join(dir, "testkey")
			keyID, err := keys.GenerateAndSave(algorithm, prefix, false)
			if err != nil {
				t.Fatalf("generate: %v", err)
			}
			if len(keyID) != 64 {
				t.Fatalf("expected 64 character keyid, got %q", keyID)
			}
			private, err := keys.LoadPrivate(prefix + ".key.pem")
			if err != nil {
				t.Fatalf("load private: %v", err)
			}
			if _, err := sigcrypto.PrivateAlgorithm(private); err != nil {
				t.Fatalf("private algorithm: %v", err)
			}
			public, err := keys.LoadPublic(prefix + ".pub.pem")
			if err != nil {
				t.Fatalf("load public: %v", err)
			}
			algorithmOfPublic, err := sigcrypto.PublicAlgorithm(public)
			if err != nil {
				t.Fatalf("public algorithm: %v", err)
			}
			if algorithmOfPublic != algorithm {
				t.Fatalf("expected algorithm %s, got %s", algorithm, algorithmOfPublic)
			}
			fingerprint, err := keys.Fingerprint(public)
			if err != nil {
				t.Fatalf("fingerprint: %v", err)
			}
			if fingerprint != keyID {
				t.Fatalf("keyid mismatch: generated %s, recomputed %s", keyID, fingerprint)
			}
			info, err := os.Stat(prefix + ".key.pem")
			if err != nil {
				t.Fatalf("stat private key: %v", err)
			}
			if info.Mode().Perm() != 0o600 {
				t.Fatalf("expected private key mode 0600, got %v", info.Mode().Perm())
			}
		})
	}
}

func TestGenerateRejectsExistingFiles(t *testing.T) {
	dir := t.TempDir()
	prefix := filepath.Join(dir, "key")
	if _, err := keys.GenerateAndSave(sigcrypto.Ed25519, prefix, false); err != nil {
		t.Fatalf("first generate: %v", err)
	}
	if _, err := keys.GenerateAndSave(sigcrypto.Ed25519, prefix, false); err == nil {
		t.Fatal("expected second generate without force to fail")
	}
	if _, err := keys.GenerateAndSave(sigcrypto.Ed25519, prefix, true); err != nil {
		t.Fatalf("generate with force: %v", err)
	}
}

func TestFingerprintStableAcrossPEMLineEndings(t *testing.T) {
	public, err := keys.LoadPublic(fixturePath("keys", "ed25519.pub.pem"))
	if err != nil {
		t.Fatalf("load public: %v", err)
	}
	original, err := keys.Fingerprint(public)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	data, err := os.ReadFile(fixturePath("keys", "ed25519.pub.pem"))
	if err != nil {
		t.Fatalf("read pem: %v", err)
	}
	crlfPath := filepath.Join(t.TempDir(), "crlf.pub.pem")
	if err := os.WriteFile(crlfPath, bytes.ReplaceAll(data, []byte("\n"), []byte("\r\n")), 0o644); err != nil {
		t.Fatalf("write crlf pem: %v", err)
	}
	reloaded, err := keys.LoadPublic(crlfPath)
	if err != nil {
		t.Fatalf("load crlf pem: %v", err)
	}
	recomputed, err := keys.Fingerprint(reloaded)
	if err != nil {
		t.Fatalf("fingerprint crlf: %v", err)
	}
	if recomputed != original {
		t.Fatalf("keyid changed across PEM re-encoding: %s vs %s", original, recomputed)
	}
}

func TestLoadPrivateRejectsBadKeys(t *testing.T) {
	badKeys := []string{
		"rsa_2048.key.pem",
		"ec_p384.key.pem",
		"legacy_pkcs1.key.pem",
		"corrupted.key.pem",
	}
	for _, name := range badKeys {
		t.Run(name, func(t *testing.T) {
			_, err := keys.LoadPrivate(fixturePath("keys", "bad", name))
			if err == nil {
				t.Fatalf("expected load of %s to fail", name)
			}
		})
	}
	if _, err := keys.LoadPrivate(fixturePath("keys", "ed25519.pub.pem")); err == nil {
		t.Fatal("expected loading a public key as private to fail")
	}
	if _, err := keys.LoadPrivate(filepath.Join(t.TempDir(), "missing.key.pem")); err == nil {
		t.Fatal("expected loading a missing file to fail")
	}
}

func TestLoadPublicRejectsBadKeys(t *testing.T) {
	if _, err := keys.LoadPublic(fixturePath("keys", "bad", "ec_p384.pub.pem")); err == nil {
		t.Fatal("expected P-384 public key to fail profile validation")
	}
	if _, err := keys.LoadPublic(fixturePath("keys", "bad", "x25519.pub.pem")); err == nil {
		t.Fatal("expected X25519 public key to fail profile validation")
	}
	if _, err := keys.LoadPublic(fixturePath("keys", "ed25519.key.pem")); err == nil {
		t.Fatal("expected loading a private key as public to fail")
	}
}

func TestPEMLabels(t *testing.T) {
	privateData, err := os.ReadFile(fixturePath("keys", "ed25519.key.pem"))
	if err != nil {
		t.Fatalf("read private pem: %v", err)
	}
	if !strings.Contains(string(privateData), "-----BEGIN PRIVATE KEY-----") {
		t.Fatal("expected PKCS8 PEM label PRIVATE KEY")
	}
	publicData, err := os.ReadFile(fixturePath("keys", "ed25519.pub.pem"))
	if err != nil {
		t.Fatalf("read public pem: %v", err)
	}
	if !strings.Contains(string(publicData), "-----BEGIN PUBLIC KEY-----") {
		t.Fatal("expected SPKI PEM label PUBLIC KEY")
	}
	legacyData, err := os.ReadFile(fixturePath("keys", "bad", "legacy_pkcs1.key.pem"))
	if err != nil {
		t.Fatalf("read legacy pem: %v", err)
	}
	if !strings.Contains(string(legacyData), "-----BEGIN RSA PRIVATE KEY-----") {
		t.Fatal("expected legacy fixture to use RSA PRIVATE KEY label")
	}
}
