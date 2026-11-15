package verifier_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"signer/internal/bundle"
	"signer/internal/keys"
	"signer/internal/signing"
	"signer/internal/trust"
	"signer/internal/verifier"
)

func TestFailurePrecedenceAndU10(t *testing.T) {
	original, err := os.ReadFile(fixturePath("bundles", "bundle_ed25519.json"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := bundle.Parse(original)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name          string
		manifest      []byte
		trust, status string
	}{
		{"unknown with malformed trust", bytes.Replace(b.Manifest, []byte("ed25519"), []byte("unknown"), 1), "trust_bad_pem.json", "FORMAT_ERROR"},
		{"duplicate", bytes.Replace(b.Manifest, []byte(`"version":"1.0.0"`), []byte(`"version":"1.0.0","version":"1.0.0"`), 1), "trust_full.json", "FORMAT_ERROR"},
		{"wrong type", bytes.Replace(b.Manifest, []byte(`"size":512`), []byte(`"size":true`), 1), "trust_full.json", "FORMAT_ERROR"},
		{"oversize", bytes.Repeat([]byte("x"), 16385), "trust_full.json", "FORMAT_ERROR"},
		{"signature before metadata", b.Manifest, "trust_full.json", "INVALID_SIGNATURE"},
		{"trust before signature", b.Manifest, "trust_empty.json", "KEY_NOT_TRUSTED"},
		{"different valid profile", bytes.Replace(b.Manifest, []byte("ed25519"), []byte("rsa-pss-sha256"), 1), "trust_full.json", "KEY_NOT_TRUSTED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sig := append([]byte{}, b.Signature...)
			sig[0] ^= 1
			raw, err := json.Marshal(map[string]string{"schema": bundle.Schema, "manifest_b64": base64.StdEncoding.EncodeToString(tc.manifest), "signature_b64": base64.StdEncoding.EncodeToString(sig)})
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "bundle.json")
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			r := verifyPaths(t, fixturePath("artifacts", "binary.bin"), path, fixturePath("trust", tc.trust), mainPackage, otherVersion)
			expectStatus(t, r, tc.status, false)
		})
	}
}
func testKeyIDFor(t *testing.T, key string) string {
	t.Helper()
	p, err := keys.LoadPublic(fixturePath("keys", key+".pub.pem"))
	if err != nil {
		t.Fatal(err)
	}
	id, err := keys.Fingerprint(p)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func TestRemoveKeyRevokesVerification(t *testing.T) {
	store, err := trust.Load(fixturePath("trust", "trust_full.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !store.Remove(testKeyIDFor(t, "ed25519")) {
		t.Fatal("key was not removed")
	}
	path := filepath.Join(t.TempDir(), "trust.json")
	if err := trust.SaveAtomic(path, store); err != nil {
		t.Fatal(err)
	}
	r := verifyPaths(t, fixturePath("artifacts", "binary.bin"), fixturePath("bundles", "bundle_ed25519.json"), path, mainPackage, testVersion)
	expectStatus(t, r, "KEY_NOT_TRUSTED", false)
}
func TestU14BothBundles(t *testing.T) {
	for _, p := range profiles {
		t.Run(p.name, func(t *testing.T) {
			var signatures [][]byte
			var manifestBytes []byte
			for i := 0; i < 2; i++ {
				path := filepath.Join(t.TempDir(), "bundle.json")
				r, err := signing.SignFile(fixturePath("artifacts", "binary.bin"), mainPackage, testVersion, fixturePath("keys", p.key+".key.pem"), path, false)
				if err != nil {
					t.Fatal(err)
				}
				if i == 0 {
					manifestBytes = r.ManifestBytes
				} else if !bytes.Equal(manifestBytes, r.ManifestBytes) {
					t.Fatal("different manifests")
				}
				signatures = append(signatures, r.Signature)
				verified := verifyPaths(t, fixturePath("artifacts", "binary.bin"), path, fixturePath("trust", "trust_full.json"), mainPackage, testVersion)
				expectStatus(t, verified, string(verifier.StatusOK), true)
			}
			equal := bytes.Equal(signatures[0], signatures[1])
			if equal != (p.algorithm == "ed25519") {
				t.Fatalf("unexpected equality: %v", equal)
			}
			t.Logf("identical signatures: %v", equal)
		})
	}
}

func TestU10MalformedBundleStatuses(t *testing.T) {
	for _, name := range []string{"bundle_duplicate_field.json", "bundle_b64_bad_char.json", "bundle_b64_unpadded.json", "bundle_b64_whitespace.json", "bundle_extra_field.json", "bundle_oversize.json"} {
		t.Run(name, func(t *testing.T) {
			r := verifyFixture(t, "binary.bin", name, "trust_full.json", mainPackage, testVersion)
			expectStatus(t, r, "FORMAT_ERROR", false)
		})
	}
}
