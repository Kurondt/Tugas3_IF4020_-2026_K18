package sbom_test

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"signer/internal/sbom"
	"signer/internal/signing"
	"signer/internal/verifier"
)

func TestSBOMAllProfiles(t *testing.T) {
	for _, key := range []string{"ed25519", "ecdsa_p256", "rsa_pss_3072"} {
		t.Run(key, func(t *testing.T) {
			dir := t.TempDir()
			artifact := filepath.Join(dir, "release.bin")
			inventory := filepath.Join(dir, "sbom.json")
			rb := filepath.Join(dir, "release.json")
			sb := filepath.Join(dir, "sbom-bundle.json")
			keyPath := "../fixture/testdata/keys/" + key + ".key.pem"
			write := func(p string, b []byte) {
				t.Helper()
				if err := os.WriteFile(p, b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			payload := []byte("release")
			write(artifact, payload)
			hash := sha256.Sum256(payload)
			doc := []byte(fmt.Sprintf(`{"schema":"norsign-sbom/v1","artifact":{"sha256":"%x"},"components":[{"name":"norsign","version":"1.0.0"}]}`, hash))
			write(inventory, doc)
			if _, err := signing.SignFile(artifact, "contoh-app", "1.0.0", keyPath, rb, false); err != nil {
				t.Fatal(err)
			}
			if _, err := sbom.SignFile(inventory, artifact, "contoh-app", "1.0.0", keyPath, sb, false); err != nil {
				t.Fatal(err)
			}
			req := sbom.Request{Release: verifier.Request{ArtifactPath: artifact, BundlePath: rb, TrustStorePath: "../fixture/testdata/trust/trust_full.json", Package: "contoh-app", Version: "1.0.0"}, SBOMPath: inventory, SBOMBundlePath: sb}
			check := func(want string) {
				t.Helper()
				r, err := sbom.Run(req)
				if err != nil || r.Status != want {
					t.Fatalf("want %s: %+v %v", want, r, err)
				}
			}
			check("OK")
			changed := append([]byte{}, doc...)
			changed[len(changed)-5] ^= 1
			write(inventory, changed)
			check("ARTIFACT_MISMATCH")
			write(inventory, doc)
			write(artifact, []byte("another"))
			check("ARTIFACT_MISMATCH")
			if _, err := signing.SignFile(artifact, "contoh-app", "1.0.0", keyPath, rb, true); err != nil {
				t.Fatal(err)
			}
			check("SBOM_BINDING_MISMATCH")
			if _, err := sbom.SignFile(inventory, artifact, "contoh-app", "1.0.0", keyPath, sb, true); err == nil {
				t.Fatal("signed wrong binding")
			}
			req.Release.TrustStorePath = "../fixture/testdata/trust/trust_empty.json"
			check("KEY_NOT_TRUSTED")
		})
	}
}
func TestInvalidSBOM(t *testing.T) {
	for _, s := range []string{`{}`, `{"schema":"norsign-sbom/v1","artifact":{"sha256":"bad"},"components":[]}`, `{"schema":"norsign-sbom/v1","artifact":{"sha256":"` + fmt.Sprintf("%064d", 0) + `"},"components":[{"name":"","version":"1"}]}`, `{"schema":"norsign-sbom/v1","artifact":{"sha256":"` + fmt.Sprintf("%064d", 0) + `"},"components":null}`} {
		if _, err := sbom.Parse([]byte(s)); err == nil {
			t.Fatalf("accepted %s", s)
		}
	}
}

func TestAuthenticatedInvalidSchema(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "app.bin")
	inventory := filepath.Join(dir, "sbom.json")
	rb := filepath.Join(dir, "release.json")
	sb := filepath.Join(dir, "sbom-bundle.json")
	for path, data := range map[string][]byte{artifact: []byte("payload"), inventory: []byte(`{"wrong":"schema"}`)} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	key := "../fixture/testdata/keys/ed25519.key.pem"
	for path, out := range map[string]string{artifact: rb, inventory: sb} {
		if _, err := signing.SignFile(path, "contoh-app", "1.0.0", key, out, false); err != nil {
			t.Fatal(err)
		}
	}
	result, err := sbom.Run(sbom.Request{Release: verifier.Request{ArtifactPath: artifact, BundlePath: rb, TrustStorePath: "../fixture/testdata/trust/trust_full.json", Package: "contoh-app", Version: "1.0.0"}, SBOMPath: inventory, SBOMBundlePath: sb})
	if err != nil || result.Status != "FORMAT_ERROR" || result.Release == nil || !result.Release.Valid || result.SBOM == nil || !result.SBOM.Valid {
		t.Fatalf("unexpected result: %+v %v", result, err)
	}
}
