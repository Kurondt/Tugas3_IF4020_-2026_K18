package interoperability_test

import (
	"encoding/asn1"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"signer/internal/bundle"
	sigcrypto "signer/internal/crypto"
	"signer/internal/keys"
	"signer/internal/signing"
	"signer/internal/verifier"
)

func TestOpenSSL(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Fatal("OpenSSL is required for interoperability tests")
	}
	profiles := []struct{ key, alg string }{{"rsa_pss_3072", "rsa-pss-sha256"}, {"ecdsa_p256", "ecdsa-p256-sha256"}, {"ed25519", "ed25519"}}
	fixture := func(parts ...string) string {
		return filepath.Join(append([]string{"..", "fixture", "testdata"}, parts...)...)
	}
	for _, p := range profiles {
		t.Run(p.alg, func(t *testing.T) {
			dir := t.TempDir()
			result, err := signing.SignFile(fixture("artifacts", "binary.bin"), "contoh-app", "1.0.0", fixture("keys", p.key+".key.pem"), filepath.Join(dir, "go.json"), false)
			if err != nil {
				t.Fatal(err)
			}
			m, s := filepath.Join(dir, "manifest"), filepath.Join(dir, "sig")
			if err := os.WriteFile(m, result.ManifestBytes, 0600); err != nil {
				t.Fatal(err)
			}
			sig := result.Signature
			if p.alg == "ecdsa-p256-sha256" {
				sig, err = asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])})
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(s, sig, 0600); err != nil {
				t.Fatal(err)
			}
			options := []string{"-rawin"}
			if p.alg != "ed25519" {
				options = append(options, "-digest", "sha256")
			}
			if p.alg == "rsa-pss-sha256" {
				options = append(options, "-pkeyopt", "rsa_padding_mode:pss", "-pkeyopt", "rsa_pss_saltlen:32", "-pkeyopt", "rsa_mgf1_md:sha256")
			}
			args := append([]string{"pkeyutl", "-verify", "-pubin", "-inkey", fixture("keys", p.key+".pub.pem"), "-in", m, "-sigfile", s}, options...)
			if out, err := exec.Command("openssl", args...).CombinedOutput(); err != nil {
				t.Fatalf("Go -> OpenSSL: %v: %s", err, out)
			}
			args = append([]string{"pkeyutl", "-sign", "-inkey", fixture("keys", p.key+".key.pem"), "-in", m, "-out", s}, options...)
			if out, err := exec.Command("openssl", args...).CombinedOutput(); err != nil {
				t.Fatalf("OpenSSL sign: %v: %s", err, out)
			}
			sig, err = os.ReadFile(s)
			if err != nil {
				t.Fatal(err)
			}
			if p.alg == "ecdsa-p256-sha256" {
				var values struct{ R, S *big.Int }
				rest, err := asn1.Unmarshal(sig, &values)
				if err != nil || len(rest) != 0 || values.R == nil || values.S == nil {
					t.Fatal("invalid external DER signature", err)
				}
				sig = make([]byte, 64)
				values.R.FillBytes(sig[:32])
				values.S.FillBytes(sig[32:])
			}
			pub, err := keys.LoadPublic(fixture("keys", p.key+".pub.pem"))
			if err != nil {
				t.Fatal(err)
			}
			v, err := sigcrypto.NewVerifier(pub)
			if err != nil {
				t.Fatal(err)
			}
			if err := v.Verify(result.ManifestBytes, sig); err != nil {
				t.Fatalf("OpenSSL -> Go: %v", err)
			}
			data, err := bundle.Build(result.ManifestBytes, sig)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "external.json")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			verified, err := verifier.Run(verifier.Request{ArtifactPath: fixture("artifacts", "binary.bin"), BundlePath: path, TrustStorePath: fixture("trust", "trust_full.json"), Package: "contoh-app", Version: "1.0.0"})
			if err != nil || !verified.Valid {
				t.Fatalf("external bundle: %+v %v", verified, err)
			}
			t.Log("Go -> OpenSSL and OpenSSL -> Go passed")
		})
	}
}
