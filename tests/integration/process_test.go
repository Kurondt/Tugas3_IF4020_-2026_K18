package integration

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestBinaryContract(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "norsign")
	if out, err := exec.Command("go", "build", "-o", binary, "../../cmd/norsign").CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	run := func(args ...string) (string, string, int) {
		t.Helper()
		var out, stderr bytes.Buffer
		cmd := exec.Command(binary, args...)
		cmd.Stdout = &out
		cmd.Stderr = &stderr
		code := 0
		if err := cmd.Run(); err != nil {
			if e, ok := err.(*exec.ExitError); ok {
				code = e.ExitCode()
			} else {
				t.Fatal(err)
			}
		}
		return out.String(), stderr.String(), code
	}
	for _, args := range [][]string{{"keygen", "--help"}, {"sign", "--help"}, {"verify", "--help"}, {"trust", "--help"}, {"trust", "add", "--help"}, {"trust", "list", "--help"}, {"trust", "remove", "--help"}, {"sbom", "--help"}, {"sbom", "sign", "--help"}, {"sbom", "verify", "--help"}} {
		if _, _, code := run(args...); code != 0 {
			t.Fatalf("help %v: %d", args, code)
		}
	}
	for _, args := range [][]string{{"verify", "--json"}, {"verify", "--unknown", "--json"}, {"verify", "--json", "--file"}, {"verify", "--json", "unexpected"}, {"sbom", "verify", "--bogus", "--json"}} {
		out, _, code := run(args...)
		var r map[string]any
		if code != 2 || json.Unmarshal([]byte(out), &r) != nil || r["status"] != "INPUT_ERROR" || r["valid"] != false || !bytes.HasSuffix([]byte(out), []byte("\n")) {
			t.Fatalf("usage %v: exit %d: %s", args, code, out)
		}
	}
	dir := t.TempDir()
	key := "../fixture/testdata/keys/ed25519.key.pem"
	artifact := filepath.Join(dir, "data.bin")
	bundle := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(artifact, []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}
	if out, stderr, code := run("sign", "--file", artifact, "--key", key, "--package", "contoh-app", "--version", "1.0.0", "--out", bundle); code != 0 {
		t.Fatalf("sign %d: %s %s", code, out, stderr)
	}
	args := []string{"verify", "--file", artifact, "--bundle", bundle, "--trust-store", "../fixture/testdata/trust/trust_full.json", "--package", "contoh-app", "--version", "1.0.0", "--json"}
	for _, tc := range []struct {
		payload, status string
		code            int
	}{{"hello", "OK", 0}, {"jello", "ARTIFACT_MISMATCH", 1}} {
		if err := os.WriteFile(artifact, []byte(tc.payload), 0600); err != nil {
			t.Fatal(err)
		}
		out, _, code := run(args...)
		var r map[string]any
		if code != tc.code || json.Unmarshal([]byte(out), &r) != nil || r["status"] != tc.status || len(r) != 7 {
			t.Fatalf("binary result %d: %s", code, out)
		}
	}
	if err := os.Remove(artifact); err != nil {
		t.Fatal(err)
	}
	out, _, code := run(args...)
	var r map[string]any
	if code != 2 || json.Unmarshal([]byte(out), &r) != nil || r["status"] != "INPUT_ERROR" || r["algorithm"] != nil {
		t.Fatalf("missing file %d: %s", code, out)
	}
	if err := os.WriteFile(artifact, []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}
	sbomPath, sbomBundle := filepath.Join(dir, "sbom.json"), filepath.Join(dir, "sbom-bundle.json")
	digest := sha256.Sum256([]byte("hello"))
	document := []byte(fmt.Sprintf(`{"schema":"norsign-sbom/v1","artifact":{"sha256":"%x"},"components":[]}`, digest))
	if err := os.WriteFile(sbomPath, document, 0600); err != nil {
		t.Fatal(err)
	}
	if out, stderr, code := run("sbom", "sign", "--file", sbomPath, "--artifact", artifact, "--package", "contoh-app", "--version", "1.0.0", "--key", key, "--out", sbomBundle); code != 0 {
		t.Fatalf("SBOM sign %d: %s %s", code, out, stderr)
	}
	out, stderr, code := run("sbom", "verify", "--file", artifact, "--bundle", bundle, "--sbom", sbomPath, "--sbom-bundle", sbomBundle, "--trust-store", "../fixture/testdata/trust/trust_full.json", "--package", "contoh-app", "--version", "1.0.0", "--json")
	r = nil
	if code != 0 || json.Unmarshal([]byte(out), &r) != nil || r["valid"] != true || r["status"] != "OK" || len(r) != 5 {
		t.Fatalf("SBOM verify %d: %s %s", code, out, stderr)
	}
}
