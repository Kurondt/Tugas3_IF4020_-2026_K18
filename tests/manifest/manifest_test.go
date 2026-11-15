package manifest_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	sigcrypto "signer/internal/crypto"
	"signer/internal/manifest"
)

func TestParseValidManifest(t *testing.T) {
	data, err := os.ReadFile(fixturePath("manifests", "valid.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	parsed, err := manifest.Parse(data)
	if err != nil {
		t.Fatalf("parse valid manifest: %v", err)
	}
	if parsed.Package != mainPackage || parsed.Version != testVersion {
		t.Fatalf("unexpected fields: %+v", parsed)
	}
	if parsed.Artifact.Name != "binary.bin" || parsed.Artifact.Size != 512 {
		t.Fatalf("unexpected artifact: %+v", parsed.Artifact)
	}
	if parsed.Schema != manifest.Schema {
		t.Fatalf("unexpected schema: %s", parsed.Schema)
	}
}

func TestCanonicalSerialization(t *testing.T) {
	data, err := os.ReadFile(fixturePath("manifests", "valid.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	parsed, err := manifest.Parse(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	rebuilt, err := manifest.Canonical(parsed)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if !bytes.Equal(rebuilt, data) {
		t.Fatalf("canonical serialization mismatch:\n%s\n%s", data, rebuilt)
	}
	if bytes.Contains(rebuilt, []byte(" ")) || bytes.Contains(rebuilt, []byte("\n")) {
		t.Fatal("canonical manifest must not contain whitespace")
	}
}

func TestManifestFieldOrder(t *testing.T) {
	data, err := os.ReadFile(fixturePath("manifests", "valid.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	serialized := string(data)
	positions := []string{`"schema":`, `"package":`, `"version":`, `"algorithm":`, `"keyid":`, `"artifact":`, `"name":`, `"size":`, `"sha256":`}
	last := -1
	for _, token := range positions {
		index := bytes.Index(data, []byte(token))
		if index < 0 {
			t.Fatalf("missing token %s", token)
		}
		if index <= last {
			t.Fatalf("field %s out of order", token)
		}
		last = index
	}
	_ = serialized
}

func TestBuildRejectsInvalidValues(t *testing.T) {
	keyID := testKeyID
	cases := []struct {
		name      string
		pkg       string
		version   string
		algorithm string
		keyID     string
		artifact  string
		size      int64
		sha256    string
	}{
		{"bad package", "Contoh-App", testVersion, "ed25519", keyID, "a.bin", 1, "0000000000000000000000000000000000000000000000000000000000000000"},
		{"bad version", mainPackage, "-bad", "ed25519", keyID, "a.bin", 1, "0000000000000000000000000000000000000000000000000000000000000000"},
		{"bad algorithm", mainPackage, testVersion, "dsa-sha1", keyID, "a.bin", 1, "0000000000000000000000000000000000000000000000000000000000000000"},
		{"bad keyid", mainPackage, testVersion, "ed25519", "abc", "a.bin", 1, "0000000000000000000000000000000000000000000000000000000000000000"},
		{"bad name", mainPackage, testVersion, "ed25519", keyID, "dir/a.bin", 1, "0000000000000000000000000000000000000000000000000000000000000000"},
		{"bad size", mainPackage, testVersion, "ed25519", keyID, "a.bin", -1, "0000000000000000000000000000000000000000000000000000000000000000"},
		{"oversize", mainPackage, testVersion, "ed25519", keyID, "a.bin", 9007199254740992, "0000000000000000000000000000000000000000000000000000000000000000"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := manifest.Build(testCase.pkg, testCase.version, sigcrypto.Algorithm(testCase.algorithm), testCase.keyID, testCase.artifact, testCase.size, testCase.sha256)
			if err == nil {
				t.Fatal("expected build to fail")
			}
		})
	}
}

func TestParseRejectsMalformedManifests(t *testing.T) {
	badManifests, err := filepath.Glob(fixturePath("manifests", "*.json"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	for _, path := range badManifests {
		name := filepath.Base(path)
		if name == "valid.json" || name == "unsupported_algo.json" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			if _, err := manifest.Parse(data); err == nil {
				t.Fatal("expected manifest.Parse to reject fixture")
			}
		})
	}
}

func TestParseUnsupportedAlgorithmAllowedAtFormatLevel(t *testing.T) {
	data, err := os.ReadFile(fixturePath("manifests", "unsupported_algo.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if _, err := manifest.Parse(data); err != nil {
		t.Fatalf("expected format-level parse to accept unknown algorithm, got: %v", err)
	}
}

func TestManifestSizeLimit(t *testing.T) {
	oversize := bytes.Repeat([]byte(" "), manifest.MaxSize+1)
	if _, err := manifest.Parse(oversize); err == nil {
		t.Fatal("expected oversize manifest to fail")
	}
	exactLimit := bytes.Repeat([]byte(" "), manifest.MaxSize)
	if _, err := manifest.Parse(exactLimit); err == nil {
		t.Fatal("expected non-canonical manifest at size limit to fail with format error, not size error")
	}
}

func TestBuildValidBoundaryValues(t *testing.T) {
	hash := "0000000000000000000000000000000000000000000000000000000000000000"
	for _, size := range []int64{0, 9007199254740991} {
		m, err := manifest.Build(mainPackage, testVersion, sigcrypto.Ed25519, testKeyID, "empty.bin", size, hash)
		if err != nil {
			t.Fatal(err)
		}
		canonical, err := manifest.Canonical(m)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := manifest.Parse(canonical); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := manifest.Build(mainPackage, testVersion, sigcrypto.Ed25519, testKeyID, "empty.bin", 0, "00"); err == nil {
		t.Fatal("accepted invalid SHA-256")
	}
}
func TestUnknownAlgorithmStringsRemainFormatValid(t *testing.T) {
	original, err := os.ReadFile(fixturePath("manifests", "valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", "unknown profile", "unknown<profile>"} {
		variant := bytes.Replace(original, []byte(`"algorithm":"ed25519"`), []byte(`"algorithm":"`+name+`"`), 1)
		if _, err := manifest.Parse(variant); err != nil {
			t.Fatalf("unknown profile %q rejected at format stage: %v", name, err)
		}
	}
}
