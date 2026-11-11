package bundle_test

import (
	"os"
	"testing"

	"signer/internal/bundle"
	"signer/internal/manifest"
)

func loadBundle(t *testing.T, name string) bundle.Bundle {
	t.Helper()
	data, err := os.ReadFile(fixturePath("bundles", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	parsed, err := bundle.Parse(data)
	if err != nil {
		t.Fatalf("parse bundle %s: %v", name, err)
	}
	return parsed
}

func TestParseValidBundles(t *testing.T) {
	for _, profile := range profiles {
		t.Run(profile.name, func(t *testing.T) {
			parsed := loadBundle(t, profile.bundle)
			if _, err := manifest.Parse(parsed.Manifest); err != nil {
				t.Fatalf("embedded manifest does not parse: %v", err)
			}
			if len(parsed.Signature) == 0 {
				t.Fatal("expected non-empty signature")
			}
		})
	}
}

func TestBundleRoundtrip(t *testing.T) {
	parsed := loadBundle(t, "bundle_ed25519.json")
	rebuilt, err := bundle.Build(parsed.Manifest, parsed.Signature)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	reparsed, err := bundle.Parse(rebuilt)
	if err != nil {
		t.Fatalf("reparse: %v", err)
	}
	if string(reparsed.Manifest) != string(parsed.Manifest) {
		t.Fatal("manifest bytes changed across roundtrip")
	}
}

func TestBundleFieldOrderAndWhitespaceAreFree(t *testing.T) {
	reference := loadBundle(t, "bundle_ed25519.json")
	for _, name := range []string{"bundle_reordered.json", "bundle_pretty.json"} {
		t.Run(name, func(t *testing.T) {
			variant := loadBundle(t, name)
			if string(variant.Manifest) != string(reference.Manifest) {
				t.Fatal("manifest bytes changed in reformatted bundle")
			}
			if string(variant.Signature) != string(reference.Signature) {
				t.Fatal("signature bytes changed in reformatted bundle")
			}
		})
	}
}

func TestParseRejectsMalformedBundles(t *testing.T) {
	names := []string{
		"bundle_extra_field.json",
		"bundle_duplicate_field.json",
		"bundle_missing_field.json",
		"bundle_wrong_schema.json",
		"bundle_b64_whitespace.json",
		"bundle_b64_bad_char.json",
		"bundle_b64_unpadded.json",
		"bundle_oversize.json",
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(fixturePath("bundles", name))
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			if _, err := bundle.Parse(data); err == nil {
				t.Fatal("expected bundle.Parse to reject fixture")
			}
		})
	}
}

func TestBundleSizeLimit(t *testing.T) {
	oversize := make([]byte, bundle.MaxSize+1)
	if _, err := bundle.Parse(oversize); err == nil {
		t.Fatal("expected oversize bundle to fail")
	}
}

func TestBundleBuildRejectsOversizeManifest(t *testing.T) {
	_, err := bundle.Build(make([]byte, manifest.MaxSize+1), make([]byte, 64))
	if err == nil {
		t.Fatal("expected build with oversize manifest to fail")
	}
}
