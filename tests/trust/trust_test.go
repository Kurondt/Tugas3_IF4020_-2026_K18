package trust_test

import (
	"os"
	"path/filepath"
	"testing"

	"signer/internal/trust"
)

func loadTrust(t *testing.T, name string) trust.Store {
	t.Helper()
	store, err := trust.Load(fixturePath("trust", name))
	if err != nil {
		t.Fatalf("load trust store %s: %v", name, err)
	}
	return store
}

func TestParseValidTrustStores(t *testing.T) {
	full := loadTrust(t, "trust_full.json")
	if len(full.Keys) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(full.Keys))
	}
	empty := loadTrust(t, "trust_empty.json")
	if len(empty.Keys) != 0 {
		t.Fatalf("expected empty key list, got %d", len(empty.Keys))
	}
	only := loadTrust(t, "trust_ed25519_only.json")
	if len(only.Keys) != 1 || only.Keys[0].Algorithm != "ed25519" {
		t.Fatalf("unexpected ed25519-only store: %+v", only.Keys)
	}
}

func TestTrustAddIdempotentAndMerging(t *testing.T) {
	store := loadTrust(t, "trust_ed25519_only.json")
	entry := store.Keys[0]
	changed, err := store.Add(trust.Entry{
		KeyID:        entry.KeyID,
		Algorithm:    entry.Algorithm,
		PublicKeyPEM: entry.PublicKeyPEM,
		Packages:     []string{mainPackage},
	})
	if err != nil {
		t.Fatalf("idempotent add: %v", err)
	}
	if changed {
		t.Fatal("expected duplicate keyid+package add to be idempotent")
	}
	if len(store.Keys) != 1 {
		t.Fatalf("expected single entry, got %d", len(store.Keys))
	}
	changed, err = store.Add(trust.Entry{
		KeyID:        entry.KeyID,
		Algorithm:    entry.Algorithm,
		PublicKeyPEM: entry.PublicKeyPEM,
		Packages:     []string{otherPackage},
	})
	if err != nil {
		t.Fatalf("merge add: %v", err)
	}
	if !changed {
		t.Fatal("expected package merge to change the store")
	}
	if len(store.Keys) != 1 || len(store.Keys[0].Packages) != 2 {
		t.Fatalf("expected merged packages, got %+v", store.Keys)
	}
}

func TestTrustAddCreatesEntry(t *testing.T) {
	store := trust.New()
	pemBytes, err := os.ReadFile(fixturePath("keys", "ecdsa_p256.pub.pem"))
	if err != nil {
		t.Fatalf("read pem: %v", err)
	}
	entry, err := trust.EntryFromPublicPEM(pemBytes, "", []string{mainPackage})
	if err != nil {
		t.Fatalf("entry from pem: %v", err)
	}
	if entry.Algorithm != "ecdsa-p256-sha256" {
		t.Fatalf("unexpected algorithm %s", entry.Algorithm)
	}
	changed, err := store.Add(entry)
	if err != nil || !changed {
		t.Fatalf("add: changed=%v err=%v", changed, err)
	}
	if len(store.Keys) != 1 || len(store.Keys[0].Packages) != 1 {
		t.Fatalf("unexpected store: %+v", store.Keys)
	}
}

func TestTrustRemove(t *testing.T) {
	store := loadTrust(t, "trust_full.json")
	target := store.Keys[0].KeyID
	if !store.Remove(target) {
		t.Fatal("expected removal of existing keyid")
	}
	if store.Remove(target) {
		t.Fatal("expected removal of missing keyid to report false")
	}
	if len(store.Keys) != 2 {
		t.Fatalf("expected 2 remaining entries, got %d", len(store.Keys))
	}
}

func TestSaveAtomicRoundtrip(t *testing.T) {
	store := loadTrust(t, "trust_ed25519_only.json")
	path := filepath.Join(t.TempDir(), "trust.json")
	if err := trust.SaveAtomic(path, store); err != nil {
		t.Fatalf("save: %v", err)
	}
	reloaded, err := trust.Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(reloaded.Keys) != 1 || reloaded.Keys[0].KeyID != store.Keys[0].KeyID {
		t.Fatalf("roundtrip mismatch: %+v", reloaded.Keys)
	}
}

func TestSaveAtomicKeepsPreviousFileOnFailure(t *testing.T) {
	store := loadTrust(t, "trust_ed25519_only.json")
	path := filepath.Join(t.TempDir(), "trust.json")
	if err := trust.SaveAtomic(path, store); err != nil {
		t.Fatalf("initial save: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read before failure: %v", err)
	}
	if err := trust.SaveAtomic(filepath.Join(path, "not-a-dir", "trust.json"), store); err == nil {
		t.Fatal("expected save to a directory path to fail")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after failure: %v", err)
	}
	if string(before) != string(after) {
		t.Fatal("previous trust store file was modified by failed save")
	}
}

func TestParseRejectsMalformedTrustStores(t *testing.T) {
	names := []string{
		"trust_duplicate_keyid.json",
		"trust_extra_field.json",
		"trust_entry_extra_field.json",
		"trust_fingerprint_mismatch.json",
		"trust_bad_algorithm.json",
		"trust_algorithm_mismatch.json",
		"trust_empty_packages.json",
		"trust_wildcard.json",
		"trust_duplicate_package.json",
		"trust_bad_pem.json",
		"trust_bad_schema.json",
		"trust_malformed.json",
		"trust_entry_missing_field.json",
		"trust_packages_wrong_type.json",
		"trust_keyid_uppercase.json",
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(fixturePath("trust", name))
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			if _, err := trust.Parse(data); err == nil {
				t.Fatal("expected trust.Parse to reject fixture")
			}
		})
	}
}

func TestFind(t *testing.T) {
	store := loadTrust(t, "trust_other_pkg.json")
	entry, found := trust.Find(store, store.Keys[0].KeyID)
	if !found {
		t.Fatal("expected entry lookup to succeed")
	}
	if len(entry.Packages) != 1 || entry.Packages[0] != otherPackage {
		t.Fatal("expected entry packages to match the trust store")
	}
	if _, found := trust.Find(store, "0000000000000000000000000000000000000000000000000000000000000000"); found {
		t.Fatal("expected unknown keyid lookup to fail")
	}
}

func TestEntryFromPublicPEMRejectsMismatch(t *testing.T) {
	pemBytes, err := os.ReadFile(fixturePath("keys", "ed25519.pub.pem"))
	if err != nil {
		t.Fatalf("read pem: %v", err)
	}
	if _, err := trust.EntryFromPublicPEM(pemBytes, "ecdsa-p256-sha256", []string{mainPackage}); err == nil {
		t.Fatal("expected algorithm mismatch to fail")
	}
	if _, err := trust.EntryFromPublicPEM([]byte("not a pem"), "", []string{mainPackage}); err == nil {
		t.Fatal("expected invalid pem to fail")
	}
}

func TestEmptyStoreGrantsNoTrust(t *testing.T) {
	store := loadTrust(t, "trust_empty.json")
	if _, found := trust.Find(store, unknownKeyID); found {
		t.Fatal("empty trust store must not contain any key")
	}
}
