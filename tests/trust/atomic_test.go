package trust_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"signer/internal/trust"
)

func TestInvalidSaveLeavesOriginalAndNoTemporaryFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.json")
	store := loadTrust(t, "trust_full.json")
	if err := trust.SaveAtomic(path, store); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	store.Keys[0].KeyID = "invalid"
	if err := trust.SaveAtomic(path, store); err == nil {
		t.Fatal("saved invalid store")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("changed old store", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatal("temporary files leaked", err)
	}
}
