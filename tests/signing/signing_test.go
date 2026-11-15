package signing_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"signer/internal/signing"
)

func TestProtectInputsAndOutput(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "a.bin")
	key := filepath.Join(dir, "private.pem")
	kb, err := os.ReadFile("../fixture/testdata/keys/ed25519.key.pem")
	if err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string][]byte{artifact: []byte("payload"), key: kb} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	hard := filepath.Join(dir, "hard.bin")
	sym := filepath.Join(dir, "sym.bin")
	if err := os.Link(artifact, hard); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(key, sym); err != nil {
		t.Fatal(err)
	}
	for _, out := range []string{artifact, key, hard, sym} {
		if _, err := signing.SignFile(artifact, "app", "1", key, out, true); err == nil {
			t.Fatalf("accepted input alias %s", out)
		}
	}
	out := filepath.Join(dir, "out.json")
	if _, err := signing.SignFile(artifact, "app", "1", key, out, false); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signing.SignFile(artifact, "app", "1", key, out, false); err == nil {
		t.Fatal("overwrote output")
	}
	after, err := os.ReadFile(out)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("changed existing output", err)
	}
	if _, err := signing.SignFile(artifact, "app", "2", key, out, true); err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(artifact)
	if err != nil || string(actual) != "payload" {
		t.Fatal("changed artifact", err)
	}
	actual, err = os.ReadFile(key)
	if err != nil || !bytes.Equal(actual, kb) {
		t.Fatal("changed key", err)
	}
}
