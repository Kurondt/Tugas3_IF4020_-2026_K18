// Package fileio provides streaming artifact IO and guarded atomic output writes.
package fileio

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func ReadLimit(path string, limit int64) ([]byte, error) {
	f, err := OpenArtifact(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, limit+1))
}

func OpenArtifact(path string) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	s, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !s.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("%q must be a regular file", path)
	}
	return f, nil
}

func Hash(r io.Reader) (int64, string, error) {
	h := sha256.New()
	n, err := io.Copy(h, r)
	if err != nil {
		return 0, "", err
	}
	if n > 9007199254740991 {
		return 0, "", fmt.Errorf("artifact exceeds maximum size")
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}

// RejectAliases checks existing inode aliases and canonical paths, including
// symlinked parent directories for output files that do not exist yet.
func RejectAliases(out string, inputs ...string) error {
	canonical := func(p string) string {
		a, _ := filepath.Abs(p)
		if resolved, err := filepath.EvalSymlinks(a); err == nil {
			return resolved
		}
		parent, err := filepath.EvalSymlinks(filepath.Dir(a))
		if err == nil {
			return filepath.Join(parent, filepath.Base(a))
		}
		return filepath.Clean(a)
	}
	o, _ := os.Stat(out)
	for _, p := range inputs {
		i, _ := os.Stat(p)
		if canonical(out) == canonical(p) || (o != nil && i != nil && os.SameFile(o, i)) {
			return fmt.Errorf("output aliases input %q", p)
		}
	}
	return nil
}

// WriteAtomic writes in the destination directory; without force, linking the
// temporary file into place provides an atomic no-clobber operation on Linux.
func WriteAtomic(path string, data []byte, mode os.FileMode, force bool) error {
	if path == "" {
		return fmt.Errorf("empty output path")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".norsign-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if force {
		return os.Rename(f.Name(), path)
	}
	if err := os.Link(f.Name(), path); err != nil {
		return fmt.Errorf("create output (use --force to replace an existing file): %w", err)
	}
	return nil
}
