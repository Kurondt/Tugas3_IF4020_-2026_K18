package signing

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"

	"signer/internal/bundle"
	"signer/internal/contract"
	sigcrypto "signer/internal/crypto"
	"signer/internal/fileio"
	"signer/internal/keys"
	"signer/internal/manifest"
)

var ErrNotImplemented = contract.ErrNotImplemented

type Result struct {
	BundlePath    string
	Manifest      manifest.Manifest
	ManifestBytes []byte
	Signature     []byte
	KeyID         string
	Algorithm     sigcrypto.Algorithm
}

func SignFile(artifactPath, pkg, version, keyPath, outPath string, force bool) (Result, error) {
	if err := fileio.RejectAliases(outPath, artifactPath, keyPath); err != nil {
		return Result{}, err
	}
	f, err := fileio.OpenArtifact(artifactPath)
	if err != nil {
		return Result{}, err
	}
	defer f.Close()
	size, hash, err := fileio.Hash(f)
	if err != nil {
		return Result{}, err
	}
	return signDigest(filepath.Base(artifactPath), size, hash, pkg, version, keyPath, outPath, force)
}

// SignBytes signs an in-memory snapshot. The caller supplies the logical basename
// and guards aliases to any source files represented by these bytes.
func SignBytes(data []byte, name, pkg, version, keyPath, outPath string, force bool) (Result, error) {
	if err := fileio.RejectAliases(outPath, keyPath); err != nil {
		return Result{}, err
	}
	hash := sha256.Sum256(data)
	return signDigest(name, int64(len(data)), hex.EncodeToString(hash[:]), pkg, version, keyPath, outPath, force)
}

func signDigest(name string, size int64, hash, pkg, version, keyPath, outPath string, force bool) (Result, error) {
	private, err := keys.LoadPrivate(keyPath)
	if err != nil {
		return Result{}, err
	}
	signer, err := sigcrypto.NewSigner(private)
	if err != nil {
		return Result{}, err
	}
	id, err := keys.KeyIDFromPrivate(private)
	if err != nil {
		return Result{}, err
	}
	m, err := manifest.Build(pkg, version, signer.Algorithm(), id, name, size, hash)
	if err != nil {
		return Result{}, err
	}
	mb, err := manifest.Canonical(m)
	if err != nil {
		return Result{}, err
	}
	sig, err := signer.Sign(mb)
	if err != nil {
		return Result{}, err
	}
	b, err := bundle.Build(mb, sig)
	if err != nil {
		return Result{}, err
	}
	if err := fileio.WriteAtomic(outPath, b, 0644, force); err != nil {
		return Result{}, err
	}
	return Result{outPath, m, mb, sig, id, signer.Algorithm()}, nil
}
