package signing

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"

	"signer/internal/bundle"
	signcrypto "signer/internal/crypto"
	"signer/internal/keys"
	"signer/internal/manifest"
)

type Result struct {
	BundlePath    string
	Manifest      manifest.Manifest
	ManifestBytes []byte
	Signature     []byte
	KeyID         string
	Algorithm     signcrypto.Algorithm
}

func hashArtifact(path string) (int64, string, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer file.Close()

	hasher := sha256.New()
	size, err := io.Copy(hasher, file)
	if err != nil {
		return 0, "", err
	}
	sha256Hex := hex.EncodeToString(hasher.Sum(nil))
	return size, sha256Hex, nil
}

func SignFile(artifactPath, pkg, version, keyPath, outPath string, force bool) (Result, error) {
	if !manifest.ValidPackage(pkg) {
		return Result{}, errors.New("invalid package name")
	}
	if !force {
		if _, err := os.Stat(outPath); err == nil {
			return Result{}, errors.New("output file exists (use --force to overwrite)")
		}
	}
	name := filepath.Base(artifactPath)

	size, sha256Hex, err := hashArtifact(artifactPath)
	if err != nil {
		return Result{}, err
	}

	private, err := keys.LoadPrivate(keyPath)
	if err != nil {
		return Result{}, err
	}
	algo, err := signcrypto.PrivateAlgorithm(private)
	if err != nil {
		return Result{}, err
	}
	keyID, err := keys.KeyIDFromPrivate(private)
	if err != nil {
		return Result{}, err
	}

	built, err := manifest.Build(pkg, version, algo, keyID, name, size, sha256Hex)
	if err != nil {
		return Result{}, err
	}
	canonical, err := manifest.Canonical(built)
	if err != nil {
		return Result{}, err
	}

	signer, err := signcrypto.NewSigner(private)
	if err != nil {
		return Result{}, err
	}
	signature, err := signer.Sign(canonical)
	if err != nil {
		return Result{}, err
	}

	bundleBytes, err := bundle.Build(canonical, signature)
	if err != nil {
		return Result{}, err
	}

	if err := os.WriteFile(outPath, bundleBytes, 0o644); err != nil {
		return Result{}, err
	}

	return Result{
		BundlePath:    outPath,
		Manifest:      built,
		ManifestBytes: canonical,
		Signature:     signature,
		KeyID:         keyID,
		Algorithm:     algo,
	}, nil
}
