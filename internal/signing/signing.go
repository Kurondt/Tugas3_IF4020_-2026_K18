package signing

import (
	"signer/internal/contract"
	"signer/internal/manifest"
)

var ErrNotImplemented = contract.ErrNotImplemented

type Result struct {
	BundlePath    string
	Manifest      manifest.Manifest
	ManifestBytes []byte
	Signature     []byte
	KeyID         string
	Algorithm     string
}

func SignFile(artifactPath, pkg, version, keyPath, outPath string, force bool) (Result, error) {
	return Result{}, ErrNotImplemented
}
