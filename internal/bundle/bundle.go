package bundle

import (
	"signer/internal/contract"
	"signer/internal/jsonx"
)

const (
	Schema  = "minisign-bundle/v1"
	MaxSize = 64 * 1024
)

var (
	bundleFields = []string{"schema", "manifest_b64", "signature_b64"}

	ErrFormat         = jsonx.ErrFormat
	ErrNotImplemented = contract.ErrNotImplemented
)

type Bundle struct {
	Manifest  []byte
	Signature []byte
}

func Build(manifestBytes []byte, signature []byte) ([]byte, error) {
	return nil, ErrNotImplemented
}

func Parse(data []byte) (Bundle, error) {
	return Bundle{}, ErrNotImplemented
}
