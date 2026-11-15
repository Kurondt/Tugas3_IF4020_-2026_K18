package bundle

import (
	"encoding/base64"
	"encoding/json"

	"signer/internal/contract"
	"signer/internal/jsonx"
	"signer/internal/manifest"
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
	if _, err := manifest.Parse(manifestBytes); err != nil {
		return nil, err
	}
	b, err := json.Marshal(struct {
		Schema    string `json:"schema"`
		Manifest  string `json:"manifest_b64"`
		Signature string `json:"signature_b64"`
	}{Schema, base64.StdEncoding.EncodeToString(manifestBytes), base64.StdEncoding.EncodeToString(signature)})
	if err != nil || len(b) > MaxSize {
		return nil, ErrFormat
	}
	return b, nil
}

func Parse(data []byte) (Bundle, error) {
	if len(data) > MaxSize {
		return Bundle{}, ErrFormat
	}
	v, err := jsonx.Decode(data)
	if err != nil {
		return Bundle{}, err
	}
	o, err := jsonx.Object(v, bundleFields...)
	if err != nil {
		return Bundle{}, err
	}
	if o["schema"] != Schema {
		return Bundle{}, ErrFormat
	}
	m, err := decode(o["manifest_b64"])
	if err != nil {
		return Bundle{}, err
	}
	s, err := decode(o["signature_b64"])
	if err != nil {
		return Bundle{}, err
	}
	if len(m) > manifest.MaxSize {
		return Bundle{}, ErrFormat
	}
	return Bundle{m, s}, nil
}

func decode(v any) ([]byte, error) {
	s, ok := v.(string)
	if !ok {
		return nil, ErrFormat
	}
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || base64.StdEncoding.EncodeToString(b) != s {
		return nil, ErrFormat
	}
	return b, nil
}
