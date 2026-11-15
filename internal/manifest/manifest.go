package manifest

import (
	"bytes"
	"encoding/json"
	"regexp"

	"signer/internal/contract"
	sigcrypto "signer/internal/crypto"
	"signer/internal/jsonx"
)

const (
	Schema  = "minisign-manifest/v1"
	MaxSize = 16 * 1024
	maxInt  = 9007199254740991
)

var (
	packagePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	versionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)
	namePattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	hex64Pattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	manifestFields = []string{"schema", "package", "version", "algorithm", "keyid", "artifact"}
	artifactFields = []string{"name", "size", "sha256"}

	ErrFormat         = jsonx.ErrFormat
	ErrNotImplemented = contract.ErrNotImplemented
)

type Artifact struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	Schema    string   `json:"schema"`
	Package   string   `json:"package"`
	Version   string   `json:"version"`
	Algorithm string   `json:"algorithm"`
	KeyID     string   `json:"keyid"`
	Artifact  Artifact `json:"artifact"`
}

func ValidPackage(value string) bool {
	return packagePattern.MatchString(value)
}

func ValidateAlgorithm(algorithm string) error {
	if !sigcrypto.Known(sigcrypto.Algorithm(algorithm)) {
		return ErrFormat
	}
	return nil
}

func Build(pkg, version string, algorithm sigcrypto.Algorithm, keyID, name string, size int64, sha256 string) (Manifest, error) {
	m := Manifest{Schema, pkg, version, string(algorithm), keyID, Artifact{name, size, sha256}}
	if err := ValidateAlgorithm(string(algorithm)); err != nil {
		return Manifest{}, err
	}
	_, err := Canonical(m)
	return m, err
}

func Canonical(m Manifest) ([]byte, error) {
	if m.Schema != Schema || !ValidPackage(m.Package) || !ValidVersion(m.Version) ||
		!namePattern.MatchString(m.Artifact.Name) || !hex64Pattern.MatchString(m.KeyID) ||
		!hex64Pattern.MatchString(m.Artifact.SHA256) || m.Artifact.Size < 0 || m.Artifact.Size > maxInt {
		return nil, ErrFormat
	}
	for _, c := range m.Algorithm {
		if c < 0x20 || c > 0x7e {
			return nil, ErrFormat
		}
	}
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(m)
	b := bytes.TrimSuffix(out.Bytes(), []byte("\n"))
	if err != nil || len(b) > MaxSize {
		return nil, ErrFormat
	}
	return b, nil
}

func Parse(data []byte) (Manifest, error) {
	if len(data) > MaxSize {
		return Manifest{}, ErrFormat
	}
	v, err := jsonx.Decode(data)
	if err != nil {
		return Manifest{}, err
	}
	o, err := jsonx.Object(v, manifestFields...)
	if err != nil {
		return Manifest{}, err
	}
	if _, err := jsonx.Object(o["artifact"], artifactFields...); err != nil {
		return Manifest{}, err
	}
	var m Manifest
	if err := jsonx.Into(o, &m); err != nil {
		return Manifest{}, err
	}
	b, err := Canonical(m)
	if err != nil || !bytes.Equal(b, data) {
		return Manifest{}, ErrFormat
	}
	return m, nil
}

func ValidVersion(value string) bool { return versionPattern.MatchString(value) }
