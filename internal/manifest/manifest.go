package manifest

import (
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

func Build(pkg string, version string, algorithm sigcrypto.Algorithm, keyID, name string, size int64, sha256 string) (Manifest, error) {
	return Manifest{}, ErrNotImplemented
}

func Canonical(m Manifest) ([]byte, error) {
	return nil, ErrNotImplemented
}

func Parse(data []byte) (Manifest, error) {
	return Manifest{}, ErrNotImplemented
}
