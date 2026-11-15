package verifier

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"

	"signer/internal/bundle"
	sigcrypto "signer/internal/crypto"
	"signer/internal/keys"
	"signer/internal/manifest"
	"signer/internal/trust"
)

type Status string

const (
	StatusOK                   Status = "OK"
	StatusFormatError          Status = "FORMAT_ERROR"
	StatusUnsupportedAlgorithm Status = "UNSUPPORTED_ALGORITHM"
	StatusKeyNotTrusted        Status = "KEY_NOT_TRUSTED"
	StatusInvalidSignature     Status = "INVALID_SIGNATURE"
	StatusMetadataMismatch     Status = "METADATA_MISMATCH"
	StatusArtifactMismatch     Status = "ARTIFACT_MISMATCH"
	StatusInputError           Status = "INPUT_ERROR"
)

type Request struct {
	ArtifactPath   string
	BundlePath     string
	TrustStorePath string
	Package        string
	Version        string
}

type Result struct {
	Valid     bool    `json:"valid"`
	Status    string  `json:"status"`
	Message   string  `json:"message"`
	Algorithm *string `json:"algorithm"`
	KeyID     *string `json:"keyid"`
	Package   *string `json:"package"`
	Version   *string `json:"version"`
}

func (r Result) ExitCode() int {
	switch r.Status {
	case string(StatusOK):
		return 0
	case string(StatusInputError):
		return 2
	default:
		return 1
	}
}

func resultOut(status Status, message string, m *manifest.Manifest) Result {
	result := Result{Valid: status == StatusOK, Status: string(status), Message: message}
	if m != nil {
		result.Algorithm = &m.Algorithm
		result.KeyID = &m.KeyID
		result.Package = &m.Package
		result.Version = &m.Version
	}
	return result
}

func Run(request Request) (Result, error) {
	artifact, err := os.Open(request.ArtifactPath)
	if err != nil {
		return resultOut(StatusInputError, "cannot read artifact", nil), nil
	}
	defer artifact.Close()

	// INPUT_ERROR
	hasher := sha256.New()
	artifactSize, err := io.Copy(hasher, artifact)
	if err != nil {
		return resultOut(StatusInputError, "cannot read artifact", nil), nil
	}
	artifactSHA256 := hex.EncodeToString(hasher.Sum(nil))

	bundleBytes, err := os.ReadFile(request.BundlePath)
	if err != nil {
		return resultOut(StatusInputError, "cannot read bundle", nil), nil
	}
	trustBytes, err := os.ReadFile(request.TrustStorePath)
	if err != nil {
		return resultOut(StatusInputError, "cannot read trust store", nil), nil
	}

	// FORMAT_ERROR
	parsedBundle, err := bundle.Parse(bundleBytes)
	if err != nil {
		return resultOut(StatusFormatError, "invalid bundle", nil), nil
	}
	m, err := manifest.Parse(parsedBundle.Manifest)
	if err != nil {
		return resultOut(StatusFormatError, "invalid manifest", nil), nil
	}
	store, err := trust.Parse(trustBytes)
	if err != nil {
		return resultOut(StatusFormatError, "invalid trust store", nil), nil
	}

	// UNSUPPORTED_ALGORITHM
	if err := manifest.ValidateAlgorithm(m.Algorithm); err != nil {
		return resultOut(StatusUnsupportedAlgorithm, "unsupported algorithm", &m), nil
	}

	// KEY_NOT_TRUSTED
	entry, found := trust.Find(store, m.KeyID)
	if !found {
		return resultOut(StatusKeyNotTrusted, "keyid not in trust store", &m), nil
	}
	if err := entry.Validate(); err != nil {
		return resultOut(StatusFormatError, "invalid trust entry", &m), nil
	}
	if entry.Algorithm != m.Algorithm {
		return resultOut(StatusKeyNotTrusted, "trust entry algorithm mismatch", &m), nil
	}
	allowed := false
	for _, pkg := range entry.Packages {
		if pkg == request.Package {
			allowed = true
		}
	}
	if !allowed {
		return resultOut(StatusKeyNotTrusted, "key not allowed for package", &m), nil
	}
	publicKey, err := keys.ParsePublic([]byte(entry.PublicKeyPEM))
	if err != nil {
		return resultOut(StatusFormatError, "invalid entry public key", &m), nil
	}
	cryptoVerifier, err := sigcrypto.NewVerifier(publicKey)
	if err != nil {
		return resultOut(StatusFormatError, "entry key does not match a known profile", &m), nil
	}

	// INVALID_SIGNATURE
	if err := cryptoVerifier.Verify(parsedBundle.Manifest, parsedBundle.Signature); err != nil {
		return resultOut(StatusInvalidSignature, "invalid signature", &m), nil
	}

	// METADATA_MISMATCH
	if m.Package != request.Package || m.Version != request.Version || m.Artifact.Name != filepath.Base(request.ArtifactPath) {
		return resultOut(StatusMetadataMismatch, "package, version, or artifact name mismatch", &m), nil
	}

	// ARTIFACT_MISMATCH
	if m.Artifact.Size != artifactSize || m.Artifact.SHA256 != artifactSHA256 {
		return resultOut(StatusArtifactMismatch, "artifact size or sha256 mismatch", &m), nil
	}

	return resultOut(StatusOK, "verification successful", &m), nil
}
