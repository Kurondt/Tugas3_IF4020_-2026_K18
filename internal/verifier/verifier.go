package verifier

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"signer/internal/bundle"
	"signer/internal/contract"
	sigcrypto "signer/internal/crypto"
	"signer/internal/fileio"
	"signer/internal/keys"
	"signer/internal/manifest"
	"signer/internal/trust"
)

var ErrNotImplemented = contract.ErrNotImplemented

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
	artifactSHA256 string
	Valid          bool    `json:"valid"`
	Status         string  `json:"status"`
	Message        string  `json:"message"`
	Algorithm      *string `json:"algorithm"`
	KeyID          *string `json:"keyid"`
	Package        *string `json:"package"`
	Version        *string `json:"version"`
}

// ArtifactSHA256 returns the digest read during successful verification. It is
// empty for rejected inputs and is excluded from the mandatory JSON interface.
func (r Result) ArtifactSHA256() string { return r.artifactSHA256 }

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

func Run(request Request) (Result, error) {
	r := Result{}
	fail := func(status Status, err any) (Result, error) {
		r.Status = string(status)
		r.Message = fmt.Sprint(err)
		return r, nil
	}
	if !manifest.ValidPackage(request.Package) || !manifest.ValidVersion(request.Version) {
		return fail(StatusInputError, "invalid expected package or version")
	}
	a, err := fileio.OpenArtifact(request.ArtifactPath)
	if err != nil {
		return fail(StatusInputError, err)
	}
	defer a.Close()
	size, hash, err := fileio.Hash(a)
	if err != nil {
		return fail(StatusInputError, err)
	}
	b, err := fileio.ReadLimit(request.BundlePath, bundle.MaxSize)
	if err != nil {
		return fail(StatusInputError, err)
	}
	t, err := os.ReadFile(request.TrustStorePath)
	if err != nil {
		return fail(StatusInputError, err)
	}
	parsed, err := bundle.Parse(b)
	if err != nil {
		return fail(StatusFormatError, err)
	}
	m, err := manifest.Parse(parsed.Manifest)
	if err != nil {
		return fail(StatusFormatError, err)
	}
	r.Algorithm = &m.Algorithm
	r.KeyID = &m.KeyID
	r.Package = &m.Package
	r.Version = &m.Version
	s, err := trust.Parse(t)
	if err != nil {
		return fail(StatusFormatError, err)
	}
	if !sigcrypto.Known(sigcrypto.Algorithm(m.Algorithm)) {
		return fail(StatusUnsupportedAlgorithm, "unsupported algorithm")
	}
	e, ok := trust.Find(s, m.KeyID)
	if !ok || e.Algorithm != m.Algorithm || !slices.Contains(e.Packages, request.Package) {
		return fail(StatusKeyNotTrusted, "key is not trusted for the expected package and profile")
	}
	pub, err := keys.ParsePublic([]byte(e.PublicKeyPEM))
	if err != nil {
		return fail(StatusFormatError, err)
	}
	v, err := sigcrypto.NewVerifier(pub)
	if err != nil {
		return fail(StatusFormatError, err)
	}
	if err := v.Verify(parsed.Manifest, parsed.Signature); err != nil {
		return fail(StatusInvalidSignature, err)
	}
	if m.Package != request.Package || m.Version != request.Version || m.Artifact.Name != filepath.Base(request.ArtifactPath) {
		return fail(StatusMetadataMismatch, "package, version, or artifact basename differs")
	}
	if size != m.Artifact.Size || hash != m.Artifact.SHA256 {
		return fail(StatusArtifactMismatch, "artifact size or SHA-256 differs")
	}
	r.Valid = true
	r.artifactSHA256 = hash
	r.Status = string(StatusOK)
	r.Message = "signature and artifact are valid"
	return r, nil
}
