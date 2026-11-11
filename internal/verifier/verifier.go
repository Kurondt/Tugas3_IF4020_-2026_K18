package verifier

import (
	"signer/internal/contract"
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

func Run(request Request) (Result, error) {
	return Result{}, ErrNotImplemented
}
