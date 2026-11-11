package crypto

import (
	"crypto"
	"errors"

	"signer/internal/contract"
)

type Algorithm string

const (
	RSAPSS    Algorithm = "rsa-pss-sha256"
	ECDSAP256 Algorithm = "ecdsa-p256-sha256"
	Ed25519   Algorithm = "ed25519"
)

const (
	rsaKeyBits     = 3072
	rsaPublicExp   = 65537
	rsaSaltLength  = 32
	ecdsaSigLength = 64
)

var (
	ErrInvalidSignature = errors.New("invalid signature")
	ErrNotImplemented   = contract.ErrNotImplemented
)

var profiles = map[Algorithm]bool{
	RSAPSS:    true,
	ECDSAP256: true,
	Ed25519:   true,
}

func Known(algorithm Algorithm) bool {
	return profiles[algorithm]
}

func ProfileNames() []Algorithm {
	return []Algorithm{RSAPSS, ECDSAP256, Ed25519}
}

type Signer interface {
	Algorithm() Algorithm
	Sign(message []byte) ([]byte, error)
}

type Verifier interface {
	Algorithm() Algorithm
	Verify(message []byte, signature []byte) error
}

func Generate(algorithm Algorithm) (crypto.PrivateKey, error) {
	return nil, ErrNotImplemented
}

func NewSigner(private crypto.PrivateKey) (Signer, error) {
	return nil, ErrNotImplemented
}

func NewVerifier(public crypto.PublicKey) (Verifier, error) {
	return nil, ErrNotImplemented
}

func PrivateAlgorithm(private crypto.PrivateKey) (Algorithm, error) {
	return "", ErrNotImplemented
}

func PublicAlgorithm(public crypto.PublicKey) (Algorithm, error) {
	return "", ErrNotImplemented
}
