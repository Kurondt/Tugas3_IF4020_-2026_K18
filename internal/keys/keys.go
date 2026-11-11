package keys

import (
	"crypto"
	"errors"

	"signer/internal/contract"
	sigcrypto "signer/internal/crypto"
)

const (
	privatePEMType = "PRIVATE KEY"
	publicPEMType  = "PUBLIC KEY"
)

var (
	ErrNotPrivate     = errors.New("not a PKCS8 private key")
	ErrNotPublic      = errors.New("not an SPKI public key")
	ErrNotImplemented = contract.ErrNotImplemented
)

func PublicFromPrivate(private crypto.PrivateKey) (crypto.PublicKey, error) {
	return nil, ErrNotImplemented
}

func Fingerprint(public crypto.PublicKey) (string, error) {
	return "", ErrNotImplemented
}

func KeyIDFromPrivate(private crypto.PrivateKey) (string, error) {
	return "", ErrNotImplemented
}

func GenerateAndSave(algorithm sigcrypto.Algorithm, outPrefix string, force bool) (string, error) {
	return "", ErrNotImplemented
}

func SavePrivate(path string, private crypto.PrivateKey) error {
	return ErrNotImplemented
}

func SavePublic(path string, private crypto.PrivateKey) error {
	return ErrNotImplemented
}

func SavePublicFile(path string, public crypto.PublicKey) error {
	return ErrNotImplemented
}

func LoadPrivate(path string) (crypto.PrivateKey, error) {
	return nil, ErrNotImplemented
}

func LoadPublic(path string) (crypto.PublicKey, error) {
	return nil, ErrNotImplemented
}

func ParsePublic(data []byte) (crypto.PublicKey, error) {
	return nil, ErrNotImplemented
}
