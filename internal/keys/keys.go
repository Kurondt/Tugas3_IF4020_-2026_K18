package keys

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

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
	if _, err := sigcrypto.PrivateAlgorithm(private); err != nil {
		return nil, err
	}
	switch k := private.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &k.PublicKey, nil
	case ed25519.PrivateKey:
		return k.Public(), nil
	default:
		return nil, ErrNotPrivate
	}
}

func Fingerprint(public crypto.PublicKey) (string, error) {
	if _, err := sigcrypto.PublicAlgorithm(public); err != nil {
		return "", err
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

func KeyIDFromPrivate(private crypto.PrivateKey) (string, error) {
	public, err := PublicFromPrivate(private)
	if err != nil {
		return "", err
	}
	return Fingerprint(public)
}

func GenerateAndSave(algorithm sigcrypto.Algorithm, outPrefix string, force bool) (string, error) {
	if outPrefix == "" {
		return "", errors.New("empty output prefix")
	}
	privPath := outPrefix + ".key.pem"
	pubPath := outPrefix + ".pub.pem"
	if !force {
		if err := ensureNotExists(privPath); err != nil {
			return "", err
		}
		if err := ensureNotExists(pubPath); err != nil {
			return "", err
		}
	}
	private, err := sigcrypto.Generate(algorithm)
	if err != nil {
		return "", err
	}
	keyID, err := KeyIDFromPrivate(private)
	if err != nil {
		return "", err
	}
	if err := savePrivateWithForce(privPath, private, force); err != nil {
		return "", err
	}
	public, err := PublicFromPrivate(private)
	if err != nil {
		return "", err
	}
	if err := savePublicFileWithForce(pubPath, public, force); err != nil {
		return "", err
	}
	return keyID, nil
}

func SavePrivate(path string, private crypto.PrivateKey) error {
	return savePrivateWithForce(path, private, true)
}

func SavePublic(path string, private crypto.PrivateKey) error {
	public, err := PublicFromPrivate(private)
	if err != nil {
		return err
	}
	return SavePublicFile(path, public)
}

func SavePublicFile(path string, public crypto.PublicKey) error {
	return savePublicFileWithForce(path, public, true)
}

func LoadPrivate(path string) (crypto.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, err := decodeSinglePEM(data)
	if err != nil {
		return nil, err
	}
	if block.Type != privatePEMType {
		return nil, ErrNotPrivate
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotPrivate, err)
	}
	if _, err := sigcrypto.PrivateAlgorithm(parsed); err != nil {
		return nil, err
	}
	return parsed, nil
}

func LoadPublic(path string) (crypto.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePublic(data)
}

func ParsePublic(data []byte) (crypto.PublicKey, error) {
	block, err := decodeSinglePEM(data)
	if err != nil {
		return nil, err
	}
	if block.Type != publicPEMType {
		return nil, ErrNotPublic
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotPublic, err)
	}
	if _, err := sigcrypto.PublicAlgorithm(parsed); err != nil {
		return nil, err
	}
	canonicalDER, err := x509.MarshalPKIXPublicKey(parsed)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(block.Bytes, canonicalDER) {
		return nil, errors.New("non-canonical SPKI public key encoding")
	}
	return parsed, nil
}

func decodeSinglePEM(data []byte) (*pem.Block, error) {
	if bytes.HasPrefix(data, []byte{0xEF, 0xBB, 0xBF}) {
		return nil, errors.New("PEM data must not start with UTF-8 BOM")
	}
	trimmed := bytes.TrimSpace(data)
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) {
		return nil, errors.New("invalid PEM header")
	}
	block, rest := pem.Decode(trimmed)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("unexpected trailing data after PEM block")
	}
	if len(block.Headers) != 0 {
		return nil, errors.New("PEM headers are not supported")
	}
	return block, nil
}

func ensureNotExists(path string) error {
	_, err := os.Stat(path)
	if err == nil {
		return fmt.Errorf("file %q already exists (use --force to overwrite)", path)
	}
	if !os.IsNotExist(err) {
		return err
	}
	return nil
}

func savePrivateWithForce(path string, private crypto.PrivateKey, force bool) error {
	if _, err := sigcrypto.PrivateAlgorithm(private); err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return err
	}
	encoded := pem.EncodeToMemory(&pem.Block{
		Type:  privatePEMType,
		Bytes: der,
	})
	return writeFile(path, encoded, 0o600, force)
}

func savePublicFileWithForce(path string, public crypto.PublicKey, force bool) error {
	if _, err := sigcrypto.PublicAlgorithm(public); err != nil {
		return err
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return err
	}
	encoded := pem.EncodeToMemory(&pem.Block{
		Type:  publicPEMType,
		Bytes: der,
	})
	return writeFile(path, encoded, 0o644, force)
}

func writeFile(path string, data []byte, perm os.FileMode, force bool) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	flags := os.O_WRONLY | os.O_CREATE
	if force {
		flags |= os.O_TRUNC
	} else {
		flags |= os.O_EXCL
	}
	f, err := os.OpenFile(path, flags, perm)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Chmod(path, perm)
}
