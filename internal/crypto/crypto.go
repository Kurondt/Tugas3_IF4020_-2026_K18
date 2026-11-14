package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

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
	rsaSigLength   = rsaKeyBits / 8
	ecdsaSigLength = 64
	ecdsaCoordLen  = ecdsaSigLength / 2
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

type signer struct {
	alg  Algorithm
	sign func([]byte) ([]byte, error)
}

func (s signer) Algorithm() Algorithm                { return s.alg }
func (s signer) Sign(message []byte) ([]byte, error) { return s.sign(message) }

type verifier struct {
	alg    Algorithm
	verify func([]byte, []byte) error
}

func (v verifier) Algorithm() Algorithm                          { return v.alg }
func (v verifier) Verify(message []byte, signature []byte) error { return v.verify(message, signature) }

func Generate(algorithm Algorithm) (crypto.PrivateKey, error) {
	switch algorithm {
	case RSAPSS:
		key, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
		if err != nil {
			return nil, err
		}
		if key.E != rsaPublicExp {
			return nil, errors.New("unexpected RSA public exponent")
		}
		return key, nil
	case ECDSAP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case Ed25519:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		return priv, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm %q", algorithm)
	}
}

func NewSigner(private crypto.PrivateKey) (Signer, error) {
	alg, err := PrivateAlgorithm(private)
	if err != nil {
		return nil, err
	}
	switch alg {
	case RSAPSS:
		key := private.(*rsa.PrivateKey)
		opts := &rsa.PSSOptions{SaltLength: rsaSaltLength, Hash: crypto.SHA256}
		return signer{alg: alg, sign: func(message []byte) ([]byte, error) {
			digest := sha256.Sum256(message)
			return rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest[:], opts)
		}}, nil
	case ECDSAP256:
		key := private.(*ecdsa.PrivateKey)
		return signer{alg: alg, sign: func(message []byte) ([]byte, error) {
			digest := sha256.Sum256(message)
			r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
			if err != nil {
				return nil, err
			}
			out := make([]byte, ecdsaSigLength)
			r.FillBytes(out[:ecdsaCoordLen])
			s.FillBytes(out[ecdsaCoordLen:])
			return out, nil
		}}, nil
	case Ed25519:
		key := private.(ed25519.PrivateKey)
		return signer{alg: alg, sign: func(message []byte) ([]byte, error) {
			return ed25519.Sign(key, message), nil
		}}, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm %q", alg)
	}
}

func NewVerifier(public crypto.PublicKey) (Verifier, error) {
	alg, err := PublicAlgorithm(public)
	if err != nil {
		return nil, err
	}
	switch alg {
	case RSAPSS:
		key := public.(*rsa.PublicKey)
		opts := &rsa.PSSOptions{SaltLength: rsaSaltLength, Hash: crypto.SHA256}
		return verifier{alg: alg, verify: func(message []byte, signature []byte) error {
			if len(signature) != rsaSigLength {
				return ErrInvalidSignature
			}
			digest := sha256.Sum256(message)
			if err := rsa.VerifyPSS(key, crypto.SHA256, digest[:], signature, opts); err != nil {
				return ErrInvalidSignature
			}
			return nil
		}}, nil
	case ECDSAP256:
		key := public.(*ecdsa.PublicKey)
		n := elliptic.P256().Params().N
		return verifier{alg: alg, verify: func(message []byte, signature []byte) error {
			if len(signature) != ecdsaSigLength {
				return ErrInvalidSignature
			}
			r := new(big.Int).SetBytes(signature[:ecdsaCoordLen])
			s := new(big.Int).SetBytes(signature[ecdsaCoordLen:])
			if r.Sign() <= 0 || r.Cmp(n) >= 0 || s.Sign() <= 0 || s.Cmp(n) >= 0 {
				return ErrInvalidSignature
			}
			digest := sha256.Sum256(message)
			if !ecdsa.Verify(key, digest[:], r, s) {
				return ErrInvalidSignature
			}
			return nil
		}}, nil
	case Ed25519:
		key := public.(ed25519.PublicKey)
		return verifier{alg: alg, verify: func(message []byte, signature []byte) error {
			if len(signature) != ed25519.SignatureSize || !ed25519.Verify(key, message, signature) {
				return ErrInvalidSignature
			}
			return nil
		}}, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm %q", alg)
	}
}

func PrivateAlgorithm(private crypto.PrivateKey) (Algorithm, error) {
	switch k := private.(type) {
	case *rsa.PrivateKey:
		if k == nil {
			return "", errors.New("nil RSA private key")
		}
		if _, err := PublicAlgorithm(&k.PublicKey); err != nil {
			return "", err
		}
		if k.D == nil || len(k.Primes) < 2 {
			return "", errors.New("invalid RSA private key parameters")
		}
		if err := k.Validate(); err != nil {
			return "", err
		}
		return RSAPSS, nil
	case *ecdsa.PrivateKey:
		if k == nil {
			return "", errors.New("nil ECDSA private key")
		}
		if _, err := PublicAlgorithm(&k.PublicKey); err != nil {
			return "", err
		}
		return ECDSAP256, nil
	case ed25519.PrivateKey:
		if len(k) != ed25519.PrivateKeySize {
			return "", errors.New("invalid Ed25519 private key length")
		}
		return Ed25519, nil
	default:
		return "", errors.New("unsupported private key type")
	}
}

func PublicAlgorithm(public crypto.PublicKey) (Algorithm, error) {
	switch k := public.(type) {
	case *rsa.PublicKey:
		if k == nil || k.N == nil {
			return "", errors.New("nil RSA public key")
		}
		if k.N.BitLen() != rsaKeyBits {
			return "", fmt.Errorf("RSA key modulus must be %d bits, got %d", rsaKeyBits, k.N.BitLen())
		}
		if k.E != rsaPublicExp {
			return "", fmt.Errorf("RSA public exponent must be %d, got %d", rsaPublicExp, k.E)
		}
		return RSAPSS, nil
	case *ecdsa.PublicKey:
		if k == nil || k.Curve != elliptic.P256() || k.X == nil || k.Y == nil {
			return "", errors.New("ECDSA public key must use P-256 curve")
		}
		return ECDSAP256, nil
	case ed25519.PublicKey:
		if len(k) != ed25519.PublicKeySize {
			return "", errors.New("invalid Ed25519 public key length")
		}
		return Ed25519, nil
	default:
		return "", errors.New("unsupported public key type")
	}
}
