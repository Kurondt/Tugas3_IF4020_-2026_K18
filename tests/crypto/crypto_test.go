package crypto_test

import (
	"bytes"
	"testing"

	sigcrypto "signer/internal/crypto"
	"signer/internal/keys"
)

const tamperedMessage = "tampered"

func signerFor(t *testing.T, keyName string) sigcrypto.Signer {
	t.Helper()
	private, err := keys.LoadPrivate(fixturePath("keys", keyName+".key.pem"))
	if err != nil {
		t.Fatalf("load private key %s: %v", keyName, err)
	}
	signer, err := sigcrypto.NewSigner(private)
	if err != nil {
		t.Fatalf("create signer %s: %v", keyName, err)
	}
	return signer
}

func verifierFor(t *testing.T, keyName string) sigcrypto.Verifier {
	t.Helper()
	public, err := keys.LoadPublic(fixturePath("keys", keyName+".pub.pem"))
	if err != nil {
		t.Fatalf("load public key %s: %v", keyName, err)
	}
	verifier, err := sigcrypto.NewVerifier(public)
	if err != nil {
		t.Fatalf("create verifier %s: %v", keyName, err)
	}
	return verifier
}

func manifestMessage() []byte {
	return []byte(testMessage)
}

func TestSignVerifyRoundtrip(t *testing.T) {
	for _, profile := range profiles {
		t.Run(profile.name, func(t *testing.T) {
			signer := signerFor(t, profile.key)
			verifier := verifierFor(t, profile.key)
			message := manifestMessage()
			signature, err := signer.Sign(message)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			if err := verifier.Verify(message, signature); err != nil {
				t.Fatalf("verify valid signature: %v", err)
			}
			if err := verifier.Verify(message, tamperOneByte(signature)); err == nil {
				t.Fatal("expected tampered signature to fail")
			}
			if err := verifier.Verify([]byte(tamperedMessage), signature); err == nil {
				t.Fatal("expected tampered message to fail")
			}
			if err := verifier.Verify(message, signature[:len(signature)-1]); err == nil {
				t.Fatal("expected truncated signature to fail")
			}
			if err := verifier.Verify(message, append(signature, 0x00)); err == nil {
				t.Fatal("expected extended signature to fail")
			}
		})
	}
}

func TestSignatureLengths(t *testing.T) {
	message := manifestMessage()
	lengths := map[string]int{"ed25519": 64, "ecdsa_p256": 64, "rsa_pss_3072": 384}
	for keyName, expected := range lengths {
		signature, err := signerFor(t, keyName).Sign(message)
		if err != nil {
			t.Fatalf("sign with %s: %v", keyName, err)
		}
		if len(signature) != expected {
			t.Fatalf("expected signature length %d for %s, got %d", expected, keyName, len(signature))
		}
	}
}

func TestECDSASignatureEncoding(t *testing.T) {
	signer := signerFor(t, "ecdsa_p256")
	verifier := verifierFor(t, "ecdsa_p256")
	message := manifestMessage()
	signature, err := signer.Sign(message)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if len(signature) != 64 {
		t.Fatalf("expected r||s 64-byte encoding, got %d bytes", len(signature))
	}
	if err := verifier.Verify(message, signature); err != nil {
		t.Fatalf("verify r||s signature: %v", err)
	}
	outOfDomain := make([]byte, 64)
	if err := verifier.Verify(message, outOfDomain); err == nil {
		t.Fatal("expected zero r||s signature to fail")
	}
	outOfDomain[31] = 0xFF
	outOfDomain[32] = 0xFF
	if err := verifier.Verify(message, outOfDomain); err == nil {
		t.Fatal("expected out-of-domain r||s signature to fail")
	}
}

func TestEd25519DeterministicSignatures(t *testing.T) {
	message := manifestMessage()
	first, err := signerFor(t, "ed25519").Sign(message)
	if err != nil {
		t.Fatalf("sign first: %v", err)
	}
	second, err := signerFor(t, "ed25519").Sign(message)
	if err != nil {
		t.Fatalf("sign second: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("expected identical Ed25519 signatures for identical input")
	}
}

func TestRandomizedSignaturesVerifyIndependently(t *testing.T) {
	for _, profile := range profiles {
		t.Run(profile.name, func(t *testing.T) {
			verifier := verifierFor(t, profile.key)
			message := manifestMessage()
			first, err := signerFor(t, profile.key).Sign(message)
			if err != nil {
				t.Fatalf("sign first: %v", err)
			}
			second, err := signerFor(t, profile.key).Sign(message)
			if err != nil {
				t.Fatalf("sign second: %v", err)
			}
			if err := verifier.Verify(message, first); err != nil {
				t.Fatalf("verify first: %v", err)
			}
			if err := verifier.Verify(message, second); err != nil {
				t.Fatalf("verify second: %v", err)
			}
		})
	}
}

func TestSignersRejectForeignKeys(t *testing.T) {
	if _, err := sigcrypto.NewVerifier(make([]byte, 0)); err == nil {
		t.Fatal("expected verifier creation to fail for empty key")
	}
}

func tamperOneByte(signature []byte) []byte {
	copied := append([]byte{}, signature...)
	copied[len(copied)/2] ^= 0x40
	return copied
}
