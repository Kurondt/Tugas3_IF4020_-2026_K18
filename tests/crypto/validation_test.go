package crypto_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"math/big"
	"testing"

	sigcrypto "signer/internal/crypto"
	"signer/internal/keys"
)

func TestRejectInvalidKeyParameters(t *testing.T) {
	invalidPublic := &ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(1), Y: big.NewInt(1)}
	if _, err := sigcrypto.PublicAlgorithm(invalidPublic); err == nil {
		t.Fatal("accepted off-curve point")
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []*big.Int{nil, big.NewInt(0), elliptic.P256().Params().N, big.NewInt(1)} {
		invalid := &ecdsa.PrivateKey{PublicKey: priv.PublicKey, D: d}
		if _, err := sigcrypto.NewSigner(invalid); err == nil {
			t.Fatal("accepted invalid scalar/public pair")
		}
	}
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ed[len(ed)-1] ^= 1
	if _, err := sigcrypto.NewSigner(ed); err == nil {
		t.Fatal("accepted inconsistent Ed25519 key")
	}
}
func TestRSARejectsWrongPSSSalt(t *testing.T) {
	key, err := keys.LoadPrivate(fixturePath("keys", "rsa_pss_3072.key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	v := verifierFor(t, "rsa_pss_3072")
	message := manifestMessage()
	digest := sha256.Sum256(message)
	for _, salt := range []int{20, rsa.PSSSaltLengthAuto} {
		sig, err := rsa.SignPSS(rand.Reader, key.(*rsa.PrivateKey), crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: salt})
		if err != nil {
			t.Fatal(err)
		}
		if err := v.Verify(message, sig); err == nil {
			t.Fatalf("accepted salt length %d", salt)
		}
	}
}
func TestECDSAHighSAccepted(t *testing.T) {
	message := manifestMessage()
	sig, err := signerFor(t, "ecdsa_p256").Sign(message)
	if err != nil {
		t.Fatal(err)
	}
	n := elliptic.P256().Params().N
	s := new(big.Int).SetBytes(sig[32:])
	s.Sub(n, s)
	s.FillBytes(sig[32:])
	if err := verifierFor(t, "ecdsa_p256").Verify(message, sig); err != nil {
		t.Fatal("rejected complementary valid S", err)
	}
}
