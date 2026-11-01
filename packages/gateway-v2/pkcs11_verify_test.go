package gatewayv2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"math/big"
	"testing"
)

func spki(t *testing.T, pub any) crypto.PublicKey {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseExpectedPublicKey(der)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func digestOf(h crypto.Hash, data []byte) []byte {
	hh := h.New()
	hh.Write(data)
	return hh.Sum(nil)
}

func rawEcdsa(t *testing.T, key *ecdsa.PrivateKey, digest []byte) []byte {
	t.Helper()
	r, s, err := ecdsa.Sign(rand.Reader, key, digest)
	if err != nil {
		t.Fatal(err)
	}
	size := (key.Curve.Params().BitSize + 7) / 8
	out := make([]byte, 2*size)
	r.FillBytes(out[:size])
	s.FillBytes(out[size:])
	return out
}

func expectCode(t *testing.T, err error, code Pkcs11ErrorCode) {
	t.Helper()
	var p11Err *Pkcs11Error
	if !errors.As(err, &p11Err) || p11Err.Code != code {
		t.Fatalf("expected %s, got %v", code, err)
	}
}

func TestVerifySignatureRsa(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	data := []byte("release artifact")
	for mechanism, h := range map[string]crypto.Hash{"CKM_SHA256_RSA_PKCS": crypto.SHA256, "CKM_SHA384_RSA_PKCS": crypto.SHA384, "CKM_SHA512_RSA_PKCS": crypto.SHA512} {
		sig, _ := rsa.SignPKCS1v15(rand.Reader, key, h, digestOf(h, data))
		if err := verifySignature(spki(t, &key.PublicKey), mechanism, false, data, sig); err != nil {
			t.Fatalf("%s: %v", mechanism, err)
		}
		expectCode(t, verifySignature(spki(t, &other.PublicKey), mechanism, false, data, sig), Pkcs11ErrSignatureMismatch)
		expectCode(t, verifySignature(spki(t, &key.PublicKey), mechanism, false, []byte("tampered"), sig), Pkcs11ErrSignatureMismatch)

		digest := digestOf(h, data)
		sigOverDigest, _ := rsa.SignPKCS1v15(rand.Reader, key, h, digestOf(h, digest))
		if err := verifySignature(spki(t, &key.PublicKey), mechanism, true, digest, sigOverDigest); err != nil {
			t.Fatalf("%s with isDigest: %v", mechanism, err)
		}
	}

	digestInfo := append([]byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}, digestOf(crypto.SHA256, data)...)
	sig, _ := rsa.SignPKCS1v15(rand.Reader, key, 0, digestInfo)
	if err := verifySignature(spki(t, &key.PublicKey), "CKM_RSA_PKCS", true, digestInfo, sig); err != nil {
		t.Fatalf("CKM_RSA_PKCS: %v", err)
	}
	expectCode(t, verifySignature(spki(t, &other.PublicKey), "CKM_RSA_PKCS", true, digestInfo, sig), Pkcs11ErrSignatureMismatch)
}

func TestVerifySignatureEcdsa(t *testing.T) {
	data := []byte("release artifact")
	for _, tc := range []struct {
		curve     elliptic.Curve
		mechanism string
		hash      crypto.Hash
	}{
		{elliptic.P256(), "CKM_ECDSA_SHA256", crypto.SHA256},
		{elliptic.P384(), "CKM_ECDSA_SHA384", crypto.SHA384},
	} {
		key, _ := ecdsa.GenerateKey(tc.curve, rand.Reader)
		other, _ := ecdsa.GenerateKey(tc.curve, rand.Reader)
		digest := digestOf(tc.hash, data)
		sig := rawEcdsa(t, key, digest)

		if err := verifySignature(spki(t, &key.PublicKey), tc.mechanism, false, data, sig); err != nil {
			t.Fatalf("%s raw data: %v", tc.mechanism, err)
		}
		if err := verifySignature(spki(t, &key.PublicKey), tc.mechanism, true, digest, sig); err != nil {
			t.Fatalf("%s pre-hashed: %v", tc.mechanism, err)
		}
		if err := verifySignature(spki(t, &key.PublicKey), "CKM_ECDSA", true, digest, sig); err != nil {
			t.Fatalf("CKM_ECDSA: %v", err)
		}
		expectCode(t, verifySignature(spki(t, &other.PublicKey), tc.mechanism, false, data, sig), Pkcs11ErrSignatureMismatch)
		expectCode(t, verifySignature(spki(t, &key.PublicKey), tc.mechanism, false, []byte("tampered"), sig), Pkcs11ErrSignatureMismatch)
	}
}

func TestVerifySignatureRejectsWrongKeyTypeAndBadInput(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	data := []byte("release artifact")
	sig := rawEcdsa(t, ecKey, digestOf(crypto.SHA256, data))
	expectCode(t, verifySignature(spki(t, &rsaKey.PublicKey), "CKM_ECDSA_SHA256", false, data, sig), Pkcs11ErrSignatureMismatch)
	_, err := parseExpectedPublicKey([]byte("not a key"))
	expectCode(t, err, Pkcs11ErrBadRequest)
}

func TestParseExpectedPublicKeyLimits(t *testing.T) {
	_, err := parseExpectedPublicKey(make([]byte, maxPublicKeySpkiBytes+1))
	expectCode(t, err, Pkcs11ErrBadRequest)

	oversized := &rsa.PublicKey{N: new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 5000), big.NewInt(1)), E: 65537}
	der, err := x509.MarshalPKIXPublicKey(oversized)
	if err != nil {
		t.Fatal(err)
	}
	if len(der) > maxPublicKeySpkiBytes {
		t.Fatalf("test key must stay under the size cap to reach the modulus check, got %d bytes", len(der))
	}
	_, err = parseExpectedPublicKey(der)
	expectCode(t, err, Pkcs11ErrBadRequest)

	key, _ := rsa.GenerateKey(rand.Reader, 4096)
	if _, err := parseExpectedPublicKey(spkiDer(t, &key.PublicKey)); err != nil {
		t.Fatalf("RSA-4096 must be accepted: %v", err)
	}
}

func spkiDer(t *testing.T, pub any) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestCompleteSignWithUnreadableAttributes(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	data := []byte("release artifact")
	sig := rawEcdsa(t, key, digestOf(crypto.SHA256, data))
	ref := KeyRef{Label: "release-key", ID: []byte{0x0a}}

	result, err := completeSign(sig, false, nil, ref, spki(t, &key.PublicKey), "CKM_ECDSA_SHA256", false, data)
	if err != nil || len(result.Signature) == 0 || string(result.KeyID) != string(ref.ID) {
		t.Fatalf("matching key must return the signature and the requested key ID, got %+v, %v", result, err)
	}

	result, err = completeSign(sig, false, nil, ref, spki(t, &other.PublicKey), "CKM_ECDSA_SHA256", false, data)
	expectCode(t, err, Pkcs11ErrSignatureMismatch)
	if len(result.Signature) != 0 {
		t.Fatal("a mismatch must not return a signature")
	}

	result, err = completeSign(sig, false, nil, ref, nil, "CKM_ECDSA_SHA256", false, data)
	if err != nil || len(result.Signature) == 0 {
		t.Fatalf("without an expected key the signature is returned as before, got %+v, %v", result, err)
	}

	result, err = completeSign(sig, true, []byte{0x0b}, ref, spki(t, &other.PublicKey), "CKM_ECDSA_SHA256", false, data)
	if err != nil || string(result.KeyID) != "\x0b" {
		t.Fatalf("readable attributes return the key's own ID, got %+v, %v", result, err)
	}
}
