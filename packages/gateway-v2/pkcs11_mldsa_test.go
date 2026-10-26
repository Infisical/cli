package gatewayv2

import (
	"bytes"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"strings"
	"testing"
)

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestMlDsaSpkiFromValueAcceptsRawAndSpki(t *testing.T) {
	for _, params := range mlDsaParamsList {
		raw := randomBytes(t, params.publicKeyBytes)
		fromRaw, err := mlDsaSpkiFromValue(params.keyAlgorithm, raw)
		if err != nil {
			t.Fatalf("%s raw: %v", params.keyAlgorithm, err)
		}
		if len(fromRaw) != params.publicKeyBytes+22 {
			t.Fatalf("%s SPKI is %d bytes, expected %d", params.keyAlgorithm, len(fromRaw), params.publicKeyBytes+22)
		}
		fromSpki, err := mlDsaSpkiFromValue(params.keyAlgorithm, fromRaw)
		if err != nil || !bytes.Equal(fromSpki, fromRaw) {
			t.Fatalf("%s SPKI form must round-trip, got %v", params.keyAlgorithm, err)
		}
		parsed, err := parseMlDsaSpki(fromRaw)
		if err != nil || parsed.keyAlgorithm != params.keyAlgorithm || !bytes.Equal(parsed.raw, raw) {
			t.Fatalf("%s parse: %+v, %v", params.keyAlgorithm, parsed, err)
		}
	}
}

func TestMlDsaSpkiFromValueRejectsMismatches(t *testing.T) {
	spki44, err := marshalMlDsaSpki(KeyAlgorithmMLDSA44, randomBytes(t, 1312))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mlDsaSpkiFromValue(KeyAlgorithmMLDSA65, spki44); err == nil {
		t.Fatal("an ML-DSA-44 key must not be accepted as ML-DSA-65")
	}
	if _, err := mlDsaSpkiFromValue(KeyAlgorithmMLDSA44, randomBytes(t, 1000)); err == nil {
		t.Fatal("a value of the wrong length must be rejected")
	}
	if _, err := mlDsaSpkiFromValue(KeyAlgorithmECCP256, randomBytes(t, 1312)); err == nil {
		t.Fatal("a non ML-DSA key algorithm must be rejected")
	}
}

func TestParseExpectedPublicKeyAcceptsMlDsa(t *testing.T) {
	der, err := marshalMlDsaSpki(KeyAlgorithmMLDSA87, randomBytes(t, 2592))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := parseExpectedPublicKey(der)
	if err != nil {
		t.Fatalf("ML-DSA-87 must be accepted: %v", err)
	}
	if key, ok := pub.(*mlDsaPublicKey); !ok || key.keyAlgorithm != KeyAlgorithmMLDSA87 {
		t.Fatalf("expected an ML-DSA-87 key, got %T", pub)
	}
}

func TestRequireVerifiableKeyRefusesHiddenMlDsaKeys(t *testing.T) {
	der, err := marshalMlDsaSpki(KeyAlgorithmMLDSA44, randomBytes(t, 1312))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := parseExpectedPublicKey(der)
	if err != nil {
		t.Fatal(err)
	}
	expectCode(t, requireVerifiableKey(false, pub), Pkcs11ErrBadRequest)
	if err := requireVerifiableKey(true, pub); err != nil {
		t.Fatalf("readable attributes must be allowed, got %v", err)
	}
	if err := requireVerifiableKey(false, nil); err != nil {
		t.Fatalf("a request without an expected key keeps the existing behaviour, got %v", err)
	}
	for _, mechanism := range []string{mechanismMlDsa, "CKM_SHA256_RSA_PKCS"} {
		result, err := completeSign([]byte("signature"), false, nil, KeyRef{Label: "ca-key"}, pub, mechanism, false, []byte("tbs"))
		if err == nil || len(result.Signature) != 0 {
			t.Fatalf("%s: an unchecked ML-DSA signature must never be returned, got %+v, %v", mechanism, result, err)
		}
	}
}

func TestParseExpectedPublicKeyKeepsMlDsaParseErrors(t *testing.T) {
	der, err := marshalMlDsaSpki(KeyAlgorithmMLDSA65, randomBytes(t, 1952))
	if err != nil {
		t.Fatal(err)
	}
	truncated, err := asn1.Marshal(subjectPublicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: mlDsaParamsList[1].oid},
		PublicKey: asn1.BitString{Bytes: randomBytes(t, 100), BitLength: 800},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = parseExpectedPublicKey(truncated)
	var p11Err *Pkcs11Error
	if !errors.As(err, &p11Err) || p11Err.Code != Pkcs11ErrBadRequest || !strings.Contains(p11Err.Message, "ML_DSA_65") {
		t.Fatalf("a malformed ML-DSA key must keep its specific error, got %v", err)
	}
	if _, err := parseExpectedPublicKey(der); err != nil {
		t.Fatalf("a valid ML-DSA-65 key must parse: %v", err)
	}
}

func TestMlDsaSpkiFromValueAcceptsWrappedRawKey(t *testing.T) {
	raw := randomBytes(t, 1312)
	wrapped, err := asn1.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	fromWrapped, err := mlDsaSpkiFromValue(KeyAlgorithmMLDSA44, wrapped)
	if err != nil {
		t.Fatalf("an OCTET STRING holding the raw key must be accepted: %v", err)
	}
	expected, _ := marshalMlDsaSpki(KeyAlgorithmMLDSA44, raw)
	if !bytes.Equal(fromWrapped, expected) {
		t.Fatal("the wrapped key must produce the same SubjectPublicKeyInfo as the raw key")
	}
}
