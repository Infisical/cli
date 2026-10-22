package gatewayv2

import (
	"bytes"
	"crypto"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseKeyRef(t *testing.T) {
	key, err := parseKeyRef("release-key", "0a1B")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key.Label != "release-key" || !bytes.Equal(key.ID, []byte{0x0a, 0x1b}) {
		t.Fatalf("unexpected key ref: %+v", key)
	}

	key, err = parseKeyRef("release-key", "")
	if err != nil || len(key.ID) != 0 {
		t.Fatalf("an empty key ID must match by label only, got %+v, %v", key, err)
	}

	for _, tc := range []struct{ label, id string }{
		{"release-key", "zz"},
		{"release-key", "abc"},
		{"release-key", strings.Repeat("ab", maxKeyIDBytes+1)},
		{strings.Repeat("a", maxKeyLabelLen+1), ""},
	} {
		_, err := parseKeyRef(tc.label, tc.id)
		var p11Err *Pkcs11Error
		if !errors.As(err, &p11Err) || p11Err.Code != Pkcs11ErrBadRequest {
			t.Fatalf("expected bad_request for label len %d id %q, got %v", len(tc.label), tc.id, err)
		}
	}
}

type noopPkcs11Module struct{ signCalled *bool }

func (noopPkcs11Module) Test(string, []byte) (SlotInfo, error) { return SlotInfo{}, nil }
func (noopPkcs11Module) GenerateKeyPair(string, []byte, string, string) (GeneratedKey, error) {
	return GeneratedKey{}, nil
}
func (noopPkcs11Module) GetPublicKey(string, []byte, KeyRef) ([]byte, error) { return nil, nil }
func (m noopPkcs11Module) Sign(string, []byte, KeyRef, string, []byte, bool, crypto.PublicKey) (SignResult, error) {
	if m.signCalled != nil {
		*m.signCalled = true
	}
	return SignResult{}, nil
}
func (noopPkcs11Module) FindPrivateKeys(string, []byte, string) ([]KeyInfo, error) { return nil, nil }
func (noopPkcs11Module) Finalize() error                                           { return nil }

func TestBadRequestKeepsItsMessage(t *testing.T) {
	body := strings.NewReader(`{"slotLabel":"slot","pin":"1234","params":{"keyLabel":"release-key","mechanism":"CKM_SHA256_RSA_PKCS","data":""}}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/sign", body)
	rec := httptest.NewRecorder()
	servePkcs11Mux(noopPkcs11Module{}).ServeHTTP(rec, req)

	var resp pkcs11ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.Code != http.StatusBadRequest || resp.Error.Code != Pkcs11ErrBadRequest || resp.Error.Message != "data is empty" {
		t.Fatalf("unexpected response %d %+v", rec.Code, resp.Error)
	}
}

func TestSignRejectsMalformedPublicKeyBeforeSigning(t *testing.T) {
	body := strings.NewReader(`{"slotLabel":"slot","pin":"1234","params":{"keyLabel":"release-key","mechanism":"CKM_SHA256_RSA_PKCS","data":"ZGF0YQ==","publicKey":"bm90IGEga2V5"}}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/sign", body)
	rec := httptest.NewRecorder()
	signCalled := false
	servePkcs11Mux(noopPkcs11Module{signCalled: &signCalled}).ServeHTTP(rec, req)

	var resp pkcs11ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if signCalled {
		t.Fatal("the HSM was asked to sign despite a malformed publicKey")
	}
	if rec.Code != http.StatusBadRequest || resp.Error.Code != Pkcs11ErrBadRequest {
		t.Fatalf("unexpected response %d %+v", rec.Code, resp.Error)
	}
}
