package oracle

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

const capturedPhaseOneRequest = "0376010001010702010101010500010757454254455354010d0d415554485f54" +
	"45524d494e414c010707756e6b6e6f776e00010f0f415554485f50524f475241" +
	"4d5f4e4d0104046e6f646500010c0c415554485f4d414348494e450119196361" +
	"726c6f732d6d6f6e6173747972736b692d6d616300010808415554485f504944" +
	"0105053130313031000109094155544855534552010505636172000000000000"

func phaseOneRequestBytes(t *testing.T) []byte {
	t.Helper()
	raw, err := hex.DecodeString(capturedPhaseOneRequest)
	if err != nil {
		t.Fatalf("bad fixture: %v", err)
	}
	return raw
}

func bundle(prefix int, authRequest []byte) []byte {
	head := append([]byte{0x01, 0x06, 0x00}, bytes.Repeat([]byte{0x41}, prefix-3)...)
	return append(head, authRequest...)
}

func TestIndexOfAuthRequestFindsAStandaloneRequest(t *testing.T) {
	if got := indexOfAuthRequest(phaseOneRequestBytes(t), AuthSubOpPhaseOne); got != 0 {
		t.Fatalf("offset = %d, want 0", got)
	}
}

func TestIndexOfAuthRequestFindsOneBundledBehindNegotiation(t *testing.T) {
	if got := indexOfAuthRequest(bundle(40, phaseOneRequestBytes(t)), AuthSubOpPhaseOne); got != 40 {
		t.Fatalf("offset = %d, want 40", got)
	}
}

func TestIndexOfAuthRequestIsNotFooledByTheOpcodePairInsideItsOwnBody(t *testing.T) {
	tampered := strings.Replace(capturedPhaseOneRequest, "010707756e6b6e6f776e", "010303767431", 1)
	if tampered == capturedPhaseOneRequest {
		t.Fatal("fixture no longer contains the AUTH_TERMINAL bytes; this test would be vacuous")
	}
	raw, err := hex.DecodeString(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if got := indexOfAuthRequest(bundle(40, raw), AuthSubOpPhaseOne); got != 40 {
		t.Fatalf("offset = %d, want 40: the header must win over a pair inside the body", got)
	}
}

func TestIndexOfAuthRequestFindsARequestWithALongUsername(t *testing.T) {
	longUser := strings.Repeat("U", 110)
	body := "0101070201010101050001" + fmt.Sprintf("%02x", len(longUser)) + hex.EncodeToString([]byte(longUser))
	raw, err := hex.DecodeString("037601" + "00" + body + "010d0d415554485f5445524d494e414c010707756e6b6e6f776e000100")
	if err != nil {
		t.Fatal(err)
	}
	if got := indexOfAuthRequest(bundle(40, raw), AuthSubOpPhaseOne); got != 40 {
		t.Fatalf("offset = %d, want 40 for a %d byte username", got, len(longUser))
	}
}

func TestIndexOfAuthRequestReturnsNothingWhenAbsent(t *testing.T) {
	if got := indexOfAuthRequest([]byte("nothing to see here"), AuthSubOpPhaseOne); got != -1 {
		t.Fatalf("offset = %d, want -1", got)
	}
}

func TestRewriteBundledUsernameSubstitutesInPlace(t *testing.T) {
	payload := bundle(40, phaseOneRequestBytes(t))
	out, applied := rewriteBundledUsername(payload, AuthSubOpPhaseOne, "OTHERUSER")
	if !applied {
		t.Fatal("substitution should have been applied")
	}
	if bytes.Contains(out, []byte("WEBTEST")) {
		t.Fatal("original username survived the rewrite")
	}
	if !bytes.Contains(out, []byte("OTHERUSER")) {
		t.Fatal("injected username missing")
	}
	if !bytes.Equal(out[:40], payload[:40]) {
		t.Fatal("the negotiation bytes ahead of the auth request must not change")
	}
}

func TestRewriteBundledUsernameLeavesARequestWithNoUsernameAlone(t *testing.T) {
	payload, err := hex.DecodeString("0373" + "00" + "00" + "0101" + "01" + "0101" + "0101" +
		"010c0c" + hex.EncodeToString([]byte("AUTH_SESSKEY")) + "010404" + hex.EncodeToString([]byte("ABCD")))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := rewriteBundledUsername(payload, AuthSubOpPhaseTwo, "WEBTEST")
	if !bytes.Equal(out, payload) {
		t.Fatal("a request carrying no username must be forwarded unchanged")
	}
}

func TestRewriteAuthRequestUserReportsAMissingUsername(t *testing.T) {
	payload, err := hex.DecodeString("0376" + "00" + "00" + "0101" + "01" + "0101" + "0101")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rewriteAuthRequestUser(payload, AuthSubOpPhaseOne, "OTHERUSER"); err == nil {
		t.Fatal("a missing username must be reported, so callers can decide what to do")
	}
}

func TestTTCReaderRejectsAHostileLength(t *testing.T) {
	r := NewTTCReader([]byte{0x01, 0x02, 0x03})
	if _, err := r.read(-5); err == nil {
		t.Fatal("a negative length must be rejected, not sliced")
	}
	if _, err := r.read(99); err == nil {
		t.Fatal("an over-long read must be rejected")
	}
}
