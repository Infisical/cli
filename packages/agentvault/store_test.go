package agentvault

import (
	"strings"
	"testing"
)

// saveCa writes the key and then the certificate. An interruption between the two leaves a new key
// beside the old certificate, and both parse, so without this check the proxy would start, call itself
// enrolled and fail to mint every leaf.
func TestLoadCaRefusesAKeyThatDoesNotMatchTheCertificate(t *testing.T) {
	st := newStore(t.TempDir())

	firstKey, firstCert, err := generateRootCa()
	if err != nil {
		t.Fatalf("generateRootCa: %v", err)
	}
	if err := st.saveCa(firstKey, firstCert); err != nil {
		t.Fatalf("saveCa: %v", err)
	}
	if _, _, err := st.loadCa(); err != nil {
		t.Fatalf("a matching pair must load: %v", err)
	}

	// Simulate the interrupted re-enrollment: the new key lands, the new certificate never does.
	secondKey, _, err := generateRootCa()
	if err != nil {
		t.Fatalf("generateRootCa: %v", err)
	}
	if err := st.saveCa(secondKey, firstCert); err != nil {
		t.Fatalf("saveCa: %v", err)
	}

	_, _, err = st.loadCa()
	if err == nil {
		t.Fatal("a mismatched pair must be refused")
	}
	if !strings.Contains(err.Error(), "does not match") || !strings.Contains(err.Error(), st.dir) {
		t.Fatalf("the error must say what is wrong and where, got %v", err)
	}
}
