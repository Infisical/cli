package agentvault

import (
	"strings"
	"testing"
)

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
