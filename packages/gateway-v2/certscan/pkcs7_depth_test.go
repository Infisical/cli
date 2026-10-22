package certscan

import (
	"bytes"
	"errors"
	"testing"
)

func TestParsePKCS7RejectsOversizedInput(t *testing.T) {
	oversized := make([]byte, maxPKCS7ParseBytes+1)
	if _, err := parsePKCS7(oversized); !errors.Is(err, errPKCS7TooLarge) {
		t.Fatalf("expected %v, got %v", errPKCS7TooLarge, err)
	}
}

func TestParsePKCS7HandlesDeeplyNestedWithinSizeCap(t *testing.T) {
	deep := bytes.Repeat([]byte{0x30, 0x80}, 200000)
	if len(deep) > maxPKCS7ParseBytes {
		t.Fatalf("fixture of %d bytes exceeds the size cap", len(deep))
	}
	if _, err := parsePKCS7(deep); errors.Is(err, errPKCS7TooLarge) {
		t.Fatal("input within the size cap must reach the parser")
	}
}
