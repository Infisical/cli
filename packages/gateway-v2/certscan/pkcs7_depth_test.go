package certscan

import (
	"bytes"
	"errors"
	"testing"
)

func TestParsePKCS7RejectsDeeplyNested(t *testing.T) {
	deep := bytes.Repeat([]byte{0x30, 0x80}, 100000)
	if asn1NestingWithinLimit(deep, maxPKCS7NestingDepth) {
		t.Fatal("expected deeply nested input to exceed the depth limit")
	}
	if _, err := parsePKCS7(deep); !errors.Is(err, errPKCS7TooDeeplyNested) {
		t.Fatalf("expected %v, got %v", errPKCS7TooDeeplyNested, err)
	}
}

func TestASN1NestingWithinLimitAllowsShallow(t *testing.T) {
	shallow := []byte{0x30, 0x03, 0x02, 0x01, 0x01}
	if !asn1NestingWithinLimit(shallow, maxPKCS7NestingDepth) {
		t.Fatal("expected shallow structure to be within the limit")
	}
}

func TestASN1NestingWithinLimitRejectsOutOfBoundsLength(t *testing.T) {
	overflowing := []byte{0x04, 0x84, 0xff, 0xff, 0xff, 0xfa}
	if asn1NestingWithinLimit(overflowing, maxPKCS7NestingDepth) {
		t.Fatal("expected a length larger than the remaining input to be rejected")
	}
}
