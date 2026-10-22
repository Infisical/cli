package certscan

import (
	"bytes"
	"errors"
	"testing"
)

func TestParsePKCS7RejectsDeeplyNested(t *testing.T) {
	deep := bytes.Repeat([]byte{0x30, 0x80}, maxPKCS7NestingDepth+100)
	if _, err := parsePKCS7(deep); !errors.Is(err, errPKCS7TooDeeplyNested) {
		t.Fatalf("expected %v, got %v", errPKCS7TooDeeplyNested, err)
	}
}

func TestParsePKCS7RejectsNestedIndefiniteWorkBomb(t *testing.T) {
	payload := bytes.Repeat([]byte{0x30, 0x80}, 100000)
	payload = append(payload, 0x05, 0x00)
	payload = append(payload, bytes.Repeat([]byte{0x00, 0x00}, 100000)...)
	if _, err := parsePKCS7(payload); !errors.Is(err, errPKCS7TooDeeplyNested) {
		t.Fatalf("expected %v, got %v", errPKCS7TooDeeplyNested, err)
	}
}

func TestParsePKCS7AllowsLargeShallowBundle(t *testing.T) {
	input := []byte{0x30, 0x80}
	input = append(input, bytes.Repeat([]byte{0x04, 0x01, 0x00}, 300000)...)
	input = append(input, 0x00, 0x00)
	if err := ensurePKCS7NestingWithinLimit(input); err != nil {
		t.Fatalf("large shallow bundle must be accepted, got %v", err)
	}
}

func TestParsePKCS7HandlesOverlongLengthWithoutHanging(t *testing.T) {
	if err := ensurePKCS7NestingWithinLimit([]byte{0x04, 0x84, 0xff, 0xff, 0xff, 0xfa}); err != nil {
		t.Fatalf("overlong length should pass the gate, got %v", err)
	}
}

func TestEnsurePKCS7NestingWithinLimitAllowsModeratelyNested(t *testing.T) {
	input := []byte{0x30, 0x06, 0x30, 0x04, 0x30, 0x02, 0x05, 0x00}
	if err := ensurePKCS7NestingWithinLimit(input); err != nil {
		t.Fatalf("a shallow definite-length structure must be accepted, got %v", err)
	}
}
