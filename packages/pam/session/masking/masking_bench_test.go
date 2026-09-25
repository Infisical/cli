package masking

import (
	"regexp"
	"strings"
	"sync"
	"testing"
)

var typicalLine = "drwxr-xr-x  2 root root  4096 Sep 16 09:31 libfoo.so.1.2.3"

func buildLargeLine() string {
	var b strings.Builder
	for b.Len() < 8192 {
		b.WriteString("SELECT id, name, created_at FROM users WHERE tenant_id = 42; ")
	}
	return b.String()[:8192]
}

func buildTokenDenseLine() string {
	var b strings.Builder
	for i := 0; i < 24; i++ {
		b.WriteString("Zk9wZjR4TmF0S2hHc1BtVzdaeVh1QVBxTHc")
		b.WriteByte(' ')
	}
	return b.String()
}

func benchmarkMask(b *testing.B, masker Masker, input string) {
	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = masker.MaskString(input)
	}
}

func BenchmarkCustomPatternsTypicalLine(b *testing.B) {
	m := New([]*regexp.Regexp{regexp.MustCompile(`password\s*=\s*\S+`)}, false, nil, "b")
	benchmarkMask(b, m, typicalLine)
}

func BenchmarkBuiltInTypicalLine(b *testing.B) {
	benchmarkMask(b, New(nil, true, nil, "b"), typicalLine)
}

func BenchmarkBuiltInLargeLine(b *testing.B) {
	benchmarkMask(b, New(nil, true, nil, "b"), buildLargeLine())
}

func BenchmarkBuiltInTokenDenseLine(b *testing.B) {
	benchmarkMask(b, New(nil, true, nil, "b"), buildTokenDenseLine())
}

func BenchmarkDetectorConstruction(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		detectorOnce = sync.Once{}
		detector, detectorErr = nil, nil
		if _, err := sharedDetector(); err != nil {
			b.Fatal(err)
		}
	}
}
