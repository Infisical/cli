package agentvault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

const (
	vectorKeyHex     = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	vectorIVHex      = "aabbccddeeff001122334455"
	vectorAADHex     = "38d8f3b86fbbd1061f9d2a8bd91e6c49c51b6231936a7ecfc21c56e129f37a1c"
	vectorIVBase64   = "qrvM3e7/ABEiM0RV"
	vectorCiphertext = "PLRwxBbgu+W68Br1N9gY1oUy8wjJxQClAtBh0NfJS1UcWOCPn3laS615sIqwFONhPIPNWRI3CA+a5tUJ7aoim0sQkE4d9gzou2mc/AWiCdToVBJPtdumA9jIzh3yAI81YPwcoDXEVnq2+7ooNNJShGdLX95itbrna/t4nFKRKSSgNzbH23eMtSMcSo72puk/2iwh4sVbTKzC2kwvbf1U6Mgd21zkIq2jDKKwhcT6mTfjPivW4FzmmkspQVMoWwANRX+QVyXzrMipZfoq5N/UcUI6rCvRUkqg+3ST5GVMelW0mjOO"
)

// The uploaded object is IV ‖ ciphertext ‖ tag. The 12-byte IV encodes without padding, so the object's base64
// is the two strings joined. The browser test pins the same object.
const vectorBlob = vectorIVBase64 + vectorCiphertext

var vectorContext = struct{ sessionID, chunkID string }{
	sessionID: "sess-1",
	chunkID:   "01a0a9c5-231d-7abc-8def-0123456789ab",
}

func vectorRecords() []sessionLogRecord {
	service, bundle := "github", "code-review"
	return []sessionLogRecord{{
		Ts:           "2026-09-16T10:31:04.221Z",
		Seq:          1,
		ProxyID:      "proxy-1",
		Method:       "GET",
		Host:         "api.github.com",
		Port:         "443",
		Path:         "/zen",
		Status:       200,
		Decision:     decisionBrokered,
		Service:      &service,
		AccessBundle: &bundle,
	}}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex fixture: %v", err)
	}
	return b
}

func TestSessionLogAADMatchesTheBrowserVector(t *testing.T) {
	got := buildSessionLogAAD(vectorContext.sessionID, vectorContext.chunkID)
	if hex.EncodeToString(got) != vectorAADHex {
		t.Fatalf("AAD is %s, the browser builds %s", hex.EncodeToString(got), vectorAADHex)
	}
}

func TestSealMatchesTheBrowserVector(t *testing.T) {
	plaintext, err := json.Marshal(vectorRecords())
	if err != nil {
		t.Fatal(err)
	}

	iv := mustHex(t, vectorIVHex)
	aad := buildSessionLogAAD(vectorContext.sessionID, vectorContext.chunkID)
	blob, err := sealSessionLogWithRand(bytes.NewReader(iv), mustHex(t, vectorKeyHex), plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}

	if base64.StdEncoding.EncodeToString(blob) != vectorBlob {
		t.Fatal("the sealed object differs from the vector the browser opens")
	}
}

func TestASealedChunkCarriesTheDigestOfExactlyWhatIsUploaded(t *testing.T) {
	key := make([]byte, 32)
	spool := newSessionLogSpool(newSessionLogGrant("sess-1", key), time.Now())
	chunk, err := spool.sealSlice(vectorRecords(), []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(chunk.ciphertext)
	if want := base64.RawStdEncoding.EncodeToString(sum[:]); chunk.meta.CiphertextSha256 != want {
		t.Fatalf("the chunk reports digest %q, its ciphertext hashes to %q", chunk.meta.CiphertextSha256, want)
	}
	if len(chunk.meta.CiphertextSha256) != 43 {
		t.Fatalf("the digest is %d characters, the backend expects 43", len(chunk.meta.CiphertextSha256))
	}

	if chunk.meta.CiphertextBytes != len(chunk.ciphertext) {
		t.Fatalf("the chunk reports %d bytes, the object is %d", chunk.meta.CiphertextBytes, len(chunk.ciphertext))
	}

	iv, sealed := chunk.ciphertext[:sessionLogIVBytes], chunk.ciphertext[sessionLogIVBytes:]
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	if _, err := gcm.Open(nil, iv, sealed, buildSessionLogAAD("sess-1", chunk.meta.ChunkID)); err != nil {
		t.Fatalf("the chunk does not open under its session and chunk ID: %v", err)
	}
}

func TestAChunkCannotBeReplayedElsewhere(t *testing.T) {
	key := mustHex(t, vectorKeyHex)
	plaintext, _ := json.Marshal(vectorRecords())
	aad := buildSessionLogAAD(vectorContext.sessionID, vectorContext.chunkID)
	blob, err := sealSessionLog(key, plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	iv, ciphertext := blob[:sessionLogIVBytes], blob[sessionLogIVBytes:]

	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)

	for _, wrong := range []struct {
		name string
		aad  []byte
	}{
		{"another session", buildSessionLogAAD("other", vectorContext.chunkID)},
		{"another chunk", buildSessionLogAAD(vectorContext.sessionID, "other")},
	} {
		if _, err := gcm.Open(nil, iv, ciphertext, wrong.aad); err == nil {
			t.Fatalf("a chunk opened under %s", wrong.name)
		}
	}
}

func TestIVsDoNotRepeat(t *testing.T) {
	key := mustHex(t, vectorKeyHex)
	seen := make(map[string]bool, 256)
	for i := 0; i < 256; i++ {
		blob, err := sealSessionLog(key, []byte("[]"), nil)
		if err != nil {
			t.Fatal(err)
		}
		iv := blob[:sessionLogIVBytes]
		if seen[string(iv)] {
			t.Fatal("an IV repeated, which would void GCM's guarantees for this key")
		}
		seen[string(iv)] = true
	}
}

func TestAChunkIDIsALowercaseUUIDv7CarryingItsTime(t *testing.T) {
	at := time.Date(2026, 9, 16, 20, 50, 33, 123_456_789, time.UTC)
	id, err := newSessionLogChunkID(at)
	if err != nil {
		t.Fatal(err)
	}

	if id != strings.ToLower(id) {
		t.Fatalf("%q is not lowercase, which is how the browser rebuilds the AAD from the object name", id)
	}
	parsed, err := uuid.Parse(id)
	if err != nil {
		t.Fatalf("a minted chunk id did not parse: %v", err)
	}
	if parsed.Version() != 7 || parsed.Variant() != uuid.RFC4122 {
		t.Fatalf("a chunk id is UUID version %d variant %s, the server only accepts version 7 RFC 4122", parsed.Version(), parsed.Variant())
	}
	sec, nsec := parsed.Time().UnixTime()
	if got := time.Unix(sec, nsec).UnixMilli(); got != at.UnixMilli() {
		t.Fatalf("the chunk id carries %d ms, expected %d", got, at.UnixMilli())
	}

	other, err := newSessionLogChunkID(at)
	if err != nil {
		t.Fatal(err)
	}
	if other == id {
		t.Fatal("two chunks closed in the same millisecond got the same id")
	}
}
