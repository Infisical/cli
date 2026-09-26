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

func TestSessionLogAADMatchesTheBackendVector(t *testing.T) {
	got := buildSessionLogAAD(vectorContext.sessionID, vectorContext.chunkID)
	if hex.EncodeToString(got) != vectorAADHex {
		t.Fatalf("AAD is %s, the backend and the browser build %s", hex.EncodeToString(got), vectorAADHex)
	}
}

func TestSealMatchesNodeVector(t *testing.T) {
	plaintext, err := json.Marshal(vectorRecords())
	if err != nil {
		t.Fatal(err)
	}

	iv := mustHex(t, vectorIVHex)
	aad := buildSessionLogAAD(vectorContext.sessionID, vectorContext.chunkID)
	ciphertext, gotIV, err := sealSessionLogWithRand(bytes.NewReader(iv), mustHex(t, vectorKeyHex), plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}

	if encodeSessionLogIV(gotIV) != vectorIVBase64 {
		t.Fatalf("IV encodes as %q, the backend expects %q", encodeSessionLogIV(gotIV), vectorIVBase64)
	}
	if base64.StdEncoding.EncodeToString(ciphertext) != vectorCiphertext {
		t.Fatal("the sealed bytes differ from the vector Infisical and the browser are checked against")
	}
}

func TestASealedChunkCarriesTheDigestOfExactlyWhatIsUploaded(t *testing.T) {
	key := make([]byte, 32)
	spool := newSessionLogSpool(newSessionLogGrant("sess-1", key), time.Now())
	chunk, err := spool.sealSlice(vectorRecords(), []byte("[]"), 0)
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

	iv, err := base64.RawStdEncoding.DecodeString(chunk.meta.IV)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	if _, err := gcm.Open(nil, iv, chunk.ciphertext, buildSessionLogAAD("sess-1", chunk.meta.ChunkID)); err != nil {
		t.Fatalf("the chunk does not open under its session and chunk ID: %v", err)
	}
}

func TestSealedChunkOpensWithTheTagAppended(t *testing.T) {
	key := mustHex(t, vectorKeyHex)
	aad := buildSessionLogAAD(vectorContext.sessionID, vectorContext.chunkID)
	plaintext, _ := json.Marshal(vectorRecords())

	ciphertext, iv, err := sealSessionLog(key, plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	if len(ciphertext) != len(plaintext)+16 {
		t.Fatalf("sealed length is %d, expected the plaintext plus a 16-byte tag", len(ciphertext))
	}

	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	opened, err := gcm.Open(nil, iv, ciphertext, aad)
	if err != nil {
		t.Fatalf("a chunk this proxy sealed could not be opened: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatal("the opened plaintext differs from what was sealed")
	}
}

func TestAChunkCannotBeReplayedElsewhere(t *testing.T) {
	key := mustHex(t, vectorKeyHex)
	plaintext, _ := json.Marshal(vectorRecords())
	aad := buildSessionLogAAD(vectorContext.sessionID, vectorContext.chunkID)
	ciphertext, iv, err := sealSessionLog(key, plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}

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
		_, iv, err := sealSessionLog(key, []byte("[]"), nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(iv) != sessionLogIVBytes {
			t.Fatalf("IV is %d bytes, the contract is %d", len(iv), sessionLogIVBytes)
		}
		if seen[string(iv)] {
			t.Fatal("an IV repeated, which would void GCM's guarantees for this key")
		}
		seen[string(iv)] = true
	}
}

func TestChunkIDsAreLowercaseUUIDv7sThatSortInMintOrder(t *testing.T) {
	earlier, err := newSessionLogChunkID()
	if err != nil {
		t.Fatal(err)
	}
	later, err := newSessionLogChunkID()
	if err != nil {
		t.Fatal(err)
	}

	if !(earlier < later) {
		t.Fatalf("%q did not sort before %q", earlier, later)
	}
	if earlier != strings.ToLower(earlier) {
		t.Fatalf("%q is not lowercase, which is how Infisical returns it and the browser rebuilds the AAD", earlier)
	}
	parsed, err := uuid.Parse(earlier)
	if err != nil {
		t.Fatalf("a minted chunk id did not parse: %v", err)
	}
	if parsed.Version() != 7 {
		t.Fatalf("a chunk id is UUID version %d, the server only accepts 7", parsed.Version())
	}
}
