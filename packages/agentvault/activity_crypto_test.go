package agentvault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

const (
	vectorKeyHex     = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	vectorIVHex      = "aabbccddeeff001122334455"
	vectorAADHex     = "ba75c71ef714535e84246066ca0a34685c42a03a130dd92fe1d795ad40908a7c"
	vectorIVBase64   = "qrvM3e7/ABEiM0RV"
	vectorCiphertext = "PLRwxBbgu+W68Br1N9gY1oUy8wjJxQClAtBh0NfJS1UcWOCPn3laS615sIqwFONhPIPNWRI3CA+a5tUJ7aoim0sQkE4d9gzou2mc/AWiCdToVBJPtdumA9jIzh3yAI81YPwcoDXEVnq2+7ooNNJShGdLX95itbrna/t4nFKRKSSgNzbH23eMtSMcSo72puk/2iwh4sVbTKzC2kwvbf1U6Mgd21zkIq2jDKKwhcT6mTfjPivW4FzmmkspQVMoWwANRX+QVyXzrMipZfoq5N/UcUI6rCvav2ddgiSoqXrTvwiXaUgv"
)

var vectorContext = struct{ projectID, sessionID, proxyID, chunkID string }{
	projectID: "proj-1",
	sessionID: "sess-1",
	proxyID:   "proxy-1",
	chunkID:   "01K5ABCDEFGHJKMNPQRSTVWXYZ",
}

func vectorRecords() []activityRecord {
	service, bundle := "github", "code-review"
	return []activityRecord{{
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

func TestActivityAADMatchesTheBackendVector(t *testing.T) {
	got := buildActivityAAD(vectorContext.projectID, vectorContext.sessionID, vectorContext.proxyID, vectorContext.chunkID)
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
	aad := buildActivityAAD(vectorContext.projectID, vectorContext.sessionID, vectorContext.proxyID, vectorContext.chunkID)
	ciphertext, gotIV, err := sealActivityWithRand(bytes.NewReader(iv), mustHex(t, vectorKeyHex), plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}

	if encodeActivityIV(gotIV) != vectorIVBase64 {
		t.Fatalf("IV encodes as %q, the backend expects %q", encodeActivityIV(gotIV), vectorIVBase64)
	}
	if base64.StdEncoding.EncodeToString(ciphertext) != vectorCiphertext {
		t.Fatal("the sealed bytes differ from the vector Infisical and the browser are checked against")
	}
}

func TestSealedChunkOpensWithTheTagAppended(t *testing.T) {
	key := mustHex(t, vectorKeyHex)
	aad := buildActivityAAD(vectorContext.projectID, vectorContext.sessionID, vectorContext.proxyID, vectorContext.chunkID)
	plaintext, _ := json.Marshal(vectorRecords())

	ciphertext, iv, err := sealActivity(key, plaintext, aad)
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
	aad := buildActivityAAD(vectorContext.projectID, vectorContext.sessionID, vectorContext.proxyID, vectorContext.chunkID)
	ciphertext, iv, err := sealActivity(key, plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}

	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)

	for _, wrong := range []struct {
		name string
		aad  []byte
	}{
		{"another project", buildActivityAAD("other", vectorContext.sessionID, vectorContext.proxyID, vectorContext.chunkID)},
		{"another session", buildActivityAAD(vectorContext.projectID, "other", vectorContext.proxyID, vectorContext.chunkID)},
		{"another proxy", buildActivityAAD(vectorContext.projectID, vectorContext.sessionID, "other", vectorContext.chunkID)},
		{"another chunk", buildActivityAAD(vectorContext.projectID, vectorContext.sessionID, vectorContext.proxyID, "other")},
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
		_, iv, err := sealActivity(key, []byte("[]"), nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(iv) != activityIVBytes {
			t.Fatalf("IV is %d bytes, the contract is %d", len(iv), activityIVBytes)
		}
		if seen[string(iv)] {
			t.Fatal("an IV repeated, which would void GCM's guarantees for this key")
		}
		seen[string(iv)] = true
	}
}

func TestChunkIDsAreULIDsThatSortByTime(t *testing.T) {
	earlier := newActivityChunkID(time.Date(2026, 9, 16, 10, 0, 0, 0, time.UTC))
	later := newActivityChunkID(time.Date(2026, 9, 16, 11, 0, 0, 0, time.UTC))

	if len(earlier) != 26 {
		t.Fatalf("a chunk id is %d characters, the server's column is 26", len(earlier))
	}
	if !(earlier < later) {
		t.Fatalf("%q did not sort before %q", earlier, later)
	}
	if _, err := parseActivityChunkID(earlier); err != nil {
		t.Fatalf("a minted chunk id did not parse: %v", err)
	}
}

func TestChunkIDsAreUniqueWithinAMillisecond(t *testing.T) {
	now := time.Now()
	seen := make(map[string]bool, 1000)
	for i := 0; i < 1000; i++ {
		id := newActivityChunkID(now)
		if seen[id] {
			t.Fatal("a chunk id repeated, which would collide with the server's unique index")
		}
		seen[id] = true
	}
}
