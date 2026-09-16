package agentvault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"time"

	"github.com/oklog/ulid"
)

// The version suffix on the additional authenticated data. Bumping it makes every existing chunk
// undecryptable, so it changes only alongside a migration of the stored objects.
const activityAADVersion = "v1"

const activityIVBytes = 12

// buildActivityAAD binds a sealed chunk to exactly one place in the hierarchy, so holding the session key
// is not enough to replay a chunk under another project, session or proxy.
//
// The same string is built by the browser in frontend/src/hooks/api/agentVault/activityDecrypt.ts, and the
// backend pins a known-good vector in agent-vault-activity-crypto.test.ts. All three must agree or
// playback fails with no useful error.
func buildActivityAAD(projectID, sessionID, proxyID, chunkID string) []byte {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%s|%s", projectID, sessionID, proxyID, chunkID, activityAADVersion)))
	return sum[:]
}

// sealActivity produces the layout Web Crypto's decrypt expects: a 12-byte IV carried beside the object,
// and the 16-byte GCM tag appended to the ciphertext rather than kept separately.
func sealActivity(key, plaintext, aad []byte) (ciphertext []byte, iv []byte, err error) {
	return sealActivityWithRand(rand.Reader, key, plaintext, aad)
}

// sealActivityWithRand takes the IV source so a test can pin one and compare against the backend's vector.
func sealActivityWithRand(random io.Reader, key, plaintext, aad []byte) (ciphertext []byte, iv []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("agent-vault: activity key is not a valid AES key: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("agent-vault: could not build GCM: %w", err)
	}

	iv = make([]byte, activityIVBytes)
	if _, err = io.ReadFull(random, iv); err != nil {
		return nil, nil, fmt.Errorf("agent-vault: could not read a nonce: %w", err)
	}

	// A nil destination makes Seal allocate, so the output is exactly ciphertext||tag with no IV prefix.
	return gcm.Seal(nil, iv, plaintext, aad), iv, nil
}

// encodeActivityIV matches the backend's `^[A-Za-z0-9+/]{16}$`: standard alphabet, no padding.
func encodeActivityIV(iv []byte) string {
	return base64.RawStdEncoding.EncodeToString(iv)
}

// newActivityChunkID mints a ULID, which sorts by time and is unique per session. A proxy-side counter
// cannot be used: it resets whenever the session cache evicts an entry, which happens at nine ordinary
// sites, and would then collide with the server's unique index for the rest of the session's life.
func newActivityChunkID(now time.Time) string {
	return ulid.MustNew(ulid.Timestamp(now), newULIDEntropy()).String()
}

// ulid.Monotonic is deliberately not used: it keeps state per reader, and two goroutines sealing in the
// same millisecond would need a mutex around it for no benefit. 80 bits of randomness is ample here.
func newULIDEntropy() io.Reader { return rand.Reader }

// Kept so a test can assert the id is well formed without reaching for the library.
func parseActivityChunkID(id string) (time.Time, error) {
	parsed, err := ulid.Parse(id)
	if err != nil {
		return time.Time{}, err
	}
	return ulid.Time(parsed.Time()), nil
}
