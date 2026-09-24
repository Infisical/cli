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

const activityAADVersion = "v1"

const activityIVBytes = 12

// Must byte-match frontend activityDecrypt.ts and the vector pinned in agent-vault-activity-crypto.test.ts.
func buildActivityAAD(projectID, sessionID, proxyID, chunkID string) []byte {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%s|%s", projectID, sessionID, proxyID, chunkID, activityAADVersion)))
	return sum[:]
}

func sealActivity(key, plaintext, aad []byte) (ciphertext []byte, iv []byte, err error) {
	return sealActivityWithRand(rand.Reader, key, plaintext, aad)
}

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

	return gcm.Seal(nil, iv, plaintext, aad), iv, nil
}

func encodeActivityIV(iv []byte) string {
	return base64.RawStdEncoding.EncodeToString(iv)
}

func newActivityChunkID(now time.Time) string {
	return ulid.MustNew(ulid.Timestamp(now), newULIDEntropy()).String()
}

func newULIDEntropy() io.Reader { return rand.Reader }
