package agentvault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/google/uuid"
)

const sessionLogAADVersion = "v1"

const sessionLogIVBytes = 12

// Must byte-match frontend sessionLogDecrypt.ts and the vector pinned in agent-vault-session-log-crypto.test.ts.
func buildSessionLogAAD(sessionID, chunkID string) []byte {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s", sessionID, chunkID, sessionLogAADVersion)))
	return sum[:]
}

func sealSessionLog(key, plaintext, aad []byte) (ciphertext []byte, iv []byte, err error) {
	return sealSessionLogWithRand(rand.Reader, key, plaintext, aad)
}

func sealSessionLogWithRand(random io.Reader, key, plaintext, aad []byte) (ciphertext []byte, iv []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("agent-vault: session log key is not a valid AES key: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("agent-vault: could not build GCM: %w", err)
	}

	iv = make([]byte, sessionLogIVBytes)
	if _, err = io.ReadFull(random, iv); err != nil {
		return nil, nil, fmt.Errorf("agent-vault: could not read a nonce: %w", err)
	}

	return gcm.Seal(nil, iv, plaintext, aad), iv, nil
}

func encodeSessionLogIV(iv []byte) string {
	return base64.RawStdEncoding.EncodeToString(iv)
}

// The browser checks the downloaded object against this before decrypting, so an edited object reads as
// changed rather than as a decryption failure.
func sessionLogCiphertextSHA256(ciphertext []byte) string {
	sum := sha256.Sum256(ciphertext)
	return base64.RawStdEncoding.EncodeToString(sum[:])
}

func newSessionLogChunkID() (string, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return "", fmt.Errorf("agent-vault: could not mint a session log chunk id: %w", err)
	}
	return id.String(), nil
}
