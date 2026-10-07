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

// Must byte-match frontend sessionLogDecrypt.ts, whose test pins the same vector as session_log_crypto_test.go.
func buildSessionLogAAD(sessionID, chunkID string) []byte {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s", sessionID, chunkID, sessionLogAADVersion)))
	return sum[:]
}

// Returns IV ‖ ciphertext ‖ tag: the object holds its own IV, so nothing about a chunk has to be stored elsewhere.
func sealSessionLog(key, plaintext, aad []byte) ([]byte, error) {
	return sealSessionLogWithRand(rand.Reader, key, plaintext, aad)
}

func sealSessionLogWithRand(random io.Reader, key, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("agent-vault: session log key is not a valid AES key: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("agent-vault: could not build GCM: %w", err)
	}

	blob := make([]byte, sessionLogIVBytes, sessionLogIVBytes+len(plaintext)+gcm.Overhead())
	if _, err = io.ReadFull(random, blob); err != nil {
		return nil, fmt.Errorf("agent-vault: could not read a nonce: %w", err)
	}

	return gcm.Seal(blob, blob[:sessionLogIVBytes], plaintext, aad), nil
}

// Infisical signs this into the upload link, so S3 refuses any other body.
func infisicalCiphertextSha256(ciphertext []byte) string {
	sum := sha256.Sum256(ciphertext)
	return base64.RawStdEncoding.EncodeToString(sum[:])
}

// S3 wants the digest in padded base64, while Infisical takes it unpadded.
func s3ChecksumHeader(ciphertext []byte) string {
	sum := sha256.Sum256(ciphertext)
	return base64.StdEncoding.EncodeToString(sum[:])
}

func newSessionLogChunkID() (string, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return "", fmt.Errorf("agent-vault: could not mint a session log chunk id: %w", err)
	}
	return id.String(), nil
}
