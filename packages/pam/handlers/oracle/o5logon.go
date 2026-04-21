// Portions of this file are adapted from github.com/sijms/go-ora/v2,
// licensed under MIT. Copyright (c) 2020 Samy Sultan.
// Original: auth_object.go (generateSpeedyKey, getKeyFromUserNameAndPassword,
// decryptSessionKey, encryptSessionKey, encryptPassword, generatePasswordEncKey) and
// network/security/general.go (PKCS5Padding).
// Modifications for server-side use by Infisical: the roles are inverted — the gateway
// acts as the Oracle server verifying the client's O5Logon using the placeholder password.

package oracle

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
)

// O5Logon verifier types. Only 18453 (12c+ PBKDF2+SHA512) is supported in v1.
const (
	VerifierType10g = 2361
	VerifierType11g = 6949
	VerifierType12c = 18453
)

// Oracle error codes we return on the client-facing leg.
const (
	ORA1017InvalidCredentials = 1017
	ORA12660EncryptionRequired = 12660
)

// PKCS5Padding appends PKCS#5 padding.
func PKCS5Padding(cipherText []byte, blockSize int) []byte {
	padding := blockSize - len(cipherText)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(cipherText, padtext...)
}

// generateSpeedyKey is HMAC-SHA512 iterative XOR, used for PBKDF2-like derivation.
func generateSpeedyKey(buffer, key []byte, turns int) []byte {
	mac := hmac.New(sha512.New, key)
	mac.Write(append(buffer, 0, 0, 0, 1))
	firstHash := mac.Sum(nil)
	tempHash := make([]byte, len(firstHash))
	copy(tempHash, firstHash)
	for index1 := 2; index1 <= turns; index1++ {
		mac.Reset()
		mac.Write(tempHash)
		tempHash = mac.Sum(nil)
		for index2 := 0; index2 < 64; index2++ {
			firstHash[index2] = firstHash[index2] ^ tempHash[index2]
		}
	}
	return firstHash
}

// decryptSessionKey AES-CBC-decrypts a hex-encoded session key using a null IV.
func decryptSessionKey(padding bool, encKey []byte, sessionKeyHex string) ([]byte, error) {
	result, err := hex.DecodeString(sessionKeyHex)
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	dec := cipher.NewCBCDecrypter(blk, make([]byte, 16))
	output := make([]byte, len(result))
	dec.CryptBlocks(output, result)
	cutLen := 0
	if padding {
		num := int(output[len(output)-1])
		if num < dec.BlockSize() {
			apply := true
			for x := len(output) - num; x < len(output); x++ {
				if output[x] != uint8(num) {
					apply = false
					break
				}
			}
			if apply {
				cutLen = int(output[len(output)-1])
			}
		}
	}
	return output[:len(output)-cutLen], nil
}

// encryptSessionKey AES-CBC-encrypts a byte slice and returns hex. Mirrors go-ora.
func encryptSessionKey(padding bool, encKey []byte, sessionKey []byte) (string, error) {
	blk, err := aes.NewCipher(encKey)
	if err != nil {
		return "", err
	}
	enc := cipher.NewCBCEncrypter(blk, make([]byte, 16))
	originalLen := len(sessionKey)
	sessionKey = PKCS5Padding(sessionKey, blk.BlockSize())
	output := make([]byte, len(sessionKey))
	enc.CryptBlocks(output, sessionKey)
	if !padding {
		return fmt.Sprintf("%X", output[:originalLen]), nil
	}
	return fmt.Sprintf("%X", output), nil
}

// encryptPassword prepends 16 random bytes to `password`, then encrypts.
func encryptPassword(password, key []byte, padding bool) (string, error) {
	buff1 := make([]byte, 0x10)
	if _, err := rand.Read(buff1); err != nil {
		return "", err
	}
	buffer := append(buff1, password...)
	return encryptSessionKey(padding, key, buffer)
}

// O5LogonServerState is the per-session state the gateway maintains across O5Logon's
// two message phases. All crypto runs against ProxyPasswordPlaceholder.
type O5LogonServerState struct {
	// ServerSessKey is the raw (not-yet-encrypted) server session key we sent to the client.
	ServerSessKey []byte
	// Salt is the AUTH_VFR_DATA we sent (10 raw bytes; hex-encoded on the wire).
	Salt []byte
	// Pbkdf2CSKSalt is AUTH_PBKDF2_CSK_SALT — EXACTLY 32 hex characters (16 raw bytes). ORA-28041 otherwise.
	Pbkdf2CSKSalt string
	Pbkdf2VGenCount int
	Pbkdf2SDerCount int

	// EServerSessKey is the hex-encoded encrypted server session key we sent (for round-trip checks).
	EServerSessKey string

	// speedyKey derived from the placeholder + salt; cached so phase 2 doesn't recompute.
	speedyKey []byte
	// key is the per-session encryption key derived from placeholder password and pbkdf2 params.
	key []byte
}

// NewO5LogonServerState generates the server-side challenge material using the placeholder password.
// Sizes match a real Oracle 19c listener's output: server session key = 32 raw bytes
// (64 hex chars on the wire), salt = 16 raw bytes (32 hex chars), PBKDF2 CSK salt = 16 raw.
func NewO5LogonServerState() (*O5LogonServerState, error) {
	s := &O5LogonServerState{
		Pbkdf2VGenCount: 4096,
		Pbkdf2SDerCount: 3,
	}

	s.ServerSessKey = make([]byte, 32)
	if _, err := rand.Read(s.ServerSessKey); err != nil {
		return nil, err
	}

	s.Salt = make([]byte, 16)
	if _, err := rand.Read(s.Salt); err != nil {
		return nil, err
	}

	// AUTH_PBKDF2_CSK_SALT must be exactly 32 hex chars on the wire (16 raw bytes).
	csk := make([]byte, 16)
	if _, err := rand.Read(csk); err != nil {
		return nil, err
	}
	s.Pbkdf2CSKSalt = fmt.Sprintf("%X", csk)

	key, speedy, err := deriveServerKey(ProxyPasswordPlaceholder, s.Salt, s.Pbkdf2VGenCount)
	if err != nil {
		return nil, err
	}
	s.key = key
	s.speedyKey = speedy

	eServerSessKey, err := encryptSessionKey(false, key, s.ServerSessKey)
	if err != nil {
		return nil, err
	}
	s.EServerSessKey = eServerSessKey

	return s, nil
}

// deriveServerKey computes the 32-byte AES-256 key used to encrypt AUTH_SESSKEY for
// verifier type 18453 (12c+ PBKDF2+SHA512), same as go-ora's client-side derivation.
func deriveServerKey(password string, salt []byte, vGenCount int) (key []byte, speedy []byte, err error) {
	message := append([]byte(nil), salt...)
	message = append(message, []byte("AUTH_PBKDF2_SPEEDY_KEY")...)
	speedy = generateSpeedyKey(message, []byte(password), vGenCount)

	buffer := append([]byte(nil), speedy...)
	buffer = append(buffer, salt...)
	h := sha512.New()
	h.Write(buffer)
	key = h.Sum(nil)[:32]
	return
}

// VerifyClientPassword runs the server side of the phase-2 handshake: decrypt the
// client's AUTH_SESSKEY + AUTH_PASSWORD and confirm the plaintext password matches the
// placeholder. Returns the clientSessKey (needed for the SVR response) plus the password
// encryption key.
func (s *O5LogonServerState) VerifyClientPassword(eClientSessKey, ePassword string) (clientSessKey, encKey []byte, err error) {
	clientSessKey, err = decryptSessionKey(false, s.key, eClientSessKey)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt client session key: %w", err)
	}
	if len(clientSessKey) != len(s.ServerSessKey) {
		// For verifier 18453, len should be 48. Mismatch → bad protocol or key mismatch.
		return nil, nil, errors.New("client session key length mismatch")
	}

	// Derive password encryption key: generateSpeedyKey(pbkdf2ChkSalt_raw,
	//   hex(clientSessKey || serverSessKey), pbkdf2SderCount)[:32]   for verifier 18453.
	buffer := append([]byte(nil), clientSessKey...)
	buffer = append(buffer, s.ServerSessKey...)
	keyBuffer := []byte(fmt.Sprintf("%X", buffer))
	df2key, err := hex.DecodeString(s.Pbkdf2CSKSalt)
	if err != nil {
		return nil, nil, fmt.Errorf("decode pbkdf2 salt: %w", err)
	}
	encKey = generateSpeedyKey(df2key, keyBuffer, s.Pbkdf2SDerCount)[:32]

	// Client calls encryptPassword(password, key, padding=true), which PKCS5-pads the
	// (random16 || password) buffer to a 16-byte boundary and returns the full padded
	// ciphertext. We decrypt with padding=true so decryptSessionKey strips the PKCS5
	// pad, leaving (random16 || password).
	decoded, err := decryptSessionKey(true, encKey, ePassword)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt password: %w", err)
	}
	// encryptPassword prepended 16 random bytes before encryption.
	if len(decoded) <= 16 {
		return nil, nil, errors.New("decoded password too short")
	}
	plain := decoded[16:]
	if string(plain) != ProxyPasswordPlaceholder {
		return nil, nil, errors.New("password mismatch")
	}
	return clientSessKey, encKey, nil
}

// BuildSvrResponse produces AUTH_SVR_RESPONSE: AES-CBC(rand(16) || "SERVER_TO_CLIENT", encKey).
// The client decrypts it and verifies bytes [16:32] == "SERVER_TO_CLIENT" (verified from
// auth_object.go:526-537 — the commented-out VerifyResponse in go-ora).
func BuildSvrResponse(encKey []byte) (string, error) {
	head := make([]byte, 16)
	if _, err := rand.Read(head); err != nil {
		return "", err
	}
	body := append(head, []byte("SERVER_TO_CLIENT")...)
	return encryptSessionKey(true, encKey, body)
}

// Legacy 11g (verifier 6949) key derivation, kept for reference — v1 does not use it.
// nolint: unused
func deriveKey11g(password, saltHex string) ([]byte, error) {
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return nil, err
	}
	buffer := append([]byte(password), salt...)
	h := sha1.New()
	if _, err := h.Write(buffer); err != nil {
		return nil, err
	}
	key := h.Sum(nil)
	key = append(key, 0, 0, 0, 0)
	return key, nil
}

// md5Hash is a small helper so callers don't have to import md5 directly.
// nolint: unused
func md5Hash(data []byte) []byte {
	sum := md5.Sum(data)
	out := make([]byte, 16)
	copy(out, sum[:])
	return out
}

// parseIntVal is a small utility for parsing the integer-encoded TTC values
// (VGEN_COUNT / SDER_COUNT) we read out of AUTH_* key-values.
func parseIntVal(v []byte) (int, error) {
	if len(v) == 0 {
		return 0, nil
	}
	return strconv.Atoi(string(v))
}
