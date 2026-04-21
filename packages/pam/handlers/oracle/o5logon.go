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
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
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

