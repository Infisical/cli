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

const (
	ORA1017InvalidCredentials = 1017
)

func PKCS5Padding(cipherText []byte, blockSize int) []byte {
	padding := blockSize - len(cipherText)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(cipherText, padtext...)
}

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

func encryptPassword(password, key []byte, padding bool) (string, error) {
	buff1 := make([]byte, 0x10)
	if _, err := rand.Read(buff1); err != nil {
		return "", err
	}
	buffer := append(buff1, password...)
	return encryptSessionKey(padding, key, buffer)
}

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
