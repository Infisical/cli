package certscan

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/sha1"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"unicode/utf16"
)

const (
	pkcs12KDFKeyID      = 1
	pkcs12KDFIVID       = 2
	pkcs12KDFBlockSize  = 64
	tripleDESKeyLength  = 24
	legacyPBEBlockBytes = des.BlockSize
)

var oidPBEWithSHAAnd3KeyTripleDESCBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 3}

type legacyPBEParams struct {
	Salt       []byte
	Iterations int
}

func bmpPassword(password string) []byte {
	units := utf16.Encode([]rune(password))
	out := make([]byte, 0, len(units)*2+2)
	for _, unit := range units {
		out = append(out, byte(unit>>8), byte(unit))
	}
	return append(out, 0, 0)
}

func repeatToBlock(pattern []byte) []byte {
	if len(pattern) == 0 {
		return nil
	}
	size := pkcs12KDFBlockSize * ((len(pattern) + pkcs12KDFBlockSize - 1) / pkcs12KDFBlockSize)
	out := make([]byte, size)
	for i := range out {
		out[i] = pattern[i%len(pattern)]
	}
	return out
}

func pkcs12KDF(salt, password []byte, iterations int, id byte, size int) []byte {
	diversifier := make([]byte, pkcs12KDFBlockSize)
	for i := range diversifier {
		diversifier[i] = id
	}
	input := append(repeatToBlock(salt), repeatToBlock(password)...)
	one := big.NewInt(1)

	var out []byte
	for len(out) < size {
		a := sha1.Sum(append(append([]byte{}, diversifier...), input...))
		for i := 1; i < iterations; i++ {
			a = sha1.Sum(a[:])
		}
		out = append(out, a[:]...)

		b := make([]byte, pkcs12KDFBlockSize)
		for i := range b {
			b[i] = a[i%sha1.Size]
		}
		bPlusOne := new(big.Int).Add(new(big.Int).SetBytes(b), one)
		for offset := 0; offset < len(input); offset += pkcs12KDFBlockSize {
			sum := new(big.Int).Add(new(big.Int).SetBytes(input[offset:offset+pkcs12KDFBlockSize]), bPlusOne)
			bytes := sum.Bytes()
			if len(bytes) > pkcs12KDFBlockSize {
				bytes = bytes[len(bytes)-pkcs12KDFBlockSize:]
			}
			block := input[offset : offset+pkcs12KDFBlockSize]
			for i := range block {
				block[i] = 0
			}
			copy(block[pkcs12KDFBlockSize-len(bytes):], bytes)
		}
	}
	return out[:size]
}

func decryptLegacyPBE(algorithm pkix.AlgorithmIdentifier, ciphertext []byte, password string) ([]byte, error) {
	if !algorithm.Algorithm.Equal(oidPBEWithSHAAnd3KeyTripleDESCBC) {
		return nil, errUnsupportedPKCS12Encryption
	}
	var params legacyPBEParams
	if _, err := asn1.Unmarshal(algorithm.Parameters.FullBytes, &params); err != nil {
		return nil, err
	}
	if params.Iterations <= 0 || params.Iterations > maxKDFIterations {
		return nil, errUnsupportedPKCS12Encryption
	}
	if len(ciphertext) == 0 || len(ciphertext)%legacyPBEBlockBytes != 0 {
		return nil, errKeystoreDecryptFailed
	}

	encodedPassword := bmpPassword(password)
	key := pkcs12KDF(params.Salt, encodedPassword, params.Iterations, pkcs12KDFKeyID, tripleDESKeyLength)
	iv := pkcs12KDF(params.Salt, encodedPassword, params.Iterations, pkcs12KDFIVID, legacyPBEBlockBytes)
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)
	return stripPKCS7Padding(plaintext, legacyPBEBlockBytes)
}
