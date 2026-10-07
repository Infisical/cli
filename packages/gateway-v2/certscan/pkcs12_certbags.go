package certscan

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"hash"
)

const maxKDFIterations = 10_000_000

var (
	oidDataContentType          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidEncryptedDataContentType = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}
	oidPBES2                    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2                   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidHMACWithSHA1             = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidHMACWithSHA256           = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidHMACWithSHA384           = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
	oidHMACWithSHA512           = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}
	oidAES128CBC                = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBC                = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC                = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidCertBagType              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}
	oidX509CertificateType      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}
)

var errUnsupportedPKCS12Encryption = errors.New("the keystore uses an encryption scheme that is not supported")

type p12ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

type p12PFX struct {
	Version  int
	AuthSafe p12ContentInfo
}

type p12EncryptedContentInfo struct {
	ContentType      asn1.ObjectIdentifier
	Algorithm        pkix.AlgorithmIdentifier
	EncryptedContent []byte `asn1:"tag:0,optional"`
}

type p12EncryptedData struct {
	Version              int
	EncryptedContentInfo p12EncryptedContentInfo
}

type p12SafeBag struct {
	ID    asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"tag:0,explicit"`
}

type p12CertBag struct {
	ID   asn1.ObjectIdentifier
	Data []byte `asn1:"tag:0,explicit"`
}

type p12PBES2Params struct {
	KeyDerivation    pkix.AlgorithmIdentifier
	EncryptionScheme pkix.AlgorithmIdentifier
}

type p12PBKDF2Params struct {
	Salt       []byte
	Iterations int
	KeyLength  int                      `asn1:"optional"`
	PRF        pkix.AlgorithmIdentifier `asn1:"optional"`
}

func unwrapOctetString(raw asn1.RawValue) ([]byte, error) {
	var octets []byte
	if _, err := asn1.Unmarshal(raw.Bytes, &octets); err != nil {
		return nil, err
	}
	return octets, nil
}

func pbkdf2Hash(prf pkix.AlgorithmIdentifier) (func() hash.Hash, error) {
	switch {
	case len(prf.Algorithm) == 0, prf.Algorithm.Equal(oidHMACWithSHA1):
		return sha1.New, nil
	case prf.Algorithm.Equal(oidHMACWithSHA256):
		return sha256.New, nil
	case prf.Algorithm.Equal(oidHMACWithSHA384):
		return sha512.New384, nil
	case prf.Algorithm.Equal(oidHMACWithSHA512):
		return sha512.New, nil
	}
	return nil, errUnsupportedPKCS12Encryption
}

func aesKeyLength(scheme asn1.ObjectIdentifier) (int, error) {
	switch {
	case scheme.Equal(oidAES128CBC):
		return 16, nil
	case scheme.Equal(oidAES192CBC):
		return 24, nil
	case scheme.Equal(oidAES256CBC):
		return 32, nil
	}
	return 0, errUnsupportedPKCS12Encryption
}

func decryptPBES2(algorithm pkix.AlgorithmIdentifier, ciphertext []byte, password string) ([]byte, error) {
	var params p12PBES2Params
	if _, err := asn1.Unmarshal(algorithm.Parameters.FullBytes, &params); err != nil {
		return nil, err
	}
	if !params.KeyDerivation.Algorithm.Equal(oidPBKDF2) {
		return nil, errUnsupportedPKCS12Encryption
	}
	var kdf p12PBKDF2Params
	if _, err := asn1.Unmarshal(params.KeyDerivation.Parameters.FullBytes, &kdf); err != nil {
		return nil, err
	}
	if kdf.Iterations <= 0 || kdf.Iterations > maxKDFIterations {
		return nil, errUnsupportedPKCS12Encryption
	}
	newHash, err := pbkdf2Hash(kdf.PRF)
	if err != nil {
		return nil, err
	}
	keyLength, err := aesKeyLength(params.EncryptionScheme.Algorithm)
	if err != nil {
		return nil, err
	}
	var iv []byte
	if _, err := asn1.Unmarshal(params.EncryptionScheme.Parameters.FullBytes, &iv); err != nil {
		return nil, err
	}
	if len(iv) != aes.BlockSize || len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("the keystore is malformed")
	}

	key, err := pbkdf2.Key(newHash, password, kdf.Salt, kdf.Iterations, keyLength)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)

	return stripPKCS7Padding(plaintext, aes.BlockSize)
}

func stripPKCS7Padding(plaintext []byte, blockSize int) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, errKeystoreDecryptFailed
	}
	padding := int(plaintext[len(plaintext)-1])
	if padding == 0 || padding > blockSize || padding > len(plaintext) {
		return nil, errKeystoreDecryptFailed
	}
	for _, b := range plaintext[len(plaintext)-padding:] {
		if int(b) != padding {
			return nil, errKeystoreDecryptFailed
		}
	}
	return plaintext[:len(plaintext)-padding], nil
}

var errKeystoreDecryptFailed = errors.New("the keystore could not be decrypted")

func certificatesFromSafeContents(der []byte) ([]*x509.Certificate, error) {
	var bags []p12SafeBag
	if _, err := asn1.Unmarshal(der, &bags); err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	for _, bag := range bags {
		if !bag.ID.Equal(oidCertBagType) {
			continue
		}
		var cb p12CertBag
		if _, err := asn1.Unmarshal(bag.Value.Bytes, &cb); err != nil || !cb.ID.Equal(oidX509CertificateType) {
			continue
		}
		if cert, err := x509.ParseCertificate(cb.Data); err == nil {
			certs = append(certs, cert)
		}
	}
	return certs, nil
}

func decodePKCS12CertificateBags(data []byte, password string) ([]*x509.Certificate, error) {
	var pfx p12PFX
	if _, err := asn1.Unmarshal(data, &pfx); err != nil {
		return nil, err
	}
	if !pfx.AuthSafe.ContentType.Equal(oidDataContentType) {
		return nil, errUnsupportedPKCS12Encryption
	}
	authSafe, err := unwrapOctetString(pfx.AuthSafe.Content)
	if err != nil {
		return nil, err
	}
	var contents []p12ContentInfo
	if _, err := asn1.Unmarshal(authSafe, &contents); err != nil {
		return nil, err
	}

	var certs []*x509.Certificate
	for _, ci := range contents {
		var safeContents []byte
		switch {
		case ci.ContentType.Equal(oidDataContentType):
			if safeContents, err = unwrapOctetString(ci.Content); err != nil {
				return nil, err
			}
		case ci.ContentType.Equal(oidEncryptedDataContentType):
			var ed p12EncryptedData
			if _, err := asn1.Unmarshal(ci.Content.Bytes, &ed); err != nil {
				return nil, err
			}
			info := ed.EncryptedContentInfo
			decrypt := decryptLegacyPBE
			if info.Algorithm.Algorithm.Equal(oidPBES2) {
				decrypt = decryptPBES2
			}
			if safeContents, err = decrypt(info.Algorithm, info.EncryptedContent, password); err != nil {
				return nil, err
			}
		default:
			continue
		}
		found, err := certificatesFromSafeContents(safeContents)
		if err != nil {
			return nil, err
		}
		certs = append(certs, found...)
	}
	return certs, nil
}
