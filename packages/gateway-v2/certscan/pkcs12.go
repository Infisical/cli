package certscan

import (
	"crypto/x509"
	"errors"

	"software.sslmate.com/src/go-pkcs12"
)

func passwordStatus(password *string) FileStatus {
	if password == nil {
		return StatusLocked
	}
	return StatusPasswordFailed
}

func parsePKCS12(data []byte, password *string) ParseResult {
	result := ParseResult{Format: FormatPKCS12, IsKeystore: true}
	secret := ""
	if password != nil {
		secret = *password
	}

	if pkcs12KDFWorkWithinLimit(data) {
		_, leaf, caCerts, err := pkcs12.DecodeChain(data, secret)
		if err == nil {
			result.Status = StatusOK
			result.Chains = chainFromOrdered(append([]*x509.Certificate{leaf}, caCerts...))
			return result
		}
		if errors.Is(err, pkcs12.ErrIncorrectPassword) {
			result.Status = passwordStatus(password)
			return result
		}
	}

	certs, bagErr := decodePKCS12CertificateBags(data, secret)
	switch {
	case bagErr == nil && len(certs) == 0:
		result.Status = StatusNoCertificates
	case bagErr == nil:
		result.Status = StatusOK
		result.Chains = buildChains(certs)
	case errors.Is(bagErr, errKeystoreDecryptFailed):
		result.Status = passwordStatus(password)
	default:
		result.Status = StatusUnsupported
		result.Err = "the keystore uses a format or encryption scheme that is not supported"
	}
	return result
}
