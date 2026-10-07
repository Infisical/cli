package certscan

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"

	"go.mozilla.org/pkcs7"
)

var pemMarker = []byte("-----BEGIN ")

const (
	asn1SequenceTag    = 0x30
	asn1LongFormLength = 0x80
)

func Parse(data []byte, password *string) ParseResult {
	switch {
	case bytes.HasPrefix(data, jksMagic):
		return parseJKS(data, FormatJKS)
	case bytes.HasPrefix(data, jceksMagic):
		return parseJKS(data, FormatJCEKS)
	case bytes.Contains(data, pemMarker):
		return parsePEM(data)
	default:
		return parseDER(data, password)
	}
}

func parseTrustedCertificate(der []byte) (*x509.Certificate, error) {
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(der, &raw); err != nil {
		return nil, err
	}
	return x509.ParseCertificate(raw.FullBytes)
}

func parsePEM(data []byte) ParseResult {
	result := ParseResult{Format: FormatPEM}
	var certs []*x509.Certificate
	sawCertificateBlock := false
	onlyPKCS7 := true

	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "CERTIFICATE", "X509 CERTIFICATE":
			sawCertificateBlock = true
			onlyPKCS7 = false
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				certs = append(certs, cert)
			}
		case "TRUSTED CERTIFICATE":
			sawCertificateBlock = true
			onlyPKCS7 = false
			if cert, err := parseTrustedCertificate(block.Bytes); err == nil {
				certs = append(certs, cert)
			}
		case "PKCS7":
			sawCertificateBlock = true
			if p7, err := pkcs7.Parse(block.Bytes); err == nil {
				certs = append(certs, p7.Certificates...)
			}
		}
	}

	if len(certs) == 0 {
		if sawCertificateBlock {
			result.Status = StatusParseError
			result.Err = "certificate blocks could not be parsed"
			return result
		}
		result.Status = StatusNoCertificates
		return result
	}
	if onlyPKCS7 {
		result.Format = FormatPKCS7
	}
	result.Status = StatusOK
	result.Chains = buildChains(certs)
	return result
}

func parseDER(data []byte, password *string) ParseResult {
	if cert, err := x509.ParseCertificate(data); err == nil {
		return ParseResult{Format: FormatDER, Status: StatusOK, Chains: buildChains([]*x509.Certificate{cert})}
	}
	if p7, err := pkcs7.Parse(data); err == nil && len(p7.Certificates) > 0 {
		return ParseResult{Format: FormatPKCS7, Status: StatusOK, Chains: buildChains(p7.Certificates)}
	}
	if len(data) < 2 || data[0] != asn1SequenceTag || data[1]&asn1LongFormLength == 0 {
		return ParseResult{Status: StatusNoCertificates}
	}
	return parsePKCS12(data, password)
}
