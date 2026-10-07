package certscan

import (
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	jksMagic   = []byte{0xFE, 0xED, 0xFE, 0xED}
	jceksMagic = []byte{0xCE, 0xCE, 0xCE, 0xCE}
)

const (
	jksTagPrivateKey  = 1
	jksTagTrustedCert = 2
	jksTagSecretKey   = 3
)

var errJKSTruncated = errors.New("keystore is truncated")

type jksReader struct {
	data []byte
	pos  int
}

func (r *jksReader) take(n int) ([]byte, error) {
	if n < 0 || n > len(r.data)-r.pos {
		return nil, errJKSTruncated
	}
	out := r.data[r.pos : r.pos+n]
	r.pos += n
	return out, nil
}

func (r *jksReader) uint16() (int, error) {
	b, err := r.take(2)
	if err != nil {
		return 0, err
	}
	return int(binary.BigEndian.Uint16(b)), nil
}

func (r *jksReader) uint32() (int, error) {
	b, err := r.take(4)
	if err != nil {
		return 0, err
	}
	v := binary.BigEndian.Uint32(b)
	if int64(v) > int64(len(r.data)) {
		return 0, errJKSTruncated
	}
	return int(v), nil
}

func (r *jksReader) utf() (string, error) {
	n, err := r.uint16()
	if err != nil {
		return "", err
	}
	b, err := r.take(n)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (r *jksReader) certificate(version int) (*x509.Certificate, error) {
	if version == 2 {
		if _, err := r.utf(); err != nil {
			return nil, err
		}
	}
	n, err := r.uint32()
	if err != nil {
		return nil, err
	}
	raw, err := r.take(n)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(raw)
}

func jksParseError(format Format, message string) ParseResult {
	return ParseResult{Format: format, IsKeystore: true, Status: StatusParseError, Err: message}
}

func parseJKS(data []byte, format Format) ParseResult {
	result := ParseResult{Format: format, IsKeystore: true}
	r := &jksReader{data: data, pos: 4}

	version, err := r.uint32()
	if err != nil || (version != 1 && version != 2) {
		return jksParseError(format, "unsupported keystore version")
	}
	count, err := r.uint32()
	if err != nil {
		return jksParseError(format, "invalid keystore entry count")
	}

	var trusted []*x509.Certificate
	fail := func(e error) ParseResult {
		if len(result.Chains) == 0 && len(trusted) == 0 {
			return jksParseError(format, e.Error())
		}
		result.Err = e.Error()
		return finishJKS(result, trusted)
	}

	for i := 0; i < count; i++ {
		tag, err := r.uint32()
		if err != nil {
			return fail(err)
		}
		if _, err := r.utf(); err != nil {
			return fail(err)
		}
		if _, err := r.take(8); err != nil {
			return fail(err)
		}

		switch tag {
		case jksTagPrivateKey:
			keyLen, err := r.uint32()
			if err != nil {
				return fail(err)
			}
			if _, err := r.take(keyLen); err != nil {
				return fail(err)
			}
			chainLen, err := r.uint32()
			if err != nil {
				return fail(err)
			}
			var chain []*x509.Certificate
			for j := 0; j < chainLen; j++ {
				cert, err := r.certificate(version)
				if err != nil {
					return fail(err)
				}
				chain = append(chain, cert)
			}
			result.Chains = append(result.Chains, chainFromOrdered(chain)...)
		case jksTagTrustedCert:
			cert, err := r.certificate(version)
			if err != nil {
				return fail(err)
			}
			trusted = append(trusted, cert)
		case jksTagSecretKey:
			if err := skipSealedSecretKey(r); err != nil {
				return fail(err)
			}
		default:
			return fail(fmt.Errorf("unknown keystore entry type %d", tag))
		}
	}
	return finishJKS(result, trusted)
}

func finishJKS(result ParseResult, trusted []*x509.Certificate) ParseResult {
	for _, cert := range dedupeCertificates(trusted) {
		result.Chains = append(result.Chains, Chain{Kind: ChainKindCA, Certificates: [][]byte{cert.Raw}})
	}
	if len(result.Chains) == 0 {
		result.Status = StatusNoCertificates
		return result
	}
	result.Status = StatusOK
	return result
}
