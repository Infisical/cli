package gatewayv2

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
)

const (
	ckkMlDsa            = 0x4a
	ckmMlDsaKeyPairGen  = 0x1c
	ckmMlDsa            = 0x1d
	ckaParameterSet     = 0x61d
	mechanismMlDsa      = "CKM_ML_DSA"
	mlDsaParameterSet44 = 0x1
	mlDsaParameterSet65 = 0x2
	mlDsaParameterSet87 = 0x3
)

type mlDsaParams struct {
	keyAlgorithm   string
	parameterSet   uint
	oid            asn1.ObjectIdentifier
	publicKeyBytes int
}

var mlDsaParamsList = []mlDsaParams{
	{KeyAlgorithmMLDSA44, mlDsaParameterSet44, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}, 1312},
	{KeyAlgorithmMLDSA65, mlDsaParameterSet65, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}, 1952},
	{KeyAlgorithmMLDSA87, mlDsaParameterSet87, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}, 2592},
}

func mlDsaParamsByKeyAlgorithm(keyAlgorithm string) (mlDsaParams, bool) {
	for _, p := range mlDsaParamsList {
		if p.keyAlgorithm == keyAlgorithm {
			return p, true
		}
	}
	return mlDsaParams{}, false
}

type mlDsaPublicKey struct {
	keyAlgorithm string
	raw          []byte
}

type subjectPublicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

func marshalMlDsaSpki(keyAlgorithm string, raw []byte) ([]byte, error) {
	params, ok := mlDsaParamsByKeyAlgorithm(keyAlgorithm)
	if !ok {
		return nil, fmt.Errorf("unsupported ML-DSA key algorithm %q", keyAlgorithm)
	}
	if len(raw) != params.publicKeyBytes {
		return nil, fmt.Errorf("%s public key is %d bytes, expected %d", keyAlgorithm, len(raw), params.publicKeyBytes)
	}
	return asn1.Marshal(subjectPublicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: params.oid},
		PublicKey: asn1.BitString{Bytes: raw, BitLength: len(raw) * 8},
	})
}

var errNotMlDsaSpki = errors.New("not an ML-DSA SubjectPublicKeyInfo")

func parseMlDsaSpki(der []byte) (*mlDsaPublicKey, error) {
	var info subjectPublicKeyInfo
	rest, err := asn1.Unmarshal(der, &info)
	if err != nil || len(rest) != 0 {
		return nil, errNotMlDsaSpki
	}
	for _, p := range mlDsaParamsList {
		if !info.Algorithm.Algorithm.Equal(p.oid) {
			continue
		}
		if len(info.Algorithm.Parameters.FullBytes) != 0 || info.PublicKey.BitLength != p.publicKeyBytes*8 {
			return nil, fmt.Errorf("malformed %s SubjectPublicKeyInfo", p.keyAlgorithm)
		}
		return &mlDsaPublicKey{keyAlgorithm: p.keyAlgorithm, raw: info.PublicKey.Bytes}, nil
	}
	return nil, errNotMlDsaSpki
}

func mlDsaSpkiFromValue(keyAlgorithm string, value []byte) ([]byte, error) {
	params, ok := mlDsaParamsByKeyAlgorithm(keyAlgorithm)
	if !ok {
		return nil, fmt.Errorf("unsupported ML-DSA key algorithm %q", keyAlgorithm)
	}
	if len(value) == params.publicKeyBytes {
		return marshalMlDsaSpki(keyAlgorithm, value)
	}
	if pub, err := parseMlDsaSpki(value); err == nil {
		if pub.keyAlgorithm != keyAlgorithm {
			return nil, fmt.Errorf("CKA_VALUE holds a %s public key, expected %s", pub.keyAlgorithm, keyAlgorithm)
		}
		return value, nil
	}
	var wrapped []byte
	if rest, err := asn1.Unmarshal(value, &wrapped); err == nil && len(rest) == 0 && len(wrapped) == params.publicKeyBytes {
		return marshalMlDsaSpki(keyAlgorithm, wrapped)
	}
	return nil, fmt.Errorf("%s CKA_VALUE is not a raw public key, a SubjectPublicKeyInfo, or an OCTET STRING holding the raw key", keyAlgorithm)
}
