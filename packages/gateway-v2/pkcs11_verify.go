package gatewayv2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"math/big"
	"strings"
)

var errSignatureMismatch = &Pkcs11Error{Code: Pkcs11ErrSignatureMismatch, Message: "Signature does not verify with the expected public key"}

func mechanismHash(mechanism string) (crypto.Hash, error) {
	switch mechanism {
	case "CKM_SHA256_RSA_PKCS", "CKM_ECDSA_SHA256":
		return crypto.SHA256, nil
	case "CKM_SHA384_RSA_PKCS", "CKM_ECDSA_SHA384":
		return crypto.SHA384, nil
	case "CKM_SHA512_RSA_PKCS":
		return crypto.SHA512, nil
	case "CKM_RSA_PKCS", "CKM_ECDSA":
		return 0, nil
	}
	return 0, &Pkcs11Error{Code: Pkcs11ErrMechanismInvalid, Message: fmt.Sprintf("Unsupported mechanism %q", mechanism)}
}

const (
	maxPublicKeySpkiBytes = 1024
	maxRsaModulusBits     = 4096
)

func parseExpectedPublicKey(publicKeySpki []byte) (crypto.PublicKey, error) {
	if len(publicKeySpki) > maxPublicKeySpkiBytes {
		return nil, &Pkcs11Error{Code: Pkcs11ErrBadRequest, Message: "publicKey is too large"}
	}
	pub, err := x509.ParsePKIXPublicKey(publicKeySpki)
	if err != nil {
		return nil, &Pkcs11Error{Code: Pkcs11ErrBadRequest, Message: "publicKey is not a valid SubjectPublicKeyInfo"}
	}
	if rsaKey, ok := pub.(*rsa.PublicKey); ok && rsaKey.N.BitLen() > maxRsaModulusBits {
		return nil, &Pkcs11Error{Code: Pkcs11ErrBadRequest, Message: "publicKey RSA modulus is larger than 4096 bits"}
	}
	return pub, nil
}

func completeSign(signature []byte, attrsReadable bool, readKeyID []byte, key KeyRef, expectedPublicKey crypto.PublicKey, mechanism string, isDigest bool, data []byte) (SignResult, error) {
	if attrsReadable {
		return SignResult{Signature: signature, KeyID: readKeyID}, nil
	}
	if expectedPublicKey != nil {
		if err := verifySignature(expectedPublicKey, mechanism, isDigest, data, signature); err != nil {
			return SignResult{}, err
		}
	}
	return SignResult{Signature: signature, KeyID: key.ID}, nil
}

func verifySignature(pub crypto.PublicKey, mechanism string, isDigest bool, data, signature []byte) error {
	hash, err := mechanismHash(mechanism)
	if err != nil {
		return err
	}
	hsmHashesData := !isDigest || !strings.HasPrefix(mechanism, "CKM_ECDSA")
	digest := data
	if hash != 0 && hsmHashesData {
		h := hash.New()
		h.Write(data)
		digest = h.Sum(nil)
	}

	switch key := pub.(type) {
	case *rsa.PublicKey:
		if mechanism == "CKM_RSA_PKCS" {
			hash = 0
		}
		if rsa.VerifyPKCS1v15(key, hash, digest, signature) != nil {
			return errSignatureMismatch
		}
		return nil
	case *ecdsa.PublicKey:
		size := (key.Curve.Params().BitSize + 7) / 8
		if len(signature) != 2*size {
			return errSignatureMismatch
		}
		r := new(big.Int).SetBytes(signature[:size])
		s := new(big.Int).SetBytes(signature[size:])
		if !ecdsa.Verify(key, digest, r, s) {
			return errSignatureMismatch
		}
		return nil
	}
	return &Pkcs11Error{Code: Pkcs11ErrMechanismInvalid, Message: "Unsupported public key type"}
}
