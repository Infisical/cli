//go:build pkcs11

package gatewayv2

import (
	"encoding/binary"
	"testing"

	"github.com/miekg/pkcs11"
)

func ulongBytes(v uint) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(v))
	return b
}

func TestMlDsaKeyPairTemplatesSetParameterSet(t *testing.T) {
	for _, params := range mlDsaParamsList {
		mechanisms, pubTpl, privTpl, err := generateKeyPairTemplates("ca-key", []byte{0x01}, params.keyAlgorithm)
		if err != nil {
			t.Fatalf("%s: %v", params.keyAlgorithm, err)
		}
		if len(mechanisms) != 1 || mechanisms[0].Mechanism != ckmMlDsaKeyPairGen {
			t.Fatalf("%s: expected CKM_ML_DSA_KEY_PAIR_GEN", params.keyAlgorithm)
		}
		var parameterSet []byte
		for _, attr := range pubTpl {
			if attr.Type == ckaParameterSet {
				parameterSet = attr.Value
			}
		}
		if parameterSet == nil || decodeUlong(parameterSet) != params.parameterSet {
			t.Fatalf("%s: public template must set CKA_PARAMETER_SET to %d", params.keyAlgorithm, params.parameterSet)
		}
		signable := false
		for _, attr := range privTpl {
			if attr.Type == pkcs11.CKA_SIGN && len(attr.Value) == 1 && attr.Value[0] == 1 {
				signable = true
			}
		}
		if !signable {
			t.Fatalf("%s: private template must allow signing", params.keyAlgorithm)
		}
	}
}

func TestResolveMechanismMlDsa(t *testing.T) {
	code, params, err := resolveMechanism(mechanismMlDsa, false)
	if err != nil || code != ckmMlDsa || params != nil {
		t.Fatalf("CKM_ML_DSA must resolve to the pure mechanism with no parameters, got %x %v %v", code, params, err)
	}
	_, _, err = resolveMechanism(mechanismMlDsa, true)
	expectCode(t, err, Pkcs11ErrBadRequest)
}

func TestAssertKeyTypeMatchesMechanismMlDsa(t *testing.T) {
	if err := assertKeyTypeMatchesMechanism(ulongBytes(ckkMlDsa), mechanismMlDsa); err != nil {
		t.Fatalf("an ML-DSA key must match CKM_ML_DSA: %v", err)
	}
	expectCode(t, assertKeyTypeMatchesMechanism(ulongBytes(pkcs11.CKK_EC), mechanismMlDsa), Pkcs11ErrKeyTypeMismatch)
	expectCode(t, assertKeyTypeMatchesMechanism(ulongBytes(ckkMlDsa), "CKM_ECDSA_SHA256"), Pkcs11ErrKeyTypeMismatch)
	expectCode(t, assertKeyTypeMatchesMechanism(ulongBytes(ckkMlDsa), "CKM_SHA256_RSA_PKCS"), Pkcs11ErrKeyTypeMismatch)
}

func TestMapPkcs11GenerateError(t *testing.T) {
	expectCode(t, mapPkcs11GenerateError(pkcs11.Error(pkcs11.CKR_MECHANISM_INVALID), KeyAlgorithmRSA2048), Pkcs11ErrMechanismInvalid)
	expectCode(t, mapPkcs11GenerateError(pkcs11.Error(pkcs11.CKR_ATTRIBUTE_TYPE_INVALID), KeyAlgorithmMLDSA65), Pkcs11ErrMechanismInvalid)
	expectCode(t, mapPkcs11GenerateError(pkcs11.Error(pkcs11.CKR_TEMPLATE_INCONSISTENT), KeyAlgorithmRSA2048), Pkcs11ErrInternal)
	expectCode(t, mapPkcs11GenerateError(pkcs11.Error(pkcs11.CKR_DEVICE_REMOVED), KeyAlgorithmMLDSA44), Pkcs11ErrDriverUnavailable)
}
