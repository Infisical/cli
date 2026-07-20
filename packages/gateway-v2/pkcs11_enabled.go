//go:build pkcs11

package gatewayv2

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"math/big"
	"strings"
	"sync"

	"github.com/miekg/pkcs11"
	"github.com/rs/zerolog/log"
)

var (
	ecParamsP256 = []byte{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}
	ecParamsP384 = []byte{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22}
)

type pkcs11ModuleImpl struct {
	mu  sync.Mutex
	ctx *pkcs11.Ctx
}

func LoadPkcs11Module(path string) (Pkcs11Module, error) {
	if strings.TrimSpace(path) == "" {
		return nil, &Pkcs11Error{
			Code:    Pkcs11ErrDriverUnavailable,
			Message: "Empty --pkcs11-module path",
		}
	}
	ctx := pkcs11.New(path)
	if ctx == nil {
		return nil, &Pkcs11Error{
			Code:    Pkcs11ErrDriverUnavailable,
			Message: fmt.Sprintf("Failed to dlopen PKCS#11 driver at %q", path),
		}
	}
	if err := ctx.Initialize(); err != nil {
		if e, ok := err.(pkcs11.Error); !ok || e != pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED {
			ctx.Destroy()
			return nil, &Pkcs11Error{
				Code:    Pkcs11ErrDriverUnavailable,
				Message: fmt.Sprintf("PKCS#11 C_Initialize failed: %v", err),
			}
		}
	}
	if _, err := ctx.GetSlotList(true); err != nil {
		_ = ctx.Finalize()
		ctx.Destroy()
		return nil, &Pkcs11Error{
			Code:    Pkcs11ErrDriverUnavailable,
			Message: fmt.Sprintf("PKCS#11 C_GetSlotList failed: %v", err),
		}
	}
	return &pkcs11ModuleImpl{ctx: ctx}, nil
}

func (m *pkcs11ModuleImpl) Finalize() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ctx == nil {
		return nil
	}
	err := m.ctx.Finalize()
	m.ctx.Destroy()
	m.ctx = nil
	return err
}

type sessionFn func(slot uint, sh pkcs11.SessionHandle) error

func (m *pkcs11ModuleImpl) withSession(slotLabel string, pin []byte, fn sessionFn) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ctx == nil {
		return &Pkcs11Error{Code: Pkcs11ErrDriverUnavailable, Message: "Module is not loaded"}
	}
	slots, err := m.ctx.GetSlotList(true)
	if err != nil {
		return &Pkcs11Error{Code: Pkcs11ErrInternal, Message: "GetSlotList failed"}
	}
	slot, ok := findSlotByLabel(m.ctx, slots, slotLabel)
	if !ok {
		return &Pkcs11Error{Code: Pkcs11ErrSlotNotFound, Message: fmt.Sprintf("Slot %q not found on this HSM", slotLabel)}
	}
	session, err := m.ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return &Pkcs11Error{Code: Pkcs11ErrInternal, Message: "OpenSession failed"}
	}
	defer func() {
		if closeErr := m.ctx.CloseSession(session); closeErr != nil {
			log.Warn().Err(closeErr).Msg("pkcs11: CloseSession failed")
		}
	}()

	loggedIn := false
	loginErr := m.ctx.Login(session, pkcs11.CKU_USER, string(pin))
	if loginErr != nil {
		if e, ok := loginErr.(pkcs11.Error); !ok || e != pkcs11.CKR_USER_ALREADY_LOGGED_IN {
			return mapPkcs11LoginError(loginErr)
		}
	} else {
		loggedIn = true
	}
	if loggedIn {
		defer func() {
			if logoutErr := m.ctx.Logout(session); logoutErr != nil {
				log.Warn().Err(logoutErr).Msg("pkcs11: Logout failed")
			}
		}()
	}

	return fn(slot, session)
}

func findSlotByLabel(ctx *pkcs11.Ctx, slots []uint, label string) (uint, bool) {
	for _, slot := range slots {
		ti, err := ctx.GetTokenInfo(slot)
		if err != nil {
			continue
		}
		if strings.TrimRight(ti.Label, " \x00") == label {
			return slot, true
		}
	}
	return 0, false
}

func mapPkcs11LoginError(err error) error {
	if e, ok := err.(pkcs11.Error); ok {
		switch e {
		case pkcs11.CKR_PIN_INCORRECT:
			return &Pkcs11Error{Code: Pkcs11ErrPinIncorrect, Message: "The HSM rejected the PIN"}
		case pkcs11.CKR_PIN_LOCKED:
			return &Pkcs11Error{Code: Pkcs11ErrPinLocked, Message: "The HSM has locked the slot"}
		case pkcs11.CKR_TOKEN_NOT_PRESENT, pkcs11.CKR_DEVICE_REMOVED, pkcs11.CKR_DEVICE_ERROR:
			return &Pkcs11Error{Code: Pkcs11ErrDriverUnavailable, Message: "Driver unavailable"}
		}
	}
	return &Pkcs11Error{Code: Pkcs11ErrLoginFailed, Message: "The HSM rejected the login"}
}

func (m *pkcs11ModuleImpl) Test(slotLabel string, pin []byte) (SlotInfo, error) {
	var info SlotInfo
	err := m.withSession(slotLabel, pin, func(slot uint, _ pkcs11.SessionHandle) error {
		ti, err := m.ctx.GetTokenInfo(slot)
		if err != nil {
			return &Pkcs11Error{Code: Pkcs11ErrInternal, Message: "GetTokenInfo failed"}
		}
		info = SlotInfo{
			Manufacturer: strings.TrimRight(ti.ManufacturerID, " \x00"),
			Model:        strings.TrimRight(ti.Model, " \x00"),
			Firmware:     fmt.Sprintf("%d.%d", ti.FirmwareVersion.Major, ti.FirmwareVersion.Minor),
		}
		return nil
	})
	return info, err
}

func (m *pkcs11ModuleImpl) GenerateKeyPair(slotLabel string, pin []byte, keyLabel, keyAlgorithm string) ([]byte, error) {
	var spkiDer []byte
	err := m.withSession(slotLabel, pin, func(_ uint, session pkcs11.SessionHandle) error {
		mech, pubTpl, privTpl, err := generateKeyPairTemplates(keyLabel, keyAlgorithm)
		if err != nil {
			return err
		}
		pubHandle, _, err := m.ctx.GenerateKeyPair(session, mech, pubTpl, privTpl)
		if err != nil {
			return &Pkcs11Error{Code: Pkcs11ErrInternal, Message: "GenerateKeyPair failed"}
		}
		der, err := buildSpkiFromHandle(m.ctx, session, pubHandle, keyAlgorithm)
		if err != nil {
			return err
		}
		spkiDer = der
		return nil
	})
	return spkiDer, err
}

func generateKeyPairTemplates(keyLabel, keyAlgorithm string) ([]*pkcs11.Mechanism, []*pkcs11.Attribute, []*pkcs11.Attribute, error) {
	commonPriv := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(keyLabel)),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
	}
	commonPub := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(keyLabel)),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
	}
	switch keyAlgorithm {
	case KeyAlgorithmRSA2048, KeyAlgorithmRSA4096:
		modulusBits := 2048
		if keyAlgorithm == KeyAlgorithmRSA4096 {
			modulusBits = 4096
		}
		pubTpl := append(commonPub,
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, modulusBits),
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{0x01, 0x00, 0x01}),
		)
		return []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)}, pubTpl, commonPriv, nil
	case KeyAlgorithmECCP256:
		pubTpl := append(commonPub, pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParamsP256))
		return []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)}, pubTpl, commonPriv, nil
	case KeyAlgorithmECCP384:
		pubTpl := append(commonPub, pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParamsP384))
		return []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)}, pubTpl, commonPriv, nil
	default:
		return nil, nil, nil, &Pkcs11Error{Code: Pkcs11ErrMechanismInvalid, Message: fmt.Sprintf("Unsupported keyAlgorithm %q", keyAlgorithm)}
	}
}

func buildSpkiFromHandle(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, pubHandle pkcs11.ObjectHandle, keyAlgorithm string) ([]byte, error) {
	switch keyAlgorithm {
	case KeyAlgorithmRSA2048, KeyAlgorithmRSA4096:
		attrs, err := ctx.GetAttributeValue(session, pubHandle, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
		})
		if err != nil {
			return nil, &Pkcs11Error{Code: Pkcs11ErrInternal, Message: "RSA GetAttributeValue failed"}
		}
		var modulus, exp []byte
		for _, a := range attrs {
			switch a.Type {
			case pkcs11.CKA_MODULUS:
				modulus = a.Value
			case pkcs11.CKA_PUBLIC_EXPONENT:
				exp = a.Value
			}
		}
		pub := &rsa.PublicKey{
			N: new(big.Int).SetBytes(modulus),
			E: int(new(big.Int).SetBytes(exp).Int64()),
		}
		der, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return nil, &Pkcs11Error{Code: Pkcs11ErrInternal, Message: "MarshalPKIXPublicKey failed"}
		}
		return der, nil

	case KeyAlgorithmECCP256, KeyAlgorithmECCP384:
		attrs, err := ctx.GetAttributeValue(session, pubHandle, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
		})
		if err != nil {
			return nil, &Pkcs11Error{Code: Pkcs11ErrInternal, Message: "EC GetAttributeValue failed"}
		}
		if len(attrs) == 0 {
			return nil, &Pkcs11Error{Code: Pkcs11ErrInternal, Message: "CKA_EC_POINT missing from response"}
		}
		// CKA_EC_POINT is DER OCTET STRING wrapping the raw point.
		var raw []byte
		if _, err := asn1.Unmarshal(attrs[0].Value, &raw); err != nil {
			return nil, &Pkcs11Error{Code: Pkcs11ErrInternal, Message: "Unmarshal CKA_EC_POINT failed"}
		}
		var curve elliptic.Curve
		if keyAlgorithm == KeyAlgorithmECCP256 {
			curve = elliptic.P256()
		} else {
			curve = elliptic.P384()
		}
		// Parse the uncompressed point format (RFC 5480 Section 2.2): 0x04 || X || Y
		// with each coordinate padded to (BitSize + 7) / 8 bytes. Stdlib's
		// elliptic.Unmarshal is deprecated and there is no ECDSA-specific replacement,
		// so do the parse inline.
		byteLen := (curve.Params().BitSize + 7) / 8
		if len(raw) != 1+2*byteLen || raw[0] != 0x04 {
			return nil, &Pkcs11Error{Code: Pkcs11ErrInternal, Message: "Failed to unmarshal EC point"}
		}
		x := new(big.Int).SetBytes(raw[1 : 1+byteLen])
		y := new(big.Int).SetBytes(raw[1+byteLen:])
		pub := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
		der, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return nil, &Pkcs11Error{Code: Pkcs11ErrInternal, Message: "MarshalPKIXPublicKey failed"}
		}
		return der, nil
	}
	return nil, &Pkcs11Error{Code: Pkcs11ErrMechanismInvalid, Message: "Unsupported keyAlgorithm for SPKI build"}
}

func (m *pkcs11ModuleImpl) GetPublicKey(slotLabel string, pin []byte, keyLabel string) ([]byte, error) {
	var spkiDer []byte
	err := m.withSession(slotLabel, pin, func(_ uint, session pkcs11.SessionHandle) error {
		handle, found, err := findObject(m.ctx, session, keyLabel, pkcs11.CKO_PUBLIC_KEY)
		if err != nil {
			return err
		}
		if !found {
			return &Pkcs11Error{Code: Pkcs11ErrKeyNotFound, Message: fmt.Sprintf("Public key with label %q not found", keyLabel)}
		}
		alg, err := detectKeyAlgorithm(m.ctx, session, handle)
		if err != nil {
			return err
		}
		der, err := buildSpkiFromHandle(m.ctx, session, handle, alg)
		if err != nil {
			return err
		}
		spkiDer = der
		return nil
	})
	return spkiDer, err
}

func detectKeyAlgorithm(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, handle pkcs11.ObjectHandle) (string, error) {
	attrs, err := ctx.GetAttributeValue(session, handle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
	})
	if err != nil || len(attrs) == 0 {
		return "", &Pkcs11Error{Code: Pkcs11ErrInternal, Message: "Failed to read CKA_KEY_TYPE"}
	}
	raw := make([]byte, 8)
	copy(raw, attrs[0].Value)
	keyType := uint(binary.LittleEndian.Uint64(raw))
	switch keyType {
	case pkcs11.CKK_RSA:
		modAttrs, err := ctx.GetAttributeValue(session, handle, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil)})
		if err != nil || len(modAttrs) == 0 {
			return "", &Pkcs11Error{Code: Pkcs11ErrInternal, Message: "Failed to read CKA_MODULUS"}
		}
		switch len(modAttrs[0].Value) {
		case 256:
			return KeyAlgorithmRSA2048, nil
		case 512:
			return KeyAlgorithmRSA4096, nil
		}
		return "", &Pkcs11Error{Code: Pkcs11ErrMechanismInvalid, Message: fmt.Sprintf("Unsupported RSA modulus length: %d bits", len(modAttrs[0].Value)*8)}
	case pkcs11.CKK_EC:
		paramsAttrs, err := ctx.GetAttributeValue(session, handle, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil)})
		if err != nil || len(paramsAttrs) == 0 {
			return "", &Pkcs11Error{Code: Pkcs11ErrInternal, Message: "Failed to read CKA_EC_PARAMS"}
		}
		if bytes.Equal(paramsAttrs[0].Value, ecParamsP256) {
			return KeyAlgorithmECCP256, nil
		}
		if bytes.Equal(paramsAttrs[0].Value, ecParamsP384) {
			return KeyAlgorithmECCP384, nil
		}
		return "", &Pkcs11Error{Code: Pkcs11ErrMechanismInvalid, Message: "Unsupported EC curve"}
	}
	return "", &Pkcs11Error{Code: Pkcs11ErrMechanismInvalid, Message: fmt.Sprintf("Unsupported PKCS#11 key type: %d", keyType)}
}

func findObject(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, label string, class uint) (pkcs11.ObjectHandle, bool, error) {
	tpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(label)),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
	}
	if err := ctx.FindObjectsInit(session, tpl); err != nil {
		return 0, false, &Pkcs11Error{Code: Pkcs11ErrInternal, Message: "FindObjectsInit failed"}
	}
	defer func() {
		if finalErr := ctx.FindObjectsFinal(session); finalErr != nil {
			log.Warn().Err(finalErr).Msg("pkcs11: FindObjectsFinal failed")
		}
	}()
	objs, _, err := ctx.FindObjects(session, 2)
	if err != nil {
		return 0, false, &Pkcs11Error{Code: Pkcs11ErrInternal, Message: "FindObjects failed"}
	}
	if len(objs) == 0 {
		return 0, false, nil
	}
	if len(objs) > 1 {
		return 0, false, &Pkcs11Error{
			Code:    Pkcs11ErrBadRequest,
			Message: fmt.Sprintf("Multiple objects on the HSM share label %q. Resolve the duplicate before proceeding.", label),
		}
	}
	return objs[0], true, nil
}

func (m *pkcs11ModuleImpl) Sign(slotLabel string, pin []byte, keyLabel, mechanism string, data []byte, isDigest bool) ([]byte, error) {
	log.Debug().Str("keyLabel", keyLabel).Str("mech", mechanism).Int("dataLen", len(data)).Msg("pkcs11.Sign: enter")
	var sig []byte
	err := m.withSession(slotLabel, pin, func(_ uint, session pkcs11.SessionHandle) error {
		mechCode, params, err := resolveMechanism(mechanism, isDigest)
		if err != nil {
			return err
		}
		handle, found, err := findObject(m.ctx, session, keyLabel, pkcs11.CKO_PRIVATE_KEY)
		if err != nil {
			return err
		}
		if !found {
			return &Pkcs11Error{Code: Pkcs11ErrKeyNotFound, Message: fmt.Sprintf("Private key with label %q not found", keyLabel)}
		}
		if err := m.ctx.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(mechCode, params)}, handle); err != nil {
			return mapPkcs11SignError(err)
		}
		out, err := m.ctx.Sign(session, data)
		if err != nil {
			return mapPkcs11SignError(err)
		}
		sig = out
		return nil
	})
	log.Debug().Bool("ok", err == nil).Int("sigLen", len(sig)).Msg("pkcs11.Sign: done")
	return sig, err
}

func resolveMechanism(name string, isDigest bool) (uint, []byte, error) {
	switch name {
	case "CKM_RSA_PKCS":
		if !isDigest {
			return 0, nil, &Pkcs11Error{Code: Pkcs11ErrBadRequest, Message: "CKM_RSA_PKCS requires a pre-hashed DigestInfo input (isDigest=true)"}
		}
		return pkcs11.CKM_RSA_PKCS, nil, nil
	case "CKM_SHA256_RSA_PKCS":
		return pkcs11.CKM_SHA256_RSA_PKCS, nil, nil
	case "CKM_SHA384_RSA_PKCS":
		return pkcs11.CKM_SHA384_RSA_PKCS, nil, nil
	case "CKM_SHA512_RSA_PKCS":
		return pkcs11.CKM_SHA512_RSA_PKCS, nil, nil
	case "CKM_ECDSA_SHA256":
		if isDigest {
			return pkcs11.CKM_ECDSA, nil, nil
		}
		return pkcs11.CKM_ECDSA_SHA256, nil, nil
	case "CKM_ECDSA_SHA384":
		if isDigest {
			return pkcs11.CKM_ECDSA, nil, nil
		}
		return pkcs11.CKM_ECDSA_SHA384, nil, nil
	case "CKM_ECDSA":
		return pkcs11.CKM_ECDSA, nil, nil
	}
	return 0, nil, &Pkcs11Error{Code: Pkcs11ErrMechanismInvalid, Message: fmt.Sprintf("Unsupported mechanism %q", name)}
}

func mapPkcs11SignError(err error) error {
	if e, ok := err.(pkcs11.Error); ok {
		switch e {
		case pkcs11.CKR_KEY_HANDLE_INVALID, pkcs11.CKR_OBJECT_HANDLE_INVALID:
			return &Pkcs11Error{Code: Pkcs11ErrKeyNotFound, Message: "The HSM rejected the key handle"}
		case pkcs11.CKR_MECHANISM_INVALID, pkcs11.CKR_KEY_TYPE_INCONSISTENT:
			return &Pkcs11Error{Code: Pkcs11ErrMechanismInvalid, Message: "The HSM does not support the requested signing algorithm"}
		case pkcs11.CKR_TOKEN_NOT_PRESENT, pkcs11.CKR_DEVICE_REMOVED, pkcs11.CKR_DEVICE_ERROR:
			return &Pkcs11Error{Code: Pkcs11ErrDriverUnavailable, Message: "Driver unavailable"}
		}
	}
	return &Pkcs11Error{Code: Pkcs11ErrInternal, Message: "Sign operation failed"}
}
