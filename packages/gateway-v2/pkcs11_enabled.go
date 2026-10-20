//go:build pkcs11

package gatewayv2

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"sync"

	"github.com/miekg/pkcs11"
	"github.com/rs/zerolog/log"
)

var (
	ecParamsP256 = []byte{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}
	ecParamsP384 = []byte{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22}
)

const (
	generatedKeyIDBytes = 16
	maxFoundKeys        = 50
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

func (m *pkcs11ModuleImpl) GenerateKeyPair(slotLabel string, pin []byte, keyLabel, keyAlgorithm string) (GeneratedKey, error) {
	var generated GeneratedKey
	keyID := make([]byte, generatedKeyIDBytes)
	if _, err := rand.Read(keyID); err != nil {
		return generated, &Pkcs11Error{Code: Pkcs11ErrInternal, Message: "Failed to generate key ID"}
	}
	err := m.withSession(slotLabel, pin, func(_ uint, session pkcs11.SessionHandle) error {
		mech, pubTpl, privTpl, err := generateKeyPairTemplates(keyLabel, keyID, keyAlgorithm)
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
		generated = GeneratedKey{PublicKey: der, KeyID: keyID}
		return nil
	})
	return generated, err
}

func generateKeyPairTemplates(keyLabel string, keyID []byte, keyAlgorithm string) ([]*pkcs11.Mechanism, []*pkcs11.Attribute, []*pkcs11.Attribute, error) {
	commonPriv := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(keyLabel)),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
	}
	commonPub := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(keyLabel)),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
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
	case KeyAlgorithmRSA2048, KeyAlgorithmRSA3072, KeyAlgorithmRSA4096:
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

func (m *pkcs11ModuleImpl) GetPublicKey(slotLabel string, pin []byte, key KeyRef) ([]byte, error) {
	var spkiDer []byte
	err := m.withSession(slotLabel, pin, func(_ uint, session pkcs11.SessionHandle) error {
		handle, found, err := findObject(m.ctx, session, key, pkcs11.CKO_PUBLIC_KEY)
		if err != nil {
			return err
		}
		if !found {
			return &Pkcs11Error{Code: Pkcs11ErrKeyNotFound, Message: fmt.Sprintf("Public key with label %q and ID %x not found", key.Label, key.ID)}
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
		return "", keyAttributeReadError(err)
	}
	keyType := decodeUlong(attrs[0].Value)
	switch keyType {
	case pkcs11.CKK_RSA:
		modAttrs, err := ctx.GetAttributeValue(session, handle, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil)})
		if err != nil || len(modAttrs) == 0 {
			return "", keyAttributeReadError(err)
		}
		modulusLen := len(bytes.TrimLeft(modAttrs[0].Value, "\x00"))
		switch modulusLen {
		case 256:
			return KeyAlgorithmRSA2048, nil
		case 384:
			return KeyAlgorithmRSA3072, nil
		case 512:
			return KeyAlgorithmRSA4096, nil
		}
		return "", &Pkcs11Error{Code: Pkcs11ErrMechanismInvalid, Message: fmt.Sprintf("Unsupported RSA modulus length: %d bits", modulusLen*8)}
	case pkcs11.CKK_EC:
		paramsAttrs, err := ctx.GetAttributeValue(session, handle, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil)})
		if err != nil || len(paramsAttrs) == 0 {
			return "", keyAttributeReadError(err)
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

var errKeyAttributeUnreadable = &Pkcs11Error{Code: Pkcs11ErrInternal, Message: "The HSM does not reveal this key attribute"}

func keyAttributeReadError(err error) error {
	e, ok := err.(pkcs11.Error)
	if err == nil || (ok && (e == pkcs11.CKR_ATTRIBUTE_TYPE_INVALID || e == pkcs11.CKR_ATTRIBUTE_SENSITIVE)) {
		return errKeyAttributeUnreadable
	}
	if ok && (e == pkcs11.CKR_TOKEN_NOT_PRESENT || e == pkcs11.CKR_DEVICE_REMOVED || e == pkcs11.CKR_DEVICE_ERROR) {
		return &Pkcs11Error{Code: Pkcs11ErrDriverUnavailable, Message: "Driver unavailable"}
	}
	return &Pkcs11Error{Code: Pkcs11ErrInternal, Message: fmt.Sprintf("Failed to read key attributes: %v", err)}
}

func isTolerableKeyLookupError(err error) bool {
	var p11Err *Pkcs11Error
	return err == errKeyAttributeUnreadable || (errors.As(err, &p11Err) && p11Err.Code == Pkcs11ErrMechanismInvalid)
}

func findObject(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, key KeyRef, class uint) (pkcs11.ObjectHandle, bool, error) {
	tpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(key.Label)),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
	}
	if len(key.ID) > 0 {
		tpl = append(tpl, pkcs11.NewAttribute(pkcs11.CKA_ID, key.ID))
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
			Code:    Pkcs11ErrKeyAmbiguous,
			Message: fmt.Sprintf("Multiple objects on the HSM match label %q and ID %x", key.Label, key.ID),
		}
	}
	return objs[0], true, nil
}

func (m *pkcs11ModuleImpl) Sign(slotLabel string, pin []byte, key KeyRef, mechanism string, data []byte, isDigest bool, expectedPublicKey crypto.PublicKey) (SignResult, error) {
	log.Debug().Str("keyLabel", key.Label).Str("mech", mechanism).Int("dataLen", len(data)).Msg("pkcs11.Sign: enter")
	var result SignResult
	err := m.withSession(slotLabel, pin, func(_ uint, session pkcs11.SessionHandle) error {
		mechCode, params, err := resolveMechanism(mechanism, isDigest)
		if err != nil {
			return err
		}
		if mechanism == "CKM_RSA_PKCS" {
			if err := validateRsaPkcs1DigestInfo(data); err != nil {
				return err
			}
		}
		handle, found, err := findObject(m.ctx, session, key, pkcs11.CKO_PRIVATE_KEY)
		if err != nil {
			return err
		}
		if !found {
			return &Pkcs11Error{Code: Pkcs11ErrKeyNotFound, Message: fmt.Sprintf("Private key with label %q and ID %x not found", key.Label, key.ID)}
		}
		attrs, err := m.ctx.GetAttributeValue(session, handle, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
			pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
		})
		attrsReadable := err == nil && len(attrs) == 2
		switch {
		case attrsReadable:
			if err := assertKeyTypeMatchesMechanism(attrs[0].Value, mechanism); err != nil {
				return err
			}
		case expectedPublicKey == nil:
			log.Warn().Err(err).Str("keyLabel", key.Label).Msg("pkcs11: key type and ID unreadable and no expected public key sent, signing without verification")
		default:
			log.Warn().Err(err).Str("keyLabel", key.Label).Msg("pkcs11: key type and ID unreadable, verifying the signature against the expected public key")
		}
		if err := m.ctx.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(mechCode, params)}, handle); err != nil {
			return mapPkcs11SignError(err)
		}
		out, err := m.ctx.Sign(session, data)
		if err != nil {
			return mapPkcs11SignError(err)
		}
		var readKeyID []byte
		if attrsReadable {
			readKeyID = attrs[1].Value
		}
		signed, err := completeSign(out, attrsReadable, readKeyID, key, expectedPublicKey, mechanism, isDigest, data)
		if err != nil {
			return err
		}
		result = signed
		return nil
	})
	log.Debug().Bool("ok", err == nil).Int("sigLen", len(result.Signature)).Msg("pkcs11.Sign: done")
	return result, err
}

func (m *pkcs11ModuleImpl) FindPrivateKeys(slotLabel string, pin []byte, keyLabel string) ([]KeyInfo, error) {
	var keys []KeyInfo
	err := m.withSession(slotLabel, pin, func(_ uint, session pkcs11.SessionHandle) error {
		handles, err := findAllObjects(m.ctx, session, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(keyLabel)),
		}, maxFoundKeys+1)
		if err != nil {
			return err
		}
		if len(handles) > maxFoundKeys {
			return &Pkcs11Error{Code: Pkcs11ErrBadRequest, Message: fmt.Sprintf("More than %d private keys in the slot have this label", maxFoundKeys)}
		}
		for _, handle := range handles {
			var keyID string
			attrs, err := m.ctx.GetAttributeValue(session, handle, []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
			})
			switch {
			case err == nil && len(attrs) == 1 && len(attrs[0].Value) <= maxKeyIDBytes:
				keyID = hex.EncodeToString(attrs[0].Value)
			case err == nil && len(attrs) == 1:
				log.Warn().Str("keyLabel", keyLabel).Int("keyIdBytes", len(attrs[0].Value)).Msg("pkcs11: CKA_ID of a matching private key is longer than a request can carry, reporting it without an ID")
			default:
				if readErr := keyAttributeReadError(err); readErr != errKeyAttributeUnreadable {
					return readErr
				}
				log.Warn().Err(err).Str("keyLabel", keyLabel).Msg("pkcs11: CKA_ID of a matching private key cannot be read")
			}
			keyAlgorithm, err := detectKeyAlgorithm(m.ctx, session, handle)
			if err != nil {
				if !isTolerableKeyLookupError(err) {
					return err
				}
				log.Warn().Err(err).Str("keyLabel", keyLabel).Msg("pkcs11: algorithm of a matching private key cannot be read")
			}
			keys = append(keys, KeyInfo{Label: keyLabel, KeyID: keyID, KeyAlgorithm: keyAlgorithm})
		}
		return nil
	})
	sort.Slice(keys, func(i, j int) bool { return keys[i].KeyID < keys[j].KeyID })
	return keys, err
}

func findAllObjects(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, template []*pkcs11.Attribute, limit int) ([]pkcs11.ObjectHandle, error) {
	if err := ctx.FindObjectsInit(session, template); err != nil {
		return nil, &Pkcs11Error{Code: Pkcs11ErrInternal, Message: "FindObjectsInit failed"}
	}
	defer func() {
		if finalErr := ctx.FindObjectsFinal(session); finalErr != nil {
			log.Warn().Err(finalErr).Msg("pkcs11: FindObjectsFinal failed")
		}
	}()
	var handles []pkcs11.ObjectHandle
	for len(handles) < limit {
		batch, _, err := ctx.FindObjects(session, limit-len(handles))
		if err != nil {
			return nil, &Pkcs11Error{Code: Pkcs11ErrInternal, Message: "FindObjects failed"}
		}
		if len(batch) == 0 {
			break
		}
		handles = append(handles, batch...)
	}
	return handles, nil
}

func decodeUlong(value []byte) uint {
	raw := make([]byte, 8)
	copy(raw, value)
	return uint(binary.LittleEndian.Uint64(raw))
}

func assertKeyTypeMatchesMechanism(keyType []byte, mechanism string) error {
	var expected uint
	switch {
	case strings.Contains(mechanism, "RSA"):
		expected = pkcs11.CKK_RSA
	case strings.Contains(mechanism, "ECDSA"):
		expected = pkcs11.CKK_EC
	default:
		return nil
	}
	if decodeUlong(keyType) != expected {
		return &Pkcs11Error{Code: Pkcs11ErrKeyTypeMismatch, Message: fmt.Sprintf("Key type does not match mechanism %s", mechanism)}
	}
	return nil
}

var rsaPkcs1DigestInfos = []struct {
	prefix    []byte
	digestLen int
}{
	{[]byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}, 32},
	{[]byte{0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30}, 48},
	{[]byte{0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40}, 64},
}

func validateRsaPkcs1DigestInfo(data []byte) error {
	for _, di := range rsaPkcs1DigestInfos {
		if len(data) == len(di.prefix)+di.digestLen && bytes.Equal(data[:len(di.prefix)], di.prefix) {
			return nil
		}
	}
	return &Pkcs11Error{Code: Pkcs11ErrBadRequest, Message: "CKM_RSA_PKCS input must be a SHA-256, SHA-384, or SHA-512 DigestInfo"}
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
