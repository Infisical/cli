package oracle

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strconv"
)

type authKVPCodec struct {
	name string
	get  func(payload []byte, key string) (string, error)
	set  func(payload []byte, key, newValue string) ([]byte, error)
}

var (
	ociCodec  = authKVPCodec{name: "oci", get: ociGetValue, set: ociSetValue}
	thinCodec = authKVPCodec{name: "thin", get: thinGetValue, set: thinSetValue}
)

func codecFor(payload []byte) (authKVPCodec, error) {
	if ociHasKey(payload, "AUTH_SESSKEY") {
		return ociCodec, nil
	}
	if thinHasKey(payload, "AUTH_SESSKEY") {
		return thinCodec, nil
	}
	return authKVPCodec{}, fmt.Errorf("payload carries no readable AUTH_SESSKEY")
}

func (c authKVPCodec) valueOrEmpty(payload []byte, key string) string {
	value, err := c.get(payload, key)
	if err != nil {
		return ""
	}
	return value
}

const (
	defaultPbkdf2VGenCount = 4096
	defaultPbkdf2SDerCount = 3
	maxPbkdf2VGenCount     = 1_000_000
	maxPbkdf2SDerCount     = 1_000
)

func pbkdf2Count(raw string, fallback, limit int) (int, error) {
	if raw == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n == 0 {
		return fallback, nil
	}
	if n < 0 || n > limit {
		return 0, fmt.Errorf("target requested a PBKDF2 work factor of %d, outside the supported range 1 to %d", n, limit)
	}
	return n, nil
}

func translatePhase1ResponseInPlace(payload []byte, realPassword string) (*ProxyAuthState, []byte, error) {
	c, cerr := codecFor(payload)
	if cerr != nil {
		return nil, nil, cerr
	}
	eSessKey := c.valueOrEmpty(payload, "AUTH_SESSKEY")
	vfrData := c.valueOrEmpty(payload, "AUTH_VFR_DATA")
	if eSessKey == "" || vfrData == "" {
		return nil, nil, fmt.Errorf("upstream phase 1 missing AUTH_SESSKEY or AUTH_VFR_DATA")
	}

	salt, err := hex.DecodeString(vfrData)
	if err != nil {
		return nil, nil, fmt.Errorf("decode salt: %w", err)
	}
	vGen, err := pbkdf2Count(c.valueOrEmpty(payload, "AUTH_PBKDF2_VGEN_COUNT"), defaultPbkdf2VGenCount, maxPbkdf2VGenCount)
	if err != nil {
		return nil, nil, err
	}
	sDer, err := pbkdf2Count(c.valueOrEmpty(payload, "AUTH_PBKDF2_SDER_COUNT"), defaultPbkdf2SDerCount, maxPbkdf2SDerCount)
	if err != nil {
		return nil, nil, err
	}

	realKey, _, err := deriveServerKey(realPassword, salt, vGen)
	if err != nil {
		return nil, nil, fmt.Errorf("derive real key: %w", err)
	}
	placeholderKey, _, err := deriveServerKey(ProxyPasswordPlaceholder, salt, vGen)
	if err != nil {
		return nil, nil, fmt.Errorf("derive placeholder key: %w", err)
	}

	serverSessKey, err := decryptSessionKey(false, realKey, eSessKey)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt upstream server session key: %w", err)
	}
	newESessKey, err := encryptSessionKey(false, placeholderKey, serverSessKey)
	if err != nil {
		return nil, nil, fmt.Errorf("re-encrypt server session key: %w", err)
	}

	rebuilt, err := c.set(payload, "AUTH_SESSKEY", newESessKey)
	if err != nil {
		return nil, nil, fmt.Errorf("rewrite AUTH_SESSKEY: %w", err)
	}

	return &ProxyAuthState{
		Salt:            salt,
		Pbkdf2CSKSalt:   c.valueOrEmpty(payload, "AUTH_PBKDF2_CSK_SALT"),
		Pbkdf2VGenCount: vGen,
		Pbkdf2SDerCount: sDer,
		RealKey:         realKey,
		PlaceholderKey:  placeholderKey,
		ServerSessKey:   serverSessKey,
	}, rebuilt, nil
}

func translatePhase2RequestInPlace(payload []byte, state *ProxyAuthState, realPassword string) ([]byte, error) {
	c, cerr := codecFor(payload)
	if cerr != nil {
		return nil, cerr
	}
	eClientSessKey := c.valueOrEmpty(payload, "AUTH_SESSKEY")
	ePassword := c.valueOrEmpty(payload, "AUTH_PASSWORD")
	if eClientSessKey == "" || ePassword == "" {
		return nil, fmt.Errorf("client phase 2 missing AUTH_SESSKEY or AUTH_PASSWORD")
	}

	clientSessKey, err := decryptSessionKey(false, state.PlaceholderKey, eClientSessKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt client session key: %w", err)
	}
	if len(clientSessKey) != len(state.ServerSessKey) {
		return nil, fmt.Errorf("client session key length mismatch: got %d want %d", len(clientSessKey), len(state.ServerSessKey))
	}
	newEClientSessKey, err := encryptSessionKey(false, state.RealKey, clientSessKey)
	if err != nil {
		return nil, fmt.Errorf("re-encrypt client session key: %w", err)
	}

	encKey, err := deriveProxyPasswordEncKey(clientSessKey, state.ServerSessKey, state.Pbkdf2CSKSalt, state.Pbkdf2SDerCount)
	if err != nil {
		return nil, fmt.Errorf("derive enc key: %w", err)
	}
	decoded, err := decryptSessionKey(true, encKey, ePassword)
	if err != nil {
		return nil, fmt.Errorf("decrypt client password: %w", err)
	}
	if len(decoded) <= 16 || string(decoded[16:]) != ProxyPasswordPlaceholder {
		return nil, fmt.Errorf("password mismatch")
	}
	newEPassword, err := encryptPassword([]byte(realPassword), encKey, true)
	if err != nil {
		return nil, fmt.Errorf("encrypt real password: %w", err)
	}

	rebuilt, err := c.set(payload, "AUTH_SESSKEY", newEClientSessKey)
	if err != nil {
		return nil, fmt.Errorf("rewrite AUTH_SESSKEY: %w", err)
	}
	rebuilt, err = c.set(rebuilt, "AUTH_PASSWORD", newEPassword)
	if err != nil {
		return nil, fmt.Errorf("rewrite AUTH_PASSWORD: %w", err)
	}
	return rebuilt, nil
}

const authRequestProbeUser = "PROBE"

func indexOfAuthRequestMatching(payload []byte, expectedSubOp byte, accepts func([]byte) bool) int {
	firstKey := bytes.Index(payload, []byte("AUTH_"))
	if firstKey < 0 {
		return -1
	}
	first := -1
	for offset := 0; offset+1 < firstKey; offset++ {
		if payload[offset] != TTCMsgAuthRequest || payload[offset+1] != expectedSubOp {
			continue
		}
		if first < 0 {
			first = offset
		}
		if accepts != nil && accepts(payload[offset:]) {
			return offset
		}
	}
	return first
}

func indexOfAuthRequest(payload []byte, expectedSubOp byte) int {
	thin := func(b []byte) bool {
		_, err := rewriteAuthRequestUser(b, expectedSubOp, authRequestProbeUser)
		return err == nil
	}
	if offset := indexOfAuthRequestMatching(payload, expectedSubOp, thin); offset >= 0 && thin(payload[offset:]) {
		return offset
	}
	oci := func(b []byte) bool {
		_, err := ociRewriteAuthRequestUser(b, authRequestProbeUser)
		return err == nil
	}
	return indexOfAuthRequestMatching(payload, expectedSubOp, oci)
}

func ociContainsAuthRequest(payload []byte, expectedSubOp byte) bool {
	return indexOfAuthRequest(payload, expectedSubOp) >= 0
}

func rewriteBundledUsername(payload []byte, expectedSubOp byte, newUser string) ([]byte, bool) {
	offset := indexOfAuthRequest(payload, expectedSubOp)
	if offset < 0 {
		return payload, false
	}
	rewritten, err := rewriteAuthRequestUser(payload[offset:], expectedSubOp, newUser)
	if err != nil {
		rewritten, err = ociRewriteAuthRequestUser(payload[offset:], newUser)
	}
	if err != nil {
		return payload, false
	}
	return append(append([]byte{}, payload[:offset]...), rewritten...), true
}
