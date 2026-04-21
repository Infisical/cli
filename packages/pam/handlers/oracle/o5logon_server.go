package oracle

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
)

// Server-role O5Logon implementation. The gateway acts as an Oracle server and drives
// the two-phase O5Logon challenge/response with the client, verifying that the client
// sends the placeholder password. Real upstream auth is handled separately (see
// upstream.go) with the injected real credentials.
//
// NOTE: This is new code (not ported from go-ora). The formats match what go-ora's
// client-side code expects; see auth_object.go newAuthObject / AuthObject.Write.

// TTC function-call opcodes we touch during auth.
const (
	TTCMsgAuthRequest  = 0x03 // generic "pre-auth" message
	TTCMsgAuthResponse = 0x08 // server's response carrying KVP dict
	TTCMsgError        = 0x04 // server's error summary packet
	TTCMsgBreak        = 0x0B // reserved
)

// AuthSubOp values — bundled inside a TTCMsgAuthRequest.
const (
	AuthSubOpPhaseOne = 0x76
	AuthSubOpPhaseTwo = 0x73
)

// LogonMode flags (subset). Sent by the client inside phase-2 so we know what kind of
// auth is requested.
const (
	LogonModeUserAndPass = 0x100
	LogonModeNoNewPass   = 0x2000
)

// AuthPhaseOne carries the parsed client request that begins auth.
type AuthPhaseOne struct {
	Username      string
	LogonMode     uint32
	KeyValuePairs map[string]string
}

// AuthPhaseTwo carries the parsed client request that completes auth.
type AuthPhaseTwo struct {
	EClientSessKey string
	EPassword      string
	ESpeedyKey     string
	ClientInfo     map[string]string
	AlterSession   string
	LogonMode      uint32
}

// readDataPayload reads a single DATA packet from the client and returns its TTC payload
// (the bytes after the 2-byte dataFlag).
func readDataPayload(conn net.Conn, use32BitLen bool) ([]byte, error) {
	raw, err := ReadFullPacket(conn, use32BitLen)
	if err != nil {
		return nil, err
	}
	if PacketTypeOf(raw) == PacketTypeMarker {
		// Discard break/marker and try again
		return readDataPayload(conn, use32BitLen)
	}
	if PacketTypeOf(raw) != PacketTypeData {
		return nil, fmt.Errorf("expected DATA packet, got type=%d", raw[4])
	}
	pkt, err := ParseDataPacket(raw, use32BitLen)
	if err != nil {
		return nil, err
	}
	return pkt.Payload, nil
}

// writeDataPayload wraps a TTC payload in a single DATA packet and writes it.
func writeDataPayload(conn net.Conn, payload []byte, use32BitLen bool) error {
	d := &DataPacket{Payload: payload}
	_, err := conn.Write(d.Bytes(use32BitLen))
	return err
}

// ParseAuthPhaseOne decodes the first auth-request TTC payload from the client.
// Layout: opcode(0x03) subop(0x76) 0x00, then username length-prefix + username,
// then mode(uint32 compressed), marker byte, KVP count, then pairs.
// The structure mirrors AuthObject.Write (inverted as reader).
func ParseAuthPhaseOne(payload []byte) (*AuthPhaseOne, error) {
	r := NewTTCReader(payload)
	op, err := r.GetByte()
	if err != nil {
		return nil, fmt.Errorf("phase1 opcode: %w", err)
	}
	if op != TTCMsgAuthRequest {
		return nil, fmt.Errorf("phase1 unexpected opcode 0x%02X", op)
	}
	sub, err := r.GetByte()
	if err != nil {
		return nil, err
	}
	if sub != AuthSubOpPhaseOne {
		return nil, fmt.Errorf("phase1 unexpected sub-op 0x%02X", sub)
	}
	if _, err := r.GetByte(); err != nil {
		return nil, err
	}

	out := &AuthPhaseOne{KeyValuePairs: map[string]string{}}

	// username presence byte + length
	hasUser, err := r.GetByte()
	if err != nil {
		return nil, err
	}
	var userLen int
	if hasUser == 1 {
		userLen, err = r.GetInt(4, true, true)
		if err != nil {
			return nil, err
		}
	} else {
		// skip the second length byte (go-ora writes two zeros when no username)
		if _, err := r.GetByte(); err != nil {
			return nil, err
		}
	}

	mode, err := r.GetInt(4, true, true)
	if err != nil {
		return nil, err
	}
	out.LogonMode = uint32(mode)

	if _, err := r.GetByte(); err != nil {
		return nil, err
	}
	index, err := r.GetInt(4, true, true)
	if err != nil {
		return nil, err
	}

	// two marker bytes (1, 1)
	if _, err := r.GetByte(); err != nil {
		return nil, err
	}
	if _, err := r.GetByte(); err != nil {
		return nil, err
	}

	if hasUser == 1 && userLen > 0 {
		// Username encoding varies per client:
		//   - go-ora: CLR-prefixed — one byte length (== userLen) followed by userLen bytes.
		//   - JDBC thin (sqlcl / SQL Developer / DBeaver): raw userLen bytes, no prefix.
		// Disambiguate by peeking: if the next byte equals userLen AND is in the control
		// range (< 0x20), it's a length prefix. Otherwise treat as raw string data.
		peek, perr := r.PeekByte()
		if perr != nil {
			return nil, fmt.Errorf("peek username: %w", perr)
		}
		if int(peek) == userLen && peek < 0x20 {
			// Consume CLR length and use GetClr-style read.
			if _, err := r.GetByte(); err != nil {
				return nil, fmt.Errorf("consume username length prefix: %w", err)
			}
		}
		u, err := r.GetBytes(userLen)
		if err != nil {
			return nil, fmt.Errorf("read username bytes: %w", err)
		}
		out.Username = string(u)
	}

	for i := 0; i < index; i++ {
		k, v, _, err := r.GetKeyVal()
		if err != nil {
			return nil, fmt.Errorf("phase1 KVP #%d: %w", i, err)
		}
		out.KeyValuePairs[string(k)] = string(v)
	}
	return out, nil
}

// BuildAuthPhaseOneResponse builds the server's phase-1 response payload carrying the
// challenge material the client needs to continue. Layout (mirrors a real Oracle 19c
// listener byte-for-byte):
//
//	opcode(0x08)
//	dictLen(compressed) = 6
//	AUTH_SESSKEY           num=0   value = 64 hex chars (32 raw bytes, AES-CBC encrypted)
//	AUTH_VFR_DATA          num=18453 value = 32 hex chars (16 raw bytes salt)
//	AUTH_PBKDF2_CSK_SALT   num=0   value = 32 hex chars
//	AUTH_PBKDF2_VGEN_COUNT num=0   value = "4096"
//	AUTH_PBKDF2_SDER_COUNT num=0   value = "3"
//	AUTH_GLOBALLY_UNIQUE_DBID num=0 value = 32 hex chars (fake DBID is fine)
//	then summary:
//	opcode(0x04) + retCode + zeros (ends the response — without it JDBC thin ORA-17401)
func BuildAuthPhaseOneResponse(state *O5LogonServerState) []byte {
	b := NewTTCBuilder()
	b.PutBytes(TTCMsgAuthResponse)
	kvs := []struct {
		key   string
		value string
		flag  uint32
	}{
		{"AUTH_SESSKEY", state.EServerSessKey, 0},
		// AUTH_VFR_DATA: value = hex-encoded salt; flag = VerifierType.
		{"AUTH_VFR_DATA", fmt.Sprintf("%X", state.Salt), VerifierType12c},
		{"AUTH_PBKDF2_CSK_SALT", state.Pbkdf2CSKSalt, 0},
		{"AUTH_PBKDF2_VGEN_COUNT", strconv.Itoa(state.Pbkdf2VGenCount), 0},
		{"AUTH_PBKDF2_SDER_COUNT", strconv.Itoa(state.Pbkdf2SDerCount), 0},
		// AUTH_GLOBALLY_UNIQUE_DBID — a fixed 32-hex-char fake DBID. Real Oracle uses
		// the instance's actual DBID; JDBC thin just validates its presence and format.
		// Key ends with an embedded NULL to exactly match the 26-byte length RDS sends.
		{"AUTH_GLOBALLY_UNIQUE_DBID\x00", "11A7D223DECC14322F8777F2BACBEE84", 0},
	}
	b.PutUint(uint64(len(kvs)), 4, true, true)
	for _, kv := range kvs {
		b.PutKeyValString(kv.key, kv.value, kv.flag)
	}

	// Trailing summary packet (message code 0x04) — marks end of the auth response so
	// JDBC thin's reader loop terminates. Format observed from RDS (34 bytes total):
	//   04 01 01 02 1A 98 <28 zero bytes>
	// Two compressed ints: first = 1 (call status), second = 2-byte sequence number.
	b.PutBytes(TTCMsgError) // opcode 4
	b.PutInt(1, 4, true, true)       // 01 01
	b.PutInt(0x1A98, 4, true, true)  // 02 1A 98
	// padding — 28 zero bytes matches RDS's 34-byte summary trailer
	for i := 0; i < 28; i++ {
		b.PutBytes(0)
	}
	return b.Bytes()
}

// ParseAuthPhaseTwo decodes the second auth-request TTC payload from the client.
func ParseAuthPhaseTwo(payload []byte) (*AuthPhaseTwo, error) {
	r := NewTTCReader(payload)
	op, err := r.GetByte()
	if err != nil {
		return nil, err
	}
	if op != TTCMsgAuthRequest {
		return nil, fmt.Errorf("phase2 unexpected opcode 0x%02X", op)
	}
	sub, err := r.GetByte()
	if err != nil {
		return nil, err
	}
	if sub != AuthSubOpPhaseTwo {
		return nil, fmt.Errorf("phase2 unexpected sub-op 0x%02X", sub)
	}
	if _, err := r.GetByte(); err != nil {
		return nil, err
	}

	out := &AuthPhaseTwo{ClientInfo: map[string]string{}}

	hasUser, err := r.GetByte()
	if err != nil {
		return nil, err
	}
	var userLen int
	if hasUser == 1 {
		userLen, err = r.GetInt(4, true, true)
		if err != nil {
			return nil, err
		}
	} else {
		if _, err := r.GetByte(); err != nil {
			return nil, err
		}
	}

	mode, err := r.GetInt(4, true, true)
	if err != nil {
		return nil, err
	}
	out.LogonMode = uint32(mode)

	if _, err := r.GetByte(); err != nil {
		return nil, err
	}
	count, err := r.GetInt(4, true, true)
	if err != nil {
		return nil, err
	}
	if _, err := r.GetByte(); err != nil {
		return nil, err
	}
	if _, err := r.GetByte(); err != nil {
		return nil, err
	}
	if hasUser == 1 && userLen > 0 {
		// Same client-specific branch as ParseAuthPhaseOne: go-ora prefixes with a
		// CLR length byte; JDBC thin sends raw. Peek to disambiguate.
		peek, perr := r.PeekByte()
		if perr != nil {
			return nil, fmt.Errorf("peek phase2 username: %w", perr)
		}
		if int(peek) == userLen && peek < 0x20 {
			if _, err := r.GetByte(); err != nil {
				return nil, fmt.Errorf("consume phase2 username length prefix: %w", err)
			}
		}
		if _, err := r.GetBytes(userLen); err != nil {
			return nil, fmt.Errorf("read phase2 username bytes: %w", err)
		}
	}

	for i := 0; i < count; i++ {
		k, v, _, err := r.GetKeyVal()
		if err != nil {
			return nil, fmt.Errorf("phase2 KVP #%d: %w", i, err)
		}
		switch string(k) {
		case "AUTH_SESSKEY":
			out.EClientSessKey = string(v)
		case "AUTH_PASSWORD":
			out.EPassword = string(v)
		case "AUTH_PBKDF2_SPEEDY_KEY":
			out.ESpeedyKey = string(v)
		case "AUTH_ALTER_SESSION":
			out.AlterSession = string(v)
		default:
			out.ClientInfo[string(k)] = string(v)
		}
	}
	return out, nil
}

// BuildAuthPhaseTwoResponseFromUpstream produces the phase-2 response using the actual
// KVPs upstream Oracle returned to go-ora during our upstream auth. We substitute
// AUTH_SVR_RESPONSE with our placeholder-derived value (so the client can verify the
// server proves knowledge of its placeholder password) and keep everything else intact.
//
// If upstreamKVPs is empty (e.g. TLS path where we can't tap), we fall back to the
// synthesised minimal response via BuildAuthPhaseTwoResponse.
func BuildAuthPhaseTwoResponseFromUpstream(svrResponse string, upstreamKVPs map[string]string) []byte {
	if len(upstreamKVPs) == 0 {
		return BuildAuthPhaseTwoResponse(svrResponse, 0xC0DE, 0x42)
	}

	b := NewTTCBuilder()
	b.PutBytes(TTCMsgAuthResponse)

	// Build KVP list preserving a canonical insertion order. We mirror the order Oracle
	// 19c uses: version info first, then DB identity, then session identity, then server
	// host scoping, then NLS params, then AUTH_SVR_RESPONSE, then misc limits. Clients
	// don't appear to require a specific order but matching reality is safest.
	order := []string{
		"AUTH_VERSION_STRING",
		"AUTH_VERSION_SQL",
		"AUTH_XACTION_TRAITS",
		"AUTH_VERSION_NO",
		"AUTH_VERSION_STATUS",
		"AUTH_CAPABILITY_TABLE",
		"AUTH_LAST_LOGIN",
		"AUTH_DBNAME",
		"AUTH_DB_MOUNT_ID",
		"AUTH_DB_ID",
		"AUTH_USER_ID",
		"AUTH_SESSION_ID",
		"AUTH_SERIAL_NUM",
		"AUTH_INSTANCE_NO",
		"AUTH_FAILOVER_ID",
		"AUTH_SERVER_PID",
		"AUTH_SC_SERVER_HOST",
		"AUTH_SC_DBUNIQUE_NAME",
		"AUTH_SC_INSTANCE_NAME",
		"AUTH_SC_INSTANCE_ID",
		"AUTH_SC_INSTANCE_START_TIME",
		"AUTH_SC_DB_DOMAIN",
		"AUTH_SC_SERVICE_NAME",
		"AUTH_ONS_RLB_SUBSCR_PATTERN",
		"AUTH_ONS_HA_SUBSCR_PATTERN",
		"AUTH_INSTANCENAME",
		"AUTH_NLS_LXLAN",
		"AUTH_NLS_LXCTERRITORY",
		"AUTH_NLS_LXCCURRENCY",
		"AUTH_NLS_LXCISOCURR",
		"AUTH_NLS_LXCNUMERICS",
		"AUTH_NLS_LXCDATEFM",
		"AUTH_NLS_LXCDATELANG",
		"AUTH_NLS_LXCSORT",
		"AUTH_NLS_LXCCALENDAR",
		"AUTH_NLS_LXCUNIONCUR",
		"AUTH_NLS_LXCTIMEFM",
		"AUTH_NLS_LXCSTMPFM",
		"AUTH_NLS_LXCTTZNFM",
		"AUTH_NLS_LXCSTZNFM",
		"AUTH_NLS_LXLENSEMANTICS",
		"AUTH_NLS_LXNCHARCONVEXCP",
		"AUTH_NLS_LXCOMP",
		"AUTH_SVR_RESPONSE", // substituted below
		"AUTH_TSTZ_ERROR_CHECK",
		"AUTH_MAX_OPEN_CURSORS",
		"AUTH_MAX_IDEN_LENGTH",
	}

	// Build the final KVP list — only include keys that appear either in the order
	// list (from upstream) or are AUTH_SVR_RESPONSE (always included).
	type kvEntry struct {
		key   string
		value string
	}
	var kvs []kvEntry
	seen := map[string]bool{}
	for _, k := range order {
		if k == "AUTH_SVR_RESPONSE" {
			kvs = append(kvs, kvEntry{k, svrResponse})
			seen[k] = true
			continue
		}
		if v, ok := upstreamKVPs[k]; ok {
			kvs = append(kvs, kvEntry{k, v})
			seen[k] = true
		}
	}
	// Append any upstream keys we didn't explicitly order (e.g. keys Oracle added in a
	// newer version that aren't in our list). This keeps us forward-compatible.
	for k, v := range upstreamKVPs {
		if !seen[k] && k != "AUTH_SVR_RESPONSE" {
			kvs = append(kvs, kvEntry{k, v})
		}
	}

	b.PutUint(uint64(len(kvs)), 4, true, true)
	for _, kv := range kvs {
		b.PutKeyValString(kv.key, kv.value, 0)
	}

	// Trailing summary packet — same shape as the non-upstream variant.
	b.PutBytes(TTCMsgError)
	b.PutInt(1, 4, true, true)
	b.PutInt(0x1A98, 4, true, true)
	for i := 0; i < 28; i++ {
		b.PutBytes(0)
	}
	return b.Bytes()
}

// BuildAuthPhaseTwoResponse produces the final server response that tells the client
// auth succeeded. It includes session IDs, NLS params and AUTH_SVR_RESPONSE.
func BuildAuthPhaseTwoResponse(svrResponse string, sessionID, serialNum uint32) []byte {
	b := NewTTCBuilder()
	b.PutBytes(TTCMsgAuthResponse)
	kvs := []struct {
		key   string
		value string
		flag  uint32
	}{
		{"AUTH_VERSION_NO", "352321536", 0},
		{"AUTH_SESSION_ID", strconv.FormatUint(uint64(sessionID), 10), 0},
		{"AUTH_SERIAL_NUM", strconv.FormatUint(uint64(serialNum), 10), 0},
		{"AUTH_SVR_RESPONSE", svrResponse, 0},
		{"AUTH_VERSION_STRING", "Oracle Database 19c Enterprise Edition Release 19.0.0.0.0 - Production", 0},
		{"AUTH_VERSION_SQL", "1", 0},
		{"AUTH_XACTION_TRAITS", "3", 0},
		{"AUTH_INSTANCENAME", "orcl", 0},
		{"AUTH_FLAGS", "16777344", 0},
		// NLS params
		{"AUTH_SC_DBUNIQUE_NAME", "orcl", 0},
		{"AUTH_SC_SERVICE_NAME", "orcl", 0},
		{"AUTH_SC_INSTANCE_NAME", "orcl", 0},
		{"AUTH_SC_DB_DOMAIN", "", 0},
		{"AUTH_SC_INSTANCE_START_TIME", "", 0},
	}
	b.PutUint(uint64(len(kvs)), 4, true, true)
	for _, kv := range kvs {
		b.PutKeyValString(kv.key, kv.value, kv.flag)
	}
	// Trailing summary packet (opcode 0x04) — terminates the auth response so the
	// client's TTC reader loop exits. Same shape as the phase-1 trailer.
	// Format (34 bytes total): 04 01 01 02 <2-byte seq> <28 zero bytes>
	b.PutBytes(TTCMsgError)
	b.PutInt(1, 4, true, true)       // 01 01
	b.PutInt(0x1A98, 4, true, true)  // 02 1A 98
	for i := 0; i < 28; i++ {
		b.PutBytes(0)
	}
	return b.Bytes()
}

// BuildErrorPacket constructs an Oracle error summary packet (opcode 0x04). The Oracle
// client checks `Session.HasError()` after each response, which reads this summary.
// Minimal fields: opcode, retCode (the ORA error number), retCol, errorPos, SQL state,
// flags, rpc message (empty), and finally the error message.
func BuildErrorPacket(oraCode int, message string) []byte {
	b := NewTTCBuilder()
	b.PutBytes(TTCMsgError)

	// length: sum of number-compressed fields. go-ora summary_object.go shows:
	//   endOfCallStatus (4 bytes compressed)
	//   endToEndECIDSequence (2 bytes)
	//   currentRowNumber (4)
	//   returnCode (4)  ← our oraCode goes here
	//   arrayElemErrorsCount (2)
	//   arrayElemError count again
	//   current cursor id (2)
	//   error position (2)
	//   sql type (1)
	//   oer_fatal (1)
	//   flags (1)
	//   user cursor opts (1)
	//   uol (1)
	//   sid (4)
	//   serial num (4)
	//   rba ts (2)
	//   rba sqn (4)
	//   rba blk (4)
	//   rba byte (4)
	//   some flags, then CLR of the message
	// Most fields can be zero; the code is what matters.
	b.PutInt(0, 4, true, true)  // endOfCallStatus
	b.PutInt(0, 2, true, true)  // endToEndECID
	b.PutInt(0, 4, true, true)  // currentRow
	b.PutInt(int64(oraCode), 4, true, true)
	b.PutInt(0, 2, true, true)
	b.PutInt(0, 2, true, true)
	b.PutInt(0, 2, true, true)
	b.PutInt(0, 2, true, true)
	b.PutInt(0, 1, true, true)
	b.PutInt(0, 1, true, true)
	b.PutInt(0, 1, true, true)
	b.PutInt(0, 1, true, true)
	b.PutInt(0, 1, true, true)
	b.PutInt(0, 4, true, true)
	b.PutInt(0, 4, true, true)
	b.PutInt(0, 2, true, true)
	b.PutInt(0, 4, true, true)
	b.PutInt(0, 4, true, true)
	b.PutInt(0, 4, true, true)
	b.PutInt(0, 2, true, true) // flags
	b.PutInt(0, 2, true, true)
	b.PutString(message)
	// trailing warning count
	b.PutInt(0, 2, true, true)
	return b.Bytes()
}

// WriteErrorToClient writes an Oracle-format error summary packet to the client.
func WriteErrorToClient(conn net.Conn, oraCode int, message string, use32BitLen bool) error {
	return writeDataPayload(conn, BuildErrorPacket(oraCode, message), use32BitLen)
}

// RunServerO5Logon drives the two-phase O5Logon handshake with the client. On success
// returns nil; on failure it has already written an ORA-error packet to the client.
func RunServerO5Logon(conn net.Conn, use32BitLen bool) error {
	// Phase 1: read client's initial auth request.
	p1Payload, err := readDataPayload(conn, use32BitLen)
	if err != nil {
		return fmt.Errorf("read phase1 DATA: %w", err)
	}
	if _, err := ParseAuthPhaseOne(p1Payload); err != nil {
		_ = WriteErrorToClient(conn, ORA1017InvalidCredentials, "ORA-01017: invalid username/password; logon denied", use32BitLen)
		return fmt.Errorf("parse phase1: %w", err)
	}

	state, err := NewO5LogonServerState()
	if err != nil {
		return fmt.Errorf("init O5Logon state: %w", err)
	}

	// Phase 1 response: send challenge material.
	if err := writeDataPayload(conn, BuildAuthPhaseOneResponse(state), use32BitLen); err != nil {
		return fmt.Errorf("write phase1 response: %w", err)
	}

	// Phase 2: read client's password response.
	p2Payload, err := readDataPayload(conn, use32BitLen)
	if err != nil {
		return fmt.Errorf("read phase2 DATA: %w", err)
	}
	p2, err := ParseAuthPhaseTwo(p2Payload)
	if err != nil {
		_ = WriteErrorToClient(conn, ORA1017InvalidCredentials, "ORA-01017: invalid username/password; logon denied", use32BitLen)
		return fmt.Errorf("parse phase2: %w", err)
	}

	_, encKey, err := state.VerifyClientPassword(p2.EClientSessKey, p2.EPassword)
	if err != nil {
		_ = WriteErrorToClient(conn, ORA1017InvalidCredentials, "ORA-01017: invalid username/password; logon denied", use32BitLen)
		return fmt.Errorf("verify password: %w", err)
	}

	svrResponse, err := BuildSvrResponse(encKey)
	if err != nil {
		return fmt.Errorf("build svr response: %w", err)
	}

	// Phase 2 response: auth OK
	if err := writeDataPayload(conn, BuildAuthPhaseTwoResponse(svrResponse, 0xC0DE, 0x42), use32BitLen); err != nil {
		return fmt.Errorf("write phase2 response: %w", err)
	}
	return nil
}

// dumpBytes is a tiny hex helper used in log messages when something goes sideways.
// nolint: unused
func dumpBytes(b []byte, max int) string {
	if len(b) > max {
		b = b[:max]
	}
	var buf bytes.Buffer
	for i, v := range b {
		if i > 0 {
			buf.WriteByte(' ')
		}
		fmt.Fprintf(&buf, "%02X", v)
	}
	return buf.String()
}

// readUint32 is a tiny helper used in tests. Kept here to avoid a separate utility file.
// nolint: unused
func readUint32(r io.Reader) (uint32, error) {
	var v [4]byte
	if _, err := io.ReadFull(r, v[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(v[:]), nil
}
