package mssql

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	TDSHeaderSize   = 8
	Login7FixedSize = 94

	// Packet types - supported (can be session recorded)
	PacketTypeSQLBatch      = 0x01
	PacketTypeTabularResult = 0x04
	PacketTypeLogin7        = 0x10
	PacketTypeSSPI          = 0x11
	PacketTypePrelogin      = 0x12

	// Packet types - unsupported (cannot reliably record)
	PacketTypeRPCRequest  = 0x03 // Stored procedures - complex binary format
	PacketTypeAttention   = 0x06 // Cancel signal
	PacketTypeBulkLoad    = 0x07 // Bulk insert
	PacketTypeTransMgrReq = 0x0E // Distributed transactions

	// Status flags
	StatusEOM = 0x01

	// Encryption options
	EncryptOff    = 0x00
	EncryptOn     = 0x01
	EncryptNotSup = 0x02
	EncryptReq    = 0x03

	// Token types
	TokenLoginAck   = 0xAD
	TokenError      = 0xAA
	TokenInfo       = 0xAB
	TokenDone       = 0xFD
	TokenDoneProc   = 0xFE
	TokenDoneInProc = 0xFF

	// PRELOGIN options
	PreloginEncryption = 0x01
	PreloginFedAuthReq = 0x06
	PreloginTerminator = 0xFF

	// Safety limits
	MaxPacketSize = 32767 + TDSHeaderSize
	MaxPackets    = 100
)

// TDSPacket represents a TDS packet
type TDSPacket struct {
	Type     uint8
	Status   uint8
	Length   uint16
	SPID     uint16
	PacketID uint8
	Window   uint8
	Payload  []byte
}

// ReadPacket reads a TDS packet from a reader
func ReadPacket(r io.Reader) (*TDSPacket, error) {
	header := make([]byte, TDSHeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	p := &TDSPacket{
		Type:     header[0],
		Status:   header[1],
		Length:   binary.BigEndian.Uint16(header[2:4]),
		SPID:     binary.BigEndian.Uint16(header[4:6]),
		PacketID: header[6],
		Window:   header[7],
	}

	// Validate packet length
	if p.Length < TDSHeaderSize {
		return nil, fmt.Errorf("invalid packet length: %d (less than header size)", p.Length)
	}
	if p.Length > MaxPacketSize {
		return nil, fmt.Errorf("packet too large: %d bytes (max %d)", p.Length, MaxPacketSize)
	}

	if p.Length > TDSHeaderSize {
		p.Payload = make([]byte, p.Length-TDSHeaderSize)
		if _, err := io.ReadFull(r, p.Payload); err != nil {
			return nil, err
		}
	}

	return p, nil
}

// Write writes the packet to a writer
func (p *TDSPacket) Write(w io.Writer) error {
	p.Length = uint16(TDSHeaderSize + len(p.Payload))

	// Write header + payload as a single write.
	// This is important for TLS connections where each Write call
	// produces a separate TLS record.
	buf := make([]byte, p.Length)
	buf[0] = p.Type
	buf[1] = p.Status
	binary.BigEndian.PutUint16(buf[2:4], p.Length)
	binary.BigEndian.PutUint16(buf[4:6], p.SPID)
	buf[6] = p.PacketID
	buf[7] = p.Window
	copy(buf[TDSHeaderSize:], p.Payload)

	_, err := w.Write(buf)
	return err
}

// IsEOM returns true if this is the last packet of a message
func (p *TDSPacket) IsEOM() bool {
	return p.Status&StatusEOM != 0
}

// ReadAllPackets reads all packets until EOM (with safety limit)
func ReadAllPackets(r io.Reader) ([]*TDSPacket, error) {
	var packets []*TDSPacket
	for i := 0; i < MaxPackets; i++ {
		p, err := ReadPacket(r)
		if err != nil {
			return nil, err
		}
		packets = append(packets, p)
		if p.IsEOM() {
			return packets, nil
		}
	}
	return nil, fmt.Errorf("message exceeded %d packets without EOM", MaxPackets)
}

// CombinePayloads combines payloads from multiple packets
func CombinePayloads(packets []*TDSPacket) []byte {
	var buf bytes.Buffer
	for _, p := range packets {
		buf.Write(p.Payload)
	}
	return buf.Bytes()
}

// GetPreloginEncryption extracts encryption option from PRELOGIN payload
func GetPreloginEncryption(payload []byte) uint8 {
	// PRELOGIN option format: token(1) + offset(2) + length(2) = 5 bytes per option
	for i := 0; i+5 <= len(payload); i += 5 {
		token := payload[i]
		if token == PreloginTerminator {
			break
		}
		if token == PreloginEncryption {
			offset := int(binary.BigEndian.Uint16(payload[i+1 : i+3]))
			if offset >= 0 && offset < len(payload) {
				return payload[offset]
			}
		}
	}
	return EncryptOff
}

// BuildPreloginRequest builds a PRELOGIN packet payload for client mode
func BuildPreloginRequest(encryption uint8) []byte {
	// PRELOGIN format:
	// Options: token(1) + offset(2) + length(2) per option, terminated by 0xFF
	// Data: option values at specified offsets
	//
	// We include: VERSION (0x00), ENCRYPTION (0x01), TERMINATOR (0xFF)

	// Header: 2 options + terminator = 5 + 5 + 1 = 11 bytes
	// Data: VERSION (6 bytes) + ENCRYPTION (1 byte) = 7 bytes
	// Total: 18 bytes

	const headerSize = 11
	const dataStart = headerSize

	buf := make([]byte, 18)

	// Option 0: VERSION at offset 11, length 6
	buf[0] = 0x00                                   // VERSION token
	binary.BigEndian.PutUint16(buf[1:3], dataStart) // offset
	binary.BigEndian.PutUint16(buf[3:5], 6)         // length

	// Option 1: ENCRYPTION at offset 17, length 1
	buf[5] = PreloginEncryption                       // ENCRYPTION token
	binary.BigEndian.PutUint16(buf[6:8], dataStart+6) // offset
	binary.BigEndian.PutUint16(buf[8:10], 1)          // length

	// Terminator
	buf[10] = PreloginTerminator

	// Data: VERSION = 0x0F 0x00 0x07 0xD0 0x00 0x00 (SQL Server 2019-ish)
	buf[11] = 0x0F
	buf[12] = 0x00
	buf[13] = 0x07
	buf[14] = 0xD0
	buf[15] = 0x00
	buf[16] = 0x00

	// Data: ENCRYPTION
	buf[17] = encryption

	return buf
}

// BuildPreloginResponse builds a PRELOGIN response payload for server mode
func BuildPreloginResponse(encryption uint8) []byte {
	// Same format as request
	return BuildPreloginRequest(encryption)
}

// CheckPreloginSupported returns an error if PRELOGIN contains unsupported options
func CheckPreloginSupported(payload []byte) error {
	// PRELOGIN option format: token(1) + offset(2) + length(2) = 5 bytes per option
	for i := 0; i+5 <= len(payload); i += 5 {
		token := payload[i]
		if token == PreloginTerminator {
			break
		}
		if token == PreloginFedAuthReq {
			offset := int(binary.BigEndian.Uint16(payload[i+1 : i+3]))
			length := int(binary.BigEndian.Uint16(payload[i+3 : i+5]))
			if length > 0 && offset >= 0 && offset < len(payload) && payload[offset] != 0 {
				return fmt.Errorf("federated authentication (Azure AD) is not supported")
			}
		}
	}
	return nil
}

// CheckLogin7Supported returns an error if LOGIN7 uses unsupported auth methods
func CheckLogin7Supported(msg *Login7Message) error {
	// Check for SSPI/Windows auth
	if msg.Header.SSPILength > 0 || msg.Header.SSPILongLength > 0 {
		return fmt.Errorf("Windows/SSPI authentication is not supported; use SQL authentication")
	}
	return nil
}

// Login7Header is the fixed portion of LOGIN7
type Login7Header struct {
	Length            uint32
	TDSVersion        uint32
	PacketSize        uint32
	ClientProgVer     uint32
	ClientPID         uint32
	ConnectionID      uint32
	OptionFlags1      uint8
	OptionFlags2      uint8
	TypeFlags         uint8
	OptionFlags3      uint8
	ClientTimeZone    int32
	ClientLCID        uint32
	HostnameOffset    uint16
	HostnameLength    uint16
	UsernameOffset    uint16
	UsernameLength    uint16
	PasswordOffset    uint16
	PasswordLength    uint16
	AppNameOffset     uint16
	AppNameLength     uint16
	ServerNameOffset  uint16
	ServerNameLength  uint16
	ExtensionOffset   uint16
	ExtensionLength   uint16
	CltIntNameOffset  uint16
	CltIntNameLength  uint16
	LanguageOffset    uint16
	LanguageLength    uint16
	DatabaseOffset    uint16
	DatabaseLength    uint16
	ClientID          [6]byte
	SSPIOffset        uint16
	SSPILength        uint16
	AtchDBFileOffset  uint16
	AtchDBFileLength  uint16
	ChangePasswordOff uint16
	ChangePasswordLen uint16
	SSPILongLength    uint32
}

// Login7Message represents a LOGIN7 message
type Login7Message struct {
	Header   Login7Header
	Hostname string
	Username string
	Password string
	AppName  string
	Database string
}

// ParseLogin7 parses a LOGIN7 message (extracts only what we need)
func ParseLogin7(payload []byte) (*Login7Message, error) {
	if len(payload) < Login7FixedSize {
		return nil, fmt.Errorf("LOGIN7 too short")
	}

	msg := &Login7Message{}
	r := bytes.NewReader(payload)
	if err := binary.Read(r, binary.LittleEndian, &msg.Header); err != nil {
		return nil, err
	}

	msg.Hostname = readUTF16(payload, msg.Header.HostnameOffset, msg.Header.HostnameLength)
	msg.Username = readUTF16(payload, msg.Header.UsernameOffset, msg.Header.UsernameLength)
	// Note: We don't parse Password - we always inject our own credentials
	msg.AppName = readUTF16(payload, msg.Header.AppNameOffset, msg.Header.AppNameLength)
	msg.Database = readUTF16(payload, msg.Header.DatabaseOffset, msg.Header.DatabaseLength)

	return msg, nil
}

// LOGIN7 option flags
const (
	// OptionFlags1
	fUseDB   = 0x20
	fSetLang = 0x80

	// OptionFlags2
	fODBC = 0x02
)

// Encode serializes the LOGIN7 message
func (m *Login7Message) Encode() []byte {
	// Set required defaults if not specified
	if m.Header.TDSVersion == 0 {
		m.Header.TDSVersion = 0x74000004 // TDS 7.4
	}
	if m.Header.PacketSize == 0 {
		m.Header.PacketSize = 4096
	}

	// Set required option flags
	m.Header.OptionFlags1 = fUseDB | fSetLang
	m.Header.OptionFlags2 = fODBC

	hostname := encodeUTF16(m.Hostname)
	username := encodeUTF16(m.Username)
	password := manglePassword(m.Password)
	appname := encodeUTF16(m.AppName)
	database := encodeUTF16(m.Database)
	cltIntName := encodeUTF16("ODBC") // Client interface name

	// Calculate offsets
	offset := uint16(Login7FixedSize)

	m.Header.HostnameOffset = offset
	m.Header.HostnameLength = uint16(len(hostname) / 2)
	offset += uint16(len(hostname))

	m.Header.UsernameOffset = offset
	m.Header.UsernameLength = uint16(len(username) / 2)
	offset += uint16(len(username))

	m.Header.PasswordOffset = offset
	m.Header.PasswordLength = uint16(len(password) / 2)
	offset += uint16(len(password))

	m.Header.AppNameOffset = offset
	m.Header.AppNameLength = uint16(len(appname) / 2)
	offset += uint16(len(appname))

	m.Header.ServerNameOffset = offset
	m.Header.ServerNameLength = 0

	m.Header.ExtensionOffset = offset
	m.Header.ExtensionLength = 0

	m.Header.CltIntNameOffset = offset
	m.Header.CltIntNameLength = uint16(len(cltIntName) / 2)
	offset += uint16(len(cltIntName))

	m.Header.LanguageOffset = offset
	m.Header.LanguageLength = 0

	m.Header.DatabaseOffset = offset
	m.Header.DatabaseLength = uint16(len(database) / 2)
	offset += uint16(len(database))

	m.Header.SSPIOffset = offset
	m.Header.SSPILength = 0
	m.Header.AtchDBFileOffset = offset
	m.Header.AtchDBFileLength = 0
	m.Header.ChangePasswordOff = offset
	m.Header.ChangePasswordLen = 0
	m.Header.SSPILongLength = 0

	m.Header.Length = uint32(offset)

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, &m.Header); err != nil {
		panic(fmt.Sprintf("unexpected error encoding LOGIN7 header: %v", err))
	}
	buf.Write(hostname)
	buf.Write(username)
	buf.Write(password)
	buf.Write(appname)
	buf.Write(cltIntName)
	buf.Write(database)

	return buf.Bytes()
}

// Helper functions

func readUTF16(data []byte, offset, length uint16) string {
	if length == 0 {
		return ""
	}
	// Check for overflow and bounds
	start := int(offset)
	byteLen := int(length) * 2
	end := start + byteLen
	if start < 0 || end < 0 || start > len(data) || end > len(data) {
		return ""
	}
	runes := make([]rune, length)
	for i := 0; i < int(length); i++ {
		runes[i] = rune(binary.LittleEndian.Uint16(data[start+i*2:]))
	}
	return string(runes)
}

func encodeUTF16(s string) []byte {
	runes := []rune(s)
	buf := make([]byte, len(runes)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(buf[i*2:], uint16(r))
	}
	return buf
}

// manglePassword encodes a password for TDS LOGIN7.
// This is the standard TDS password obfuscation: swap nibbles then XOR with 0xA5.
// Note: go-mssqldb has an identical implementation but doesn't export it.
func manglePassword(password string) []byte {
	utf16 := encodeUTF16(password)
	for i, b := range utf16 {
		utf16[i] = ((b << 4) | (b >> 4)) ^ 0xA5
	}
	return utf16
}

// ContainsToken scans the TDS token stream for a specific token type.
// This is a simplified scan - tokens have variable lengths, but LoginAck (0xAD) and
// Error (0xAA) are distinctive enough that a byte scan is reliable for login responses.
func ContainsToken(payload []byte, token byte) bool {
	// For login responses, we're looking for specific tokens that are unlikely
	// to appear as data bytes. This is good enough for login success/failure detection.
	for _, b := range payload {
		if b == token {
			return true
		}
	}
	return false
}

// ParseResponseOutcome analyzes a TDS response payload and returns the outcome.
// Returns (hasError, errorMessage, rowsAffected).
// The TDS token stream contains ERROR tokens (0xAA) for failures and DONE tokens (0xFD) for completion.
func ParseResponseOutcome(payload []byte) (hasError bool, errorMsg string, rowsAffected int64) {
	if len(payload) < 2 {
		return false, "", 0
	}

	i := 0
	for i < len(payload) {
		token := payload[i]
		i++

		switch token {
		case TokenError:
			// ERROR token format:
			// 1 byte token (0xAA)
			// 2 bytes length (not including token and length)
			// 4 bytes error number
			// 1 byte state
			// 1 byte class (severity)
			// 2 bytes message length (in characters)
			// variable message (UTF-16LE)
			// ... more fields follow
			if i+8 > len(payload) {
				return true, "error parsing response", 0
			}
			length := int(binary.LittleEndian.Uint16(payload[i : i+2]))
			if i+2+length > len(payload) {
				return true, "error parsing response", 0
			}

			errorNum := binary.LittleEndian.Uint32(payload[i+2 : i+6])
			// state := payload[i+6]
			// class := payload[i+7]
			msgLen := int(binary.LittleEndian.Uint16(payload[i+8 : i+10]))

			if i+10+msgLen*2 > len(payload) {
				return true, fmt.Sprintf("error %d", errorNum), 0
			}

			// Extract UTF-16LE message
			msgBytes := payload[i+10 : i+10+msgLen*2]
			runes := make([]rune, 0, msgLen)
			for j := 0; j+1 < len(msgBytes); j += 2 {
				r := rune(binary.LittleEndian.Uint16(msgBytes[j:]))
				if r == 0 {
					break
				}
				runes = append(runes, r)
			}
			errorMsg = string(runes)
			hasError = true
			i += 2 + length

		case TokenDone, TokenDoneProc, TokenDoneInProc:
			// DONE token format:
			// 1 byte token
			// 2 bytes status
			// 2 bytes curcmd
			// 8 bytes done row count (only if DONE_COUNT flag is set)
			if i+4 > len(payload) {
				break
			}
			status := binary.LittleEndian.Uint16(payload[i : i+2])
			i += 4 // skip status and curcmd

			// Check if DONE_COUNT flag (0x10) is set
			if status&0x10 != 0 && i+8 <= len(payload) {
				rowsAffected = int64(binary.LittleEndian.Uint64(payload[i : i+8]))
				i += 8
			}

			// Check if DONE_ERROR flag (0x02) is set
			if status&0x02 != 0 {
				hasError = true
				if errorMsg == "" {
					errorMsg = "query failed"
				}
			}

		case TokenInfo:
			// INFO token has same structure as ERROR, skip it
			if i+2 > len(payload) {
				return hasError, errorMsg, rowsAffected
			}
			length := int(binary.LittleEndian.Uint16(payload[i : i+2]))
			i += 2 + length

		default:
			// Unknown token - we can't reliably skip it without knowing its length
			// Just continue scanning for known tokens
			continue
		}
	}

	return hasError, errorMsg, rowsAffected
}

// ExtractRPCText extracts readable text from an RPC request payload by
// scanning for UTF-16LE strings. This captures the procedure name,
// SQL text (for sp_executesql), and parameter values without needing
// to fully parse the RPC binary format.
func ExtractRPCText(payload []byte) string {
	if len(payload) < 6 {
		return "RPC"
	}

	// Skip ALL_HEADERS
	allHeadersLen := binary.LittleEndian.Uint32(payload[0:4])
	if allHeadersLen < 4 || int(allHeadersLen) > len(payload) {
		allHeadersLen = 0
	}

	// Scan the payload for UTF-16LE strings (runs of printable chars)
	data := payload[allHeadersLen:]
	var parts []string
	var current []rune
	for i := 0; i+1 < len(data); i += 2 {
		r := rune(binary.LittleEndian.Uint16(data[i:]))
		if r >= 0x20 && r < 0xFFFE {
			current = append(current, r)
		} else {
			if len(current) >= 3 {
				parts = append(parts, string(current))
			}
			current = current[:0]
		}
	}
	if len(current) >= 3 {
		parts = append(parts, string(current))
	}

	if len(parts) == 0 {
		return "RPC"
	}

	result := parts[0]
	for _, p := range parts[1:] {
		joined := result + " " + p
		if len(joined) > 4096 {
			break
		}
		result = joined
	}
	return result
}

// ExtractSQL extracts SQL text from a SQL_BATCH packet payload.
// SQL_BATCH format: ALL_HEADERS (4-byte total length + headers) followed by UTF-16LE SQL text
func ExtractSQL(payload []byte) string {
	if len(payload) < 6 {
		return ""
	}

	// ALL_HEADERS: first 4 bytes = total length of ALL_HEADERS section (includes these 4 bytes)
	allHeadersLen := binary.LittleEndian.Uint32(payload[0:4])

	// Sanity check: length should be at least 4 (the length field itself) and fit in payload
	if allHeadersLen < 4 || int(allHeadersLen) > len(payload) {
		// No valid ALL_HEADERS, try to parse as raw UTF-16
		allHeadersLen = 0
	}

	// SQL text starts after ALL_HEADERS
	offset := int(allHeadersLen)
	if offset >= len(payload) {
		return ""
	}

	// Parse UTF-16LE string
	remaining := payload[offset:]
	runes := make([]rune, 0, len(remaining)/2)
	for i := 0; i+1 < len(remaining); i += 2 {
		r := rune(binary.LittleEndian.Uint16(remaining[i:]))
		if r == 0 {
			break
		}
		runes = append(runes, r)
	}
	return string(runes)
}

// PassthroughConn wraps a connection and allows switching the underlying conn.
// Used for TLS handshake where we need to switch from TDS-wrapped I/O to direct I/O.
type PassthroughConn struct {
	Conn net.Conn
}

func (c *PassthroughConn) Read(b []byte) (int, error)  { return c.Conn.Read(b) }
func (c *PassthroughConn) Write(b []byte) (int, error) { return c.Conn.Write(b) }
func (c *PassthroughConn) Close() error                { return c.Conn.Close() }
func (c *PassthroughConn) LocalAddr() net.Addr         { return c.Conn.LocalAddr() }
func (c *PassthroughConn) RemoteAddr() net.Addr        { return c.Conn.RemoteAddr() }
func (c *PassthroughConn) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}
func (c *PassthroughConn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}
func (c *PassthroughConn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}

// TLSHandshakeConn wraps TLS handshake data inside TDS PRELOGIN packets.
// This is required because MSSQL performs TLS handshake within the TDS protocol
// rather than as a separate layer.
type TLSHandshakeConn struct {
	conn      net.Conn
	packetSeq uint8
	readBuf   bytes.Buffer
}

// NewTLSHandshakeConn creates a wrapper that encapsulates TLS handshake
// data within TDS PRELOGIN packets.
func NewTLSHandshakeConn(conn net.Conn) *TLSHandshakeConn {
	return &TLSHandshakeConn{
		conn:      conn,
		packetSeq: 1,
	}
}

// Read reads TLS data from TDS PRELOGIN packets.
func (c *TLSHandshakeConn) Read(b []byte) (int, error) {
	// Drain buffered data first
	if c.readBuf.Len() > 0 {
		return c.readBuf.Read(b)
	}

	// Read a TDS packet header
	header := make([]byte, TDSHeaderSize)
	if _, err := io.ReadFull(c.conn, header); err != nil {
		return 0, err
	}

	length := binary.BigEndian.Uint16(header[2:4])
	if length < TDSHeaderSize {
		return 0, fmt.Errorf("invalid TDS packet length: %d", length)
	}

	// Read the packet payload
	payloadLen := int(length) - TDSHeaderSize
	if payloadLen > 0 {
		payload := make([]byte, payloadLen)
		if _, err := io.ReadFull(c.conn, payload); err != nil {
			return 0, err
		}
		c.readBuf.Write(payload)
	}

	return c.readBuf.Read(b)
}

// Write wraps TLS data in TDS PRELOGIN packets and sends them.
func (c *TLSHandshakeConn) Write(b []byte) (int, error) {
	const maxPayload = 4088 // TDS packet size (4096) minus header (8)

	total := 0
	for len(b) > 0 {
		chunk := b
		if len(chunk) > maxPayload {
			chunk = b[:maxPayload]
		}
		b = b[len(chunk):]

		// Determine status: EOM if this is the last chunk
		status := uint8(0)
		if len(b) == 0 {
			status = StatusEOM
		}

		// Build TDS packet
		pktLen := uint16(TDSHeaderSize + len(chunk))
		header := make([]byte, TDSHeaderSize)
		header[0] = PacketTypePrelogin
		header[1] = status
		binary.BigEndian.PutUint16(header[2:4], pktLen)
		header[4] = 0 // SPID high
		header[5] = 0 // SPID low
		header[6] = c.packetSeq
		header[7] = 0 // Window

		c.packetSeq++

		// Write header + payload
		if _, err := c.conn.Write(header); err != nil {
			return total, err
		}
		if _, err := c.conn.Write(chunk); err != nil {
			return total, err
		}
		total += len(chunk)
	}

	return total, nil
}

func (c *TLSHandshakeConn) Close() error         { return c.conn.Close() }
func (c *TLSHandshakeConn) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c *TLSHandshakeConn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }
func (c *TLSHandshakeConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}
func (c *TLSHandshakeConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}
func (c *TLSHandshakeConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
