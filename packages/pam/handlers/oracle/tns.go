// Portions of this file are adapted from github.com/sijms/go-ora/v2,
// licensed under MIT. Copyright (c) 2020 Samy Sultan.
// Original sources:
//   network/packets.go, network/connect_packet.go, network/accept_packet.go,
//   network/data_packet.go, network/marker_packet.go, network/refuse_packet.go
// Modifications for server-side use by Infisical: field accessors exported,
// added reader/writer helpers operating directly on io.Reader / io.Writer,
// removed Session/trace/encryption coupling (handled separately by the gateway).

package oracle

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

type PacketType uint8

const (
	PacketTypeConnect  PacketType = 1
	PacketTypeAccept   PacketType = 2
	PacketTypeAck      PacketType = 3
	PacketTypeRefuse   PacketType = 4
	PacketTypeRedirect PacketType = 5
	PacketTypeData     PacketType = 6
	PacketTypeNull     PacketType = 7
	PacketTypeAbort    PacketType = 9
	PacketTypeResend   PacketType = 11
	PacketTypeMarker   PacketType = 12
	PacketTypeAttn     PacketType = 13
	PacketTypeCtrl     PacketType = 14
)

const (
	markerTypeReset     uint8 = 2
	markerTypeInterrupt uint8 = 3
)

// TNS header is always 8 bytes. Length field is uint16 before handshakeComplete+v315,
// uint32 afterwards. For server-side use the simple rule is: CONNECT / ACCEPT / REFUSE /
// early MARKER use 16-bit length; post-ACCEPT (nego onwards) use 32-bit length when the
// negotiated version is >= 315. Callers pass use32BitLen explicitly so we don't carry
// hidden state.

// ReadPacketHeader reads the 8-byte TNS header and returns the parsed fields plus the
// full raw header bytes (so the caller can dispatch on PacketType and pass the full packet
// bytes to the type-specific parser). It reads the remaining payload into the returned
// buffer whose first 8 bytes are the header.
func ReadFullPacket(r io.Reader, use32BitLen bool) ([]byte, error) {
	head := make([]byte, 8)
	if _, err := io.ReadFull(r, head); err != nil {
		return nil, err
	}
	var length uint32
	if use32BitLen {
		length = binary.BigEndian.Uint32(head)
	} else {
		length = uint32(binary.BigEndian.Uint16(head))
	}
	if length < 8 {
		return nil, fmt.Errorf("invalid TNS packet length: %d", length)
	}
	if length > 1<<22 { // 4MB ceiling — Oracle SDU is 16-bit, but 32-bit length can go larger post-handshake
		return nil, fmt.Errorf("TNS packet too large: %d", length)
	}
	buf := make([]byte, length)
	copy(buf, head)
	if length > 8 {
		if _, err := io.ReadFull(r, buf[8:]); err != nil {
			return nil, err
		}
	}
	return buf, nil
}

func PacketTypeOf(packet []byte) PacketType {
	if len(packet) < 5 {
		return 0
	}
	return PacketType(packet[4])
}

// ConnectPacket holds the parsed fields from a client CONNECT packet (or used to build a
// response). Field layout matches go-ora's ConnectPacket / newConnectPacket.
type ConnectPacket struct {
	Version           uint16
	LoVersion         uint16
	Options           uint16
	SessionDataUnit   uint32
	TransportDataUnit uint32
	OurOne            uint16
	Flag              uint8
	ACFL0             uint8
	ACFL1             uint8
	DataOffset        uint16
	ConnectData       []byte // the connect-string payload ("(DESCRIPTION=...)")
}

func ParseConnectPacket(raw []byte) (*ConnectPacket, error) {
	if len(raw) < 70 {
		return nil, errors.New("CONNECT packet too short")
	}
	if PacketType(raw[4]) != PacketTypeConnect {
		return nil, fmt.Errorf("not a CONNECT packet: type=%d", raw[4])
	}
	p := &ConnectPacket{
		Version:     binary.BigEndian.Uint16(raw[8:]),
		LoVersion:   binary.BigEndian.Uint16(raw[10:]),
		Options:     binary.BigEndian.Uint16(raw[12:]),
		OurOne:      binary.BigEndian.Uint16(raw[22:]),
		ACFL0:       raw[32],
		ACFL1:       raw[33],
		DataOffset:  binary.BigEndian.Uint16(raw[26:]),
		Flag:        raw[5],
		// 16-bit SDU/TDU at offset 14/16; 32-bit at 58/62
		SessionDataUnit:   binary.BigEndian.Uint32(raw[58:]),
		TransportDataUnit: binary.BigEndian.Uint32(raw[62:]),
	}
	if p.SessionDataUnit == 0 {
		p.SessionDataUnit = uint32(binary.BigEndian.Uint16(raw[14:]))
	}
	if p.TransportDataUnit == 0 {
		p.TransportDataUnit = uint32(binary.BigEndian.Uint16(raw[16:]))
	}
	buffLen := binary.BigEndian.Uint16(raw[24:])
	if p.DataOffset > 0 && int(p.DataOffset)+int(buffLen) <= len(raw) {
		p.ConnectData = make([]byte, buffLen)
		copy(p.ConnectData, raw[int(p.DataOffset):int(p.DataOffset)+int(buffLen)])
	}
	return p, nil
}

// AcceptPacket is the server response to CONNECT, plus the negotiated session parameters
// the gateway will use. We always respond with >= v315 framing to match modern clients.
type AcceptPacket struct {
	Version           uint16
	NegotiatedOptions uint16
	SessionDataUnit   uint32
	TransportDataUnit uint32
	Histone           uint16
	ACFL0             uint8
	ACFL1             uint8
	ConnectData       []byte // usually empty on ACCEPT
}

// AcceptFromConnect returns a server-role ACCEPT that mirrors what a real Oracle 19c
// listener (RDS) sends. Captured values from a real AWS RDS Oracle listener:
//
//	version = 317, options = 0x0801 (2049), Histone = 256,
//	dataOffset = 45 (equals total length), ACFL0 = 0x41, ACFL1 = 0x01,
//	SDU = 8192, TDU = 2_097_152, 5 trailing zero bytes after the 32-bit SDU/TDU.
//
// These are the bytes JDBC thin actually validates against; downgrading version or
// shortening the packet makes it silently drop the TCP connection.
func AcceptFromConnect(c *ConnectPacket) *AcceptPacket {
	sdu := c.SessionDataUnit
	tdu := c.TransportDataUnit
	if sdu == 0 {
		sdu = 8192
	}
	if tdu == 0 {
		tdu = sdu
	}
	if sdu < 512 {
		sdu = 512
	}
	if tdu < sdu {
		tdu = sdu
	}
	if sdu > 2097152 {
		sdu = 2097152
	}
	if tdu > 2097152 {
		tdu = 2097152
	}
	return &AcceptPacket{
		Version:           317,
		NegotiatedOptions: 0x0801,
		SessionDataUnit:   sdu,
		TransportDataUnit: tdu,
		Histone:           256,
		ACFL0:             0x41,
		ACFL1:             0x01,
	}
}

// Bytes serializes the ACCEPT to wire format, mirroring a real Oracle 19c listener.
// For version < 315 we use the legacy 24-byte layout; for >= 315 the packet is 45
// bytes (header 0-23, reserved/reconAddr 24-31, 32-bit SDU/TDU 32-39, 5 trailing
// zero bytes 40-44). dataOffset equals the total length, indicating no trailing buffer.
func (a *AcceptPacket) Bytes() []byte {
	var dataOffset uint16
	if a.Version < 315 {
		dataOffset = 24
	} else {
		dataOffset = 45
	}
	length := uint32(int(dataOffset) + len(a.ConnectData))
	out := make([]byte, length)
	binary.BigEndian.PutUint16(out, uint16(length))
	out[4] = byte(PacketTypeAccept)
	out[5] = 0 // flag
	binary.BigEndian.PutUint16(out[8:], a.Version)
	binary.BigEndian.PutUint16(out[10:], a.NegotiatedOptions)
	if a.Version < 315 {
		sdu := uint16(a.SessionDataUnit)
		if a.SessionDataUnit > 0xFFFF {
			sdu = 0xFFFF
		}
		tdu := uint16(a.TransportDataUnit)
		if a.TransportDataUnit > 0xFFFF {
			tdu = 0xFFFF
		}
		binary.BigEndian.PutUint16(out[12:], sdu)
		binary.BigEndian.PutUint16(out[14:], tdu)
	} else {
		binary.BigEndian.PutUint32(out[32:], a.SessionDataUnit)
		binary.BigEndian.PutUint32(out[36:], a.TransportDataUnit)
	}
	binary.BigEndian.PutUint16(out[16:], a.Histone)
	binary.BigEndian.PutUint16(out[18:], uint16(len(a.ConnectData)))
	binary.BigEndian.PutUint16(out[20:], dataOffset)
	out[22] = a.ACFL0
	out[23] = a.ACFL1
	copy(out[dataOffset:], a.ConnectData)
	return out
}

// DataPacket wraps a single TNS DATA frame, without any ANO encryption/hash (the gateway
// refuses ANO so we never deal with those on the client-facing leg).
type DataPacket struct {
	DataFlag uint16
	Payload  []byte
}

func ParseDataPacket(raw []byte, use32BitLen bool) (*DataPacket, error) {
	if len(raw) < 10 || PacketType(raw[4]) != PacketTypeData {
		return nil, errors.New("not a DATA packet")
	}
	return &DataPacket{
		DataFlag: binary.BigEndian.Uint16(raw[8:]),
		Payload:  append([]byte(nil), raw[10:]...),
	}, nil
}

// Bytes serializes a DATA packet. use32BitLen must match the negotiated version (>= 315).
func (d *DataPacket) Bytes(use32BitLen bool) []byte {
	length := uint32(10 + len(d.Payload))
	out := make([]byte, length)
	if use32BitLen {
		binary.BigEndian.PutUint32(out, length)
	} else {
		binary.BigEndian.PutUint16(out, uint16(length))
	}
	out[4] = byte(PacketTypeData)
	out[5] = 0 // flag
	binary.BigEndian.PutUint16(out[8:], d.DataFlag)
	copy(out[10:], d.Payload)
	return out
}

// MarkerPacket fixed 11-byte frame for break / reset signals.
func MarkerPacketBytes(markerType uint8, use32BitLen bool) []byte {
	if use32BitLen {
		return []byte{0, 0x0, 0, 0xB, byte(PacketTypeMarker), 0, 0, 0, 1, 0, markerType}
	}
	return []byte{0, 0xB, 0, 0, byte(PacketTypeMarker), 0, 0, 0, 1, 0, markerType}
}

// RefusePacket is the server's polite "no" to an incoming CONNECT (pre-ACCEPT). Used for
// upstream-failure reporting.
type RefusePacket struct {
	UserReason   uint8
	SystemReason uint8
	Message      string
}

func (r *RefusePacket) Bytes() []byte {
	msg := []byte(r.Message)
	length := uint32(12 + len(msg))
	out := make([]byte, length)
	binary.BigEndian.PutUint16(out, uint16(length))
	out[4] = byte(PacketTypeRefuse)
	out[5] = 0
	out[8] = r.UserReason
	out[9] = r.SystemReason
	binary.BigEndian.PutUint16(out[10:], uint16(len(msg)))
	copy(out[12:], msg)
	return out
}

// WriteRefuseToClient is a convenience: build and write a REFUSE packet. The message
// should look like "(ERR=...)(ERROR_STACK=...)" so clients surface it as an Oracle error.
func WriteRefuseToClient(w io.Writer, message string) error {
	pkt := &RefusePacket{
		UserReason:   0,
		SystemReason: 0,
		Message:      message,
	}
	_, err := w.Write(pkt.Bytes())
	return err
}
