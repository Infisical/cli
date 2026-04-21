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
