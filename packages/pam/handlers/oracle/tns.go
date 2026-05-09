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
	PacketTypeRefuse   PacketType = 4
	PacketTypeRedirect PacketType = 5
	PacketTypeData     PacketType = 6
	PacketTypeResend   PacketType = 11
	PacketTypeMarker   PacketType = 12
)

// use32BitLen: 32-bit length framing after ACCEPT (version >= 315), 16-bit before.
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
	if length > 1<<22 {
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

func (d *DataPacket) Bytes(use32BitLen bool) []byte {
	length := uint32(10 + len(d.Payload))
	out := make([]byte, length)
	if use32BitLen {
		binary.BigEndian.PutUint32(out, length)
	} else {
		binary.BigEndian.PutUint16(out, uint16(length))
	}
	out[4] = byte(PacketTypeData)
	out[5] = 0
	binary.BigEndian.PutUint16(out[8:], d.DataFlag)
	copy(out[10:], d.Payload)
	return out
}

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

func WriteRefuseToClient(w io.Writer, message string) error {
	pkt := &RefusePacket{
		UserReason:   0,
		SystemReason: 0,
		Message:      message,
	}
	_, err := w.Write(pkt.Bytes())
	return err
}
