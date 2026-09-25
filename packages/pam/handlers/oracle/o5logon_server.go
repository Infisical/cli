package oracle

import (
	"fmt"
	"net"
)

const (
	TTCMsgAuthRequest = 0x03
	TTCMsgError       = 0x04
	TTCMsgStatus      = 0x09
)

const (
	AuthSubOpPhaseOne = 0x76
	AuthSubOpPhaseTwo = 0x73
)

func readDataPacket(conn net.Conn, use32BitLen bool) (*DataPacket, error) {
	raw, err := ReadFullPacket(conn, use32BitLen)
	if err != nil {
		return nil, err
	}
	if PacketTypeOf(raw) == PacketTypeMarker {
		return readDataPacket(conn, use32BitLen)
	}
	if PacketTypeOf(raw) != PacketTypeData {
		return nil, fmt.Errorf("expected DATA packet, got type=%d", raw[4])
	}
	return ParseDataPacket(raw, use32BitLen)
}

func writeDataPacket(conn net.Conn, pkt *DataPacket, use32BitLen bool) error {
	_, err := conn.Write(pkt.Bytes(use32BitLen))
	return err
}

func writeDataPayload(conn net.Conn, payload []byte, use32BitLen bool) error {
	d := &DataPacket{Payload: payload}
	_, err := conn.Write(d.Bytes(use32BitLen))
	return err
}

func BuildErrorPacket(oraCode int, message string) []byte {
	b := NewTTCBuilder()
	b.PutBytes(TTCMsgError)
	b.PutInt(0, 4, true, true)
	b.PutInt(0, 2, true, true)
	b.PutInt(0, 4, true, true)
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
	b.PutInt(0, 2, true, true)
	b.PutInt(0, 2, true, true)
	b.PutString(message)
	b.PutInt(0, 2, true, true)
	return b.Bytes()
}

func WriteErrorToClient(conn net.Conn, oraCode int, message string, use32BitLen bool) error {
	return writeDataPayload(conn, BuildErrorPacket(oraCode, message), use32BitLen)
}
