package oracle

import (
	"fmt"
	"net"
)

const (
	TTCMsgAuthRequest = 0x03
	TTCMsgError       = 0x04
)

const (
	AuthSubOpPhaseOne = 0x76
	AuthSubOpPhaseTwo = 0x73
)

type AuthPhaseTwo struct {
	EClientSessKey string
	EPassword      string
}

func readDataPayload(conn net.Conn, use32BitLen bool) ([]byte, error) {
	raw, err := ReadFullPacket(conn, use32BitLen)
	if err != nil {
		return nil, err
	}
	if PacketTypeOf(raw) == PacketTypeMarker {
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

func writeDataPayload(conn net.Conn, payload []byte, use32BitLen bool) error {
	d := &DataPacket{Payload: payload}
	_, err := conn.Write(d.Bytes(use32BitLen))
	return err
}

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

	out := &AuthPhaseTwo{}

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

	if _, err := r.GetInt(4, true, true); err != nil {
		return nil, err
	}
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
		// go-ora prefixes username with CLR length byte; JDBC thin sends it raw.
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
		}
	}
	return out, nil
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
