// Portions of this file are adapted from github.com/sijms/go-ora/v2,
// licensed under MIT. Copyright (c) 2020 Samy Sultan.
// Original sources:
//   auth_object.go (AuthObject.Write — phase-2 request layout mirrored by
//   ParseAuthPhaseTwo in reverse) and summary_object.go (Oracle error summary
//   packet layout mirrored by BuildErrorPacket).
// Modifications for server-side use by Infisical: the parser operates from the
// server's perspective (reading what go-ora's client would write), and the
// error packet is constructed standalone rather than via a Session.

package oracle

import (
	"fmt"
	"net"
)

// Packet-layer helpers for the O5Logon exchange: DATA-packet I/O, phase-2
// request parsing, and error packet construction. Used by proxy_auth.go's
// proxied-auth flow to parse AUTH_SESSKEY / AUTH_PASSWORD at the O5Logon
// boundary (so they can be re-encrypted before forwarding) and to synthesise
// clean error responses back to the client when upstream rejects auth.

// TTC function-call opcodes we touch during auth.
const (
	TTCMsgAuthRequest = 0x03 // generic "pre-auth" message
	TTCMsgError       = 0x04 // server's error summary packet
)

// AuthSubOp values — bundled inside a TTCMsgAuthRequest.
const (
	AuthSubOpPhaseOne = 0x76
	AuthSubOpPhaseTwo = 0x73
)

// AuthPhaseTwo carries the parsed client request that completes auth.
type AuthPhaseTwo struct {
	EClientSessKey string
	EPassword      string
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

	// Advance past mode + marker + count + 1 + 1. We don't keep any of these today,
	// but we have to consume them to reach the KVP list.
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
		// go-ora prefixes the username with a CLR length byte; JDBC thin sends it raw.
		// Peek to disambiguate.
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

	// Only AUTH_SESSKEY and AUTH_PASSWORD are consumed downstream; skip the rest.
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
	b.PutInt(0, 4, true, true) // endOfCallStatus
	b.PutInt(0, 2, true, true) // endToEndECID
	b.PutInt(0, 4, true, true) // currentRow
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
