// Portions of this file are adapted from github.com/sijms/go-ora/v2,
// licensed under MIT. Copyright (c) 2020 Samy Sultan.
// Original: tcp_protocol_nego.go (newTCPNego) and data_type_nego.go (buildTypeNego,
// DataTypeNego.read/write, TZBytes).
// Modifications for server-side use: inverted roles — the gateway reads the client's
// ProtocolNego TTC message and responds with a fixed server profile matching 19c.

package oracle

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/rs/zerolog/log"
)

// Server-side protocol negotiation. The flow after the ACCEPT packet is:
//  1. Client sends a TCPNego TTC message (opcode 1): [0x01 <client_ver> 0x00 "client_name\x00"]
//  2. Server responds with its own TCPNego: [0x01 0x06 0x00 ...]
//  3. Client sends a DataTypeNego message (opcode 2) with client caps and type list.
//  4. Server responds with a matching DataTypeNego.
//
// We advertise a 19c-class server profile, which is the most broadly compatible choice
// across supported Oracle client drivers.

// Hard-coded server capabilities for a 19c-class server. These match go-ora's default
// CompileTimeCaps (modified for server role) and RuntimeCap.
var serverCompileTimeCaps = []byte{
	6, 1, 0, 0, 106, 1, 1, 11,
	1, 1, 1, 1, 1, 1, 0, 41,
	144, 3, 7, 3, 0, 1, 0, 235,
	1, 0, 5, 1, 0, 0, 0, 24,
	0, 0, 7, 32, 2, 58, 0, 0,
	5, 0, 0, 0, 8,
}

var serverRuntimeCaps = []byte{2, 1, 0, 0, 0, 0, 0}

// tzBytes returns the server's time zone — go-ora's TZBytes in reverse.
func tzBytes() []byte {
	_, offset := time.Now().Zone()
	hours := int8(offset / 3600)
	minutes := int8((offset / 60) % 60)
	seconds := int8(offset % 60)
	return []byte{128, 0, 0, 0, uint8(hours + 60), uint8(minutes + 60), uint8(seconds + 60), 128, 0, 0, 0}
}

// RunPreAuthExchange is a thin wrapper that calls RunPreAuthExchangeWithUpstream with no
// upstream overrides; responses are constructed from local templates (TCPNego) and
// dynamic echoes (DataTypeNego).
func RunPreAuthExchange(conn net.Conn, use32BitLen bool) (authPhase1Payload []byte, err error) {
	return RunPreAuthExchangeWithUpstream(conn, use32BitLen, nil, nil)
}

// RunPreAuthExchangeWithUpstream reads the client's pre-authentication DATA payloads and
// dispatches each based on content (ANO magic, TCPNego opcode, DataTypeNego opcode, auth
// opcode). If upstreamTCPNego and/or upstreamDataTypeNego are non-nil, those exact bytes
// are forwarded to the client as responses — aligning client-negotiated caps with what
// upstream actually negotiated. When nil, falls back to locally-built responses.
func RunPreAuthExchangeWithUpstream(conn net.Conn, use32BitLen bool, upstreamTCPNego, upstreamDataTypeNego []byte) (authPhase1Payload []byte, err error) {
	seenTCPNego := false
	seenDataTypeNego := false
	iteration := 0
	for {
		iteration++
		// Apply a generous per-step deadline so a client that stops sending surfaces
		// as a diagnosable timeout rather than blocking the handler forever.
		if tc, ok := conn.(interface{ SetReadDeadline(time.Time) error }); ok {
			_ = tc.SetReadDeadline(time.Now().Add(15 * time.Second))
		}
		payload, rerr := readDataPayload(conn, use32BitLen)
		if tc, ok := conn.(interface{ SetReadDeadline(time.Time) error }); ok {
			_ = tc.SetReadDeadline(time.Time{})
		}
		if rerr != nil {
			return nil, fmt.Errorf("read pre-auth payload (iter %d): %w", iteration, rerr)
		}
		if len(payload) == 0 {
			// Some clients send an empty DATA packet as a flush/ack between steps.
			// Skip it and read the next payload.
			log.Info().Int("iter", iteration).Msg("empty pre-auth payload (ignored)")
			continue
		}
		log.Info().
			Int("iter", iteration).
			Int("payloadLen", len(payload)).
			Str("firstBytes", fmt.Sprintf("% X", payload[:min(32, len(payload))])).
			Msg("Pre-auth payload received")

		// ANO request: DATA payload begins with 0xDEADBEEF magic (4-byte BE uint32).
		if len(payload) >= 4 && binary.BigEndian.Uint32(payload[:4]) == anoMagic {
			if werr := handleANOPayload(payload, conn, use32BitLen); werr != nil {
				return nil, werr
			}
			continue
		}

		switch payload[0] {
		case 1: // TCPNego
			if err := parseClientTCPNego(payload); err != nil {
				return nil, fmt.Errorf("parse client TCPNego: %w", err)
			}
			var resp []byte
			if upstreamTCPNego != nil {
				resp = upstreamTCPNego
				log.Info().Int("respLen", len(resp)).Msg("Server TCPNego response (from upstream)")
			} else {
				resp = buildServerTCPNego()
				log.Info().Int("respLen", len(resp)).Msg("Server TCPNego response (local)")
			}
			if err := writeDataPayload(conn, resp, use32BitLen); err != nil {
				return nil, fmt.Errorf("write server TCPNego: %w", err)
			}
			seenTCPNego = true
		case 2: // DataTypeNego
			req, err := parseClientDataTypeNego(payload)
			if err != nil {
				return nil, fmt.Errorf("parse client DataTypeNego: %w", err)
			}
			var resp []byte
			if upstreamDataTypeNego != nil {
				resp = upstreamDataTypeNego
				log.Info().Int("respLen", len(resp)).Msg("Server DataTypeNego response (from upstream)")
			} else {
				resp = buildServerDataTypeNego(req)
				log.Info().
					Int("clientTypes", len(req.Types)).
					Int("respLen", len(resp)).
					Msg("Server DataTypeNego response (echoed)")
			}
			if err := writeDataPayload(conn, resp, use32BitLen); err != nil {
				return nil, fmt.Errorf("write server DataTypeNego: %w", err)
			}
			seenDataTypeNego = true
		case TTCMsgAuthRequest: // 0x03 — auth phase 1 begins
			if !seenTCPNego || !seenDataTypeNego {
				// Permissive: some clients may skip nego steps; we still progress to auth.
			}
			return payload, nil
		default:
			return nil, fmt.Errorf("unexpected pre-auth payload opcode 0x%02X", payload[0])
		}
	}
}

func parseClientTCPNego(payload []byte) error {
	r := NewTTCReader(payload)
	op, err := r.GetByte()
	if err != nil {
		return err
	}
	if op != 1 {
		return fmt.Errorf("expected TCPNego opcode 1, got 0x%02X", op)
	}
	// client version byte
	if _, err := r.GetByte(); err != nil {
		return err
	}
	if _, err := r.GetByte(); err != nil {
		return err
	}
	// null-terminated client name
	if _, err := r.GetNullTermString(); err != nil {
		return err
	}
	return nil
}

// buildServerTCPNego returns the server's TCPNego response. We use RDS's exact bytes
// (captured from a real Oracle 19c listener) because JDBC thin uses the negotiated
// compile-time caps downstream for summary-object parsing — and any deviation from
// the real Oracle caps causes ORA-17401 during auth.
func buildServerTCPNego() []byte {
	// Return a copy so callers can't mutate the template.
	out := make([]byte, len(rdsTCPNegoResponse))
	copy(out, rdsTCPNegoResponse)
	return out
}

// DataTypeTuple is one entry in the client's offered type-representation list.
// Wire format is u16BE per field, with a trailing u16BE 0 between entries.
type DataTypeTuple struct {
	DataType     uint16
	ConvDataType uint16
	Representation uint16
}

// ClientDataTypeNegoRequest holds everything we parsed from the client's DataType Nego
// request. We keep the offered tuple list so we can echo it back in the response
// (mirror strategy — we claim to support whatever the client offered; the actual type
// handling happens upstream where go-ora already negotiated with real Oracle).
type ClientDataTypeNegoRequest struct {
	InCharset       uint16
	OutCharset      uint16
	Flags           byte
	CompileCaps     []byte
	RuntimeCaps     []byte
	TZBlock         []byte // 11 bytes if runtimeCaps[1]&1 else nil
	ClientTZVersion uint32 // present if TZBlock present AND compileCaps[37]&2
	HasTZVersion    bool
	ServernCharset  uint16
	Types           []DataTypeTuple
}

// parseClientDataTypeNego parses the client's DataType Nego payload into a struct the
// response builder can echo back from.
//
// Request wire format (ported from go-ora's DataTypeNego.write):
//   u8   opcode                0x02
//   u16LE client_in_charset
//   u16LE client_out_charset
//   u8   server_flags
//   u8   compile_caps_len
//   []   compile_caps
//   u8   runtime_caps_len
//   []   runtime_caps
//   [if runtime_caps[1]&1 == 1:
//     [11]byte tz_block
//     [if compile_caps[37]&2 == 2:
//       u32BE client_tz_version]]
//   u16LE server_ncharset
//   (tuples loop — each entry is either full [8B] or bare [4B]:
//     u16BE data_type
//     u16BE conv_data_type
//     [if conv_data_type != 0:
//       u16BE rep
//       u16BE 0 (separator)])
//   u16BE 0      // terminator
//
// Full entries carry a (dty, conv, rep) triple; bare entries are (dty, 0) used to signal
// types offered without a specific representation. Terminator is u16BE 0.
func parseClientDataTypeNego(payload []byte) (*ClientDataTypeNegoRequest, error) {
	r := NewTTCReader(payload)
	op, err := r.GetByte()
	if err != nil {
		return nil, err
	}
	if op != 2 {
		return nil, fmt.Errorf("expected DataTypeNego opcode 2, got 0x%02X", op)
	}
	req := &ClientDataTypeNegoRequest{}

	inBytes, err := r.GetBytes(2)
	if err != nil {
		return nil, fmt.Errorf("in_charset: %w", err)
	}
	req.InCharset = binary.LittleEndian.Uint16(inBytes)

	outBytes, err := r.GetBytes(2)
	if err != nil {
		return nil, fmt.Errorf("out_charset: %w", err)
	}
	req.OutCharset = binary.LittleEndian.Uint16(outBytes)

	req.Flags, err = r.GetByte()
	if err != nil {
		return nil, fmt.Errorf("flags: %w", err)
	}

	ccLen, err := r.GetByte()
	if err != nil {
		return nil, fmt.Errorf("compile_caps_len: %w", err)
	}
	req.CompileCaps, err = r.GetBytes(int(ccLen))
	if err != nil {
		return nil, fmt.Errorf("compile_caps: %w", err)
	}

	rcLen, err := r.GetByte()
	if err != nil {
		return nil, fmt.Errorf("runtime_caps_len: %w", err)
	}
	req.RuntimeCaps, err = r.GetBytes(int(rcLen))
	if err != nil {
		return nil, fmt.Errorf("runtime_caps: %w", err)
	}

	// Optional TZ preamble: 11 bytes if runtime_caps[1]&1 == 1, plus 4 more for
	// clientTZVersion if compile_caps[37]&2 == 2. Mirrored exactly in our response.
	if len(req.RuntimeCaps) >= 2 && req.RuntimeCaps[1]&1 == 1 {
		req.TZBlock, err = r.GetBytes(11)
		if err != nil {
			return nil, fmt.Errorf("tz_block: %w", err)
		}
		if len(req.CompileCaps) > 37 && req.CompileCaps[37]&2 == 2 {
			vBytes, err := r.GetBytes(4)
			if err != nil {
				return nil, fmt.Errorf("client_tz_version: %w", err)
			}
			req.ClientTZVersion = binary.BigEndian.Uint32(vBytes)
			req.HasTZVersion = true
		}
	}

	// ServernCharset (2 bytes LE) — always present.
	ncBytes, err := r.GetBytes(2)
	if err != nil {
		return nil, fmt.Errorf("server_ncharset: %w", err)
	}
	req.ServernCharset = binary.LittleEndian.Uint16(ncBytes)

	// Tuple loop. Full entry = 8 bytes (dty, conv, rep, 0). Bare = 4 bytes (dty, 0).
	// 2-byte fields are u16BE. CompileCaps[27]==0 would switch to 1-byte fields
	// (legacy mode); every mainstream modern client uses 2-byte.
	use1ByteFields := len(req.CompileCaps) > 27 && req.CompileCaps[27] == 0
	readField := func() (uint16, error) {
		if use1ByteFields {
			b, err := r.GetByte()
			return uint16(b), err
		}
		bs, err := r.GetBytes(2)
		if err != nil {
			return 0, err
		}
		return binary.BigEndian.Uint16(bs), nil
	}

	for {
		dt, err := readField()
		if err != nil {
			return nil, fmt.Errorf("tuple %d data_type: %w", len(req.Types), err)
		}
		if dt == 0 {
			break
		}
		conv, err := readField()
		if err != nil {
			return nil, fmt.Errorf("tuple %d conv_data_type: %w", len(req.Types), err)
		}
		t := DataTypeTuple{DataType: dt, ConvDataType: conv}
		if conv != 0 {
			rep, err := readField()
			if err != nil {
				return nil, fmt.Errorf("tuple %d rep: %w", len(req.Types), err)
			}
			sep, err := readField()
			if err != nil {
				return nil, fmt.Errorf("tuple %d separator: %w", len(req.Types), err)
			}
			if sep != 0 {
				log.Debug().
					Int("tuple", len(req.Types)).
					Uint16("separator", sep).
					Msg("DataTypeNego: unexpected non-zero tuple separator")
			}
			t.Representation = rep
		}
		req.Types = append(req.Types, t)
	}

	log.Info().
		Int("types", len(req.Types)).
		Int("compileCapsLen", len(req.CompileCaps)).
		Int("runtimeCapsLen", len(req.RuntimeCaps)).
		Bool("tzBlock", req.TZBlock != nil).
		Bool("tzVersion", req.HasTZVersion).
		Uint16("ncharset", req.ServernCharset).
		Msg("DataTypeNego request parsed")
	return req, nil
}

// buildServerDataTypeNego returns the server's DataTypeNego response that echoes back
// the client's offered type list as "all supported".
//
// Response wire format (per go-ora's DataTypeNego.read):
//   u8   opcode                 0x02
//   [if client_runtime_caps[1]&1 == 1:
//     [11]byte tz_block
//     [if client_compile_caps[37]&2 == 2:
//       u32BE server_tz_version]]
//   (tuples loop echoing client's offer — full entry 8B or bare 4B):
//     u16BE data_type
//     u16BE conv_data_type
//     [if conv != 0: u16BE rep, u16BE 0]
//   u16BE 0                     // terminator
//
// Strategy: "mirror everything." We don't maintain a server-side supported-type set
// because actual type handling happens upstream (go-ora → real Oracle negotiates for
// real). We just need the client to accept the handshake and move on to auth.
func buildServerDataTypeNego(req *ClientDataTypeNegoRequest) []byte {
	var out bytes.Buffer
	out.WriteByte(0x02) // opcode

	// Mirror the TZ preamble the client sent us. If the client included a TZ block,
	// the response must include one too; mismatches cause protocol violations.
	if req.TZBlock != nil {
		out.Write(tzBytes())
		if req.HasTZVersion {
			var vbuf [4]byte
			// Use a stable 19c-era serverTZVersion. Exact value doesn't matter — client
			// just validates structure and records it.
			binary.BigEndian.PutUint32(vbuf[:], 44)
			out.Write(vbuf[:])
		}
	}

	use1ByteFields := len(req.CompileCaps) > 27 && req.CompileCaps[27] == 0
	writeField := func(v uint16) {
		if use1ByteFields {
			out.WriteByte(byte(v))
			return
		}
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], v)
		out.Write(b[:])
	}

	// Echo each client-offered tuple. If client sent a full entry, we reply with a
	// full entry (supported). If client sent a bare entry (conv == 0), we reply with
	// a bare entry (also conv == 0) to mirror the structure.
	for _, t := range req.Types {
		writeField(t.DataType)
		writeField(t.ConvDataType)
		if t.ConvDataType != 0 {
			writeField(t.Representation)
			writeField(0) // separator
		}
	}
	// Final terminator: u16BE 0 (or u8 0 in legacy mode)
	writeField(0)
	return out.Bytes()
}
