// Portions of this file are adapted from github.com/sijms/go-ora/v2,
// licensed under MIT. Copyright (c) 2020 Samy Sultan.
// Original: network/session.go codec helpers (PutUint/PutInt/PutClr/PutKeyVal/Get*).
// Modifications: lifted out as stateless helpers over bytes.Buffer / []byte cursor so
// the gateway can build and parse TTC payloads without owning a full go-ora Session.

package oracle

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

// TTCBuilder accumulates a TTC payload to be placed inside a DATA packet body.
// The resulting bytes go through Bytes() and are then embedded in a DataPacket.
type TTCBuilder struct {
	buf bytes.Buffer
	// useBigClrChunks mirrors go-ora's Session.UseBigClrChunks flag. Enabled when
	// ServerCompileTimeCaps[37]&32 != 0 (true for 12c+). Since we always negotiate a 19c
	// profile as the server, we can leave this true.
	useBigClrChunks bool
	clrChunkSize    int
}

func NewTTCBuilder() *TTCBuilder {
	return &TTCBuilder{useBigClrChunks: true, clrChunkSize: 0x7FFF}
}

func (b *TTCBuilder) Bytes() []byte { return b.buf.Bytes() }

func (b *TTCBuilder) PutBytes(data ...byte) { b.buf.Write(data) }

func (b *TTCBuilder) PutUint(num uint64, size uint8, bigEndian, compress bool) {
	if size == 1 {
		b.buf.WriteByte(uint8(num))
		return
	}
	if compress {
		temp := make([]byte, 8)
		binary.BigEndian.PutUint64(temp, num)
		temp = bytes.TrimLeft(temp, "\x00")
		if size > uint8(len(temp)) {
			size = uint8(len(temp))
		}
		if size == 0 {
			b.buf.WriteByte(0)
			return
		}
		b.buf.WriteByte(size)
		b.buf.Write(temp)
		return
	}
	temp := make([]byte, size)
	if bigEndian {
		switch size {
		case 2:
			binary.BigEndian.PutUint16(temp, uint16(num))
		case 4:
			binary.BigEndian.PutUint32(temp, uint32(num))
		case 8:
			binary.BigEndian.PutUint64(temp, num)
		}
	} else {
		switch size {
		case 2:
			binary.LittleEndian.PutUint16(temp, uint16(num))
		case 4:
			binary.LittleEndian.PutUint32(temp, uint32(num))
		case 8:
			binary.LittleEndian.PutUint64(temp, num)
		}
	}
	b.buf.Write(temp)
}

func (b *TTCBuilder) PutInt(num int64, size uint8, bigEndian, compress bool) {
	if compress {
		temp := make([]byte, 8)
		binary.BigEndian.PutUint64(temp, uint64(num))
		temp = bytes.TrimLeft(temp, "\x00")
		if size > uint8(len(temp)) {
			size = uint8(len(temp))
		}
		if size == 0 {
			b.buf.WriteByte(0)
			return
		}
		b.buf.WriteByte(size)
		b.buf.Write(temp[:size])
		return
	}
	b.PutUint(uint64(num), size, bigEndian, false)
}

// PutClr writes a chunked variable-length byte array. 1-byte length for short, 0xFE
// prefix + multi-chunk for long, matching go-ora's Session.PutClr.
func (b *TTCBuilder) PutClr(data []byte) {
	dataLen := len(data)
	if dataLen == 0 {
		b.buf.WriteByte(0)
		return
	}
	if dataLen > 0xFC {
		b.buf.WriteByte(0xFE)
		start := 0
		for start < dataLen {
			end := start + b.clrChunkSize
			if end > dataLen {
				end = dataLen
			}
			chunk := data[start:end]
			if b.useBigClrChunks {
				b.PutInt(int64(len(chunk)), 4, true, true)
			} else {
				b.buf.WriteByte(uint8(len(chunk)))
			}
			b.buf.Write(chunk)
			start += b.clrChunkSize
		}
		b.buf.WriteByte(0)
		return
	}
	b.buf.WriteByte(uint8(dataLen))
	b.buf.Write(data)
}

func (b *TTCBuilder) PutString(s string) { b.PutClr([]byte(s)) }

// PutKeyVal writes key + val + flag. This is the core TTC KVP format used for auth info.
func (b *TTCBuilder) PutKeyVal(key, val []byte, num uint32) {
	if len(key) == 0 {
		b.buf.WriteByte(0)
	} else {
		b.PutUint(uint64(len(key)), 4, true, true)
		b.PutClr(key)
	}
	if len(val) == 0 {
		b.buf.WriteByte(0)
	} else {
		b.PutUint(uint64(len(val)), 4, true, true)
		b.PutClr(val)
	}
	b.PutInt(int64(num), 4, true, true)
}

func (b *TTCBuilder) PutKeyValString(key, val string, num uint32) {
	b.PutKeyVal([]byte(key), []byte(val), num)
}

// TTCReader walks a TTC payload (the body of a DATA packet) and exposes the same codec
// as go-ora's Session, sans the network plumbing.
type TTCReader struct {
	buf             []byte
	pos             int
	useBigClrChunks bool
}

func NewTTCReader(payload []byte) *TTCReader {
	return &TTCReader{buf: payload, useBigClrChunks: true}
}

// SetUseBigClrChunks lets callers match negotiated capabilities. Default is true.
func (r *TTCReader) SetUseBigClrChunks(v bool) { r.useBigClrChunks = v }

func (r *TTCReader) Remaining() int { return len(r.buf) - r.pos }

func (r *TTCReader) read(n int) ([]byte, error) {
	if r.pos+n > len(r.buf) {
		return nil, io.ErrUnexpectedEOF
	}
	out := r.buf[r.pos : r.pos+n]
	r.pos += n
	return out, nil
}

func (r *TTCReader) GetByte() (uint8, error) {
	b, err := r.read(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

// PeekByte returns the next byte without advancing the position. Returns 0 and
// io.ErrUnexpectedEOF if the reader is exhausted. Callers should only rely on
// this for format-sniffing decisions (e.g., distinguishing a length-prefixed
// string from a raw string when clients differ in encoding).
func (r *TTCReader) PeekByte() (uint8, error) {
	if r.pos >= len(r.buf) {
		return 0, io.ErrUnexpectedEOF
	}
	return r.buf[r.pos], nil
}

func (r *TTCReader) GetBytes(n int) ([]byte, error) {
	b, err := r.read(n)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out, nil
}

func (r *TTCReader) GetInt64(size int, compress, bigEndian bool) (int64, error) {
	negFlag := false
	if compress {
		sb, err := r.read(1)
		if err != nil {
			return 0, err
		}
		size = int(sb[0])
		if size&0x80 > 0 {
			negFlag = true
			size = size & 0x7F
		}
		bigEndian = true
	}
	if size == 0 {
		return 0, nil
	}
	if size > 8 {
		return 0, errors.New("invalid size for GetInt64")
	}
	rb, err := r.read(size)
	if err != nil {
		return 0, err
	}
	temp := make([]byte, 8)
	var v int64
	if bigEndian {
		copy(temp[8-size:], rb)
		v = int64(binary.BigEndian.Uint64(temp))
	} else {
		copy(temp[:size], rb)
		v = int64(binary.LittleEndian.Uint64(temp))
	}
	if negFlag {
		v = -v
	}
	return v, nil
}

func (r *TTCReader) GetInt(size int, compress, bigEndian bool) (int, error) {
	v, err := r.GetInt64(size, compress, bigEndian)
	return int(v), err
}

// GetClr reads variable-length byte data.
func (r *TTCReader) GetClr() ([]byte, error) {
	nb, err := r.GetByte()
	if err != nil {
		return nil, err
	}
	if nb == 0 || nb == 0xFF || nb == 0xFD {
		return nil, nil
	}
	if nb != 0xFE {
		out, err := r.read(int(nb))
		if err != nil {
			return nil, err
		}
		ret := make([]byte, len(out))
		copy(ret, out)
		return ret, nil
	}
	var buf bytes.Buffer
	for {
		var chunkSize int
		if r.useBigClrChunks {
			chunkSize, err = r.GetInt(4, true, true)
		} else {
			b, err2 := r.GetByte()
			err = err2
			chunkSize = int(b)
		}
		if err != nil {
			return nil, err
		}
		if chunkSize == 0 {
			break
		}
		chunk, err := r.read(chunkSize)
		if err != nil {
			return nil, err
		}
		buf.Write(chunk)
	}
	return buf.Bytes(), nil
}

// GetDlc reads a length-prefixed variable-length byte array.
func (r *TTCReader) GetDlc() ([]byte, error) {
	length, err := r.GetInt(4, true, true)
	if err != nil {
		return nil, err
	}
	if length <= 0 {
		// length prefix = 0, but we still need to consume the CLR body (single zero byte).
		_, _ = r.GetClr()
		return nil, nil
	}
	out, err := r.GetClr()
	if err != nil {
		return nil, err
	}
	if len(out) > length {
		out = out[:length]
	}
	return out, nil
}

func (r *TTCReader) GetKeyVal() (key, val []byte, num int, err error) {
	key, err = r.GetDlc()
	if err != nil {
		return
	}
	val, err = r.GetDlc()
	if err != nil {
		return
	}
	num, err = r.GetInt(4, true, true)
	return
}

func (r *TTCReader) GetNullTermString() (string, error) {
	start := r.pos
	for r.pos < len(r.buf) {
		if r.buf[r.pos] == 0 {
			s := string(r.buf[start:r.pos])
			r.pos++
			return s, nil
		}
		r.pos++
	}
	return "", io.ErrUnexpectedEOF
}
