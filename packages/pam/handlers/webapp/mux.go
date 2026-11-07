package webapp

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"sync"
)

const (
	MuxCDP byte = iota
	MuxControl
)

type Mux struct {
	r  io.Reader
	w  io.Writer
	mu sync.Mutex
}

func NewMux(r io.Reader, w io.Writer) *Mux { return &Mux{r: r, w: w} }

func muxLimit(channel byte) int {
	switch channel {
	case MuxCDP:
		return 16 << 20
	case MuxControl:
		return 64 << 10
	default:
		return 0
	}
}

func (m *Mux) Read() (byte, []byte, error) {
	var h [5]byte
	if _, err := io.ReadFull(m.r, h[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(h[1:])
	if muxLimit(h[0]) == 0 || n == 0 || uint64(n) > uint64(muxLimit(h[0])) {
		return 0, nil, errors.New("invalid mux message")
	}
	b := make([]byte, n)
	_, err := io.ReadFull(m.r, b)
	return h[0], b, err
}

func writeFull(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

func (m *Mux) Write(channel byte, b []byte) error {
	if len(b) == 0 || muxLimit(channel) == 0 || len(b) > muxLimit(channel) {
		return errors.New("invalid mux message")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var h [5]byte
	h[0] = channel
	binary.BigEndian.PutUint32(h[1:], uint32(len(b)))
	if err := writeFull(m.w, h[:]); err != nil {
		return err
	}
	return writeFull(m.w, b)
}

func (m *Mux) Control(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return m.Write(MuxControl, b)
}
