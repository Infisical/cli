package webapp

import (
	"encoding/binary"
	"fmt"
	"io"
)

// maxFrameSize bounds a single CDP message read off the tunnel, guarding
// against a corrupted or hostile length prefix causing an unbounded
// allocation. 32 MiB comfortably covers a full-size screencast JPEG frame.
const maxFrameSize = 32 * 1024 * 1024

// writeFrame writes one CDP message as a length-prefixed frame: a 4-byte
// big-endian length followed by the raw JSON payload. This preserves CDP
// message boundaries across the raw byte tunnel; the frontend unwraps the
// same framing on its end.
func writeFrame(w io.Writer, payload []byte) error {
	if len(payload) > maxFrameSize {
		return fmt.Errorf("cdp frame too large: %d bytes", len(payload))
	}
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(payload)))
	if _, err := w.Write(header); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// readFrame reads one length-prefixed CDP message from r, blocking until a
// full frame (or an error) is available.
func readFrame(r io.Reader) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(header)
	if length > maxFrameSize {
		return nil, fmt.Errorf("cdp frame too large: %d bytes", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}
