package oracle

import (
	"bytes"
	"fmt"
)

const thinChunkedLengthMarker = 0xFE

func thinLocateValue(payload []byte, key string) (lenStart, valStart, valLen int, err error) {
	idx := -1
	for from := 0; ; {
		at := bytes.Index(payload[from:], []byte(key))
		if at < 0 {
			break
		}
		at += from
		if at > 0 && payload[at-1] == byte(len(key)) {
			idx = at
			break
		}
		from = at + 1
	}
	if idx < 0 {
		return 0, 0, 0, fmt.Errorf("key %s not present", key)
	}

	lenStart = idx + len(key)
	r := NewTTCReader(payload[lenStart:])
	declared, rerr := r.GetInt(4, true, true)
	if rerr != nil {
		return 0, 0, 0, fmt.Errorf("key %s has no value length: %w", key, rerr)
	}
	clrPos := lenStart + r.Pos()
	if clrPos >= len(payload) {
		return 0, 0, 0, fmt.Errorf("key %s has no value header", key)
	}
	length := int(payload[clrPos])
	if length == thinChunkedLengthMarker {
		return 0, 0, 0, fmt.Errorf("key %s uses chunked encoding", key)
	}
	if declared != length {
		return 0, 0, 0, fmt.Errorf("key %s declares %d but its chunk is %d", key, declared, length)
	}

	valStart = clrPos + 1
	if valStart+length > len(payload) {
		return 0, 0, 0, fmt.Errorf("key %s declares %d bytes past the end of the payload", key, length)
	}
	return lenStart, valStart, length, nil
}

func thinGetValue(payload []byte, key string) (string, error) {
	_, valStart, valLen, err := thinLocateValue(payload, key)
	if err != nil {
		return "", err
	}
	return string(payload[valStart : valStart+valLen]), nil
}

func thinSetValue(payload []byte, key, newValue string) ([]byte, error) {
	lenStart, valStart, valLen, err := thinLocateValue(payload, key)
	if err != nil {
		return nil, err
	}
	if len(newValue) >= thinChunkedLengthMarker {
		return nil, fmt.Errorf("replacement for %s is %d bytes, too long for a single chunk", key, len(newValue))
	}

	b := NewTTCBuilder()
	b.PutInt(int64(len(newValue)), 4, true, true)

	out := make([]byte, 0, len(payload)+len(newValue))
	out = append(out, payload[:lenStart]...)
	out = append(out, b.Bytes()...)
	out = append(out, byte(len(newValue)))
	out = append(out, []byte(newValue)...)
	out = append(out, payload[valStart+valLen:]...)
	return out, nil
}

func thinHasKey(payload []byte, key string) bool {
	_, _, _, err := thinLocateValue(payload, key)
	return err == nil
}
