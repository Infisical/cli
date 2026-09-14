package oracle

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	ociChunkedLengthMarker = 0xFE
	ociMaxCharacterWidth   = 4
)

func ociLocateValue(payload []byte, key string) (capStart, valStart, valLen int, err error) {
	// The capacity field ahead of a key is scaled by the character set on the request side, so the
	// key is anchored on its CLR length byte instead.
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
	capStart = idx + len(key)
	if capStart+5 > len(payload) {
		return 0, 0, 0, fmt.Errorf("key %s has no value header", key)
	}
	length := int(payload[capStart+4])
	if length == ociChunkedLengthMarker {
		return 0, 0, 0, fmt.Errorf("key %s uses chunked encoding", key)
	}
	valStart = capStart + 5
	if valStart+length > len(payload) {
		return 0, 0, 0, fmt.Errorf("key %s declares %d bytes past the end of the payload", key, length)
	}
	capacity := int(binary.LittleEndian.Uint32(payload[capStart : capStart+4]))
	if capacity < length || capacity > length*ociMaxCharacterWidth {
		return 0, 0, 0, fmt.Errorf("key %s has a capacity of %d for a %d byte value", key, capacity, length)
	}
	return capStart, valStart, length, nil
}

func ociGetValue(payload []byte, key string) (string, error) {
	_, valStart, valLen, err := ociLocateValue(payload, key)
	if err != nil {
		return "", err
	}
	return string(payload[valStart : valStart+valLen]), nil
}

func ociSetValue(payload []byte, key, newValue string) ([]byte, error) {
	capStart, valStart, valLen, err := ociLocateValue(payload, key)
	if err != nil {
		return nil, err
	}
	if len(newValue) >= ociChunkedLengthMarker {
		return nil, fmt.Errorf("replacement for %s is %d bytes, too long for a single chunk", key, len(newValue))
	}

	oldCapacity := binary.LittleEndian.Uint32(payload[capStart : capStart+4])
	scale := 1
	if valLen > 0 && int(oldCapacity)%valLen == 0 {
		scale = int(oldCapacity) / valLen
	}

	out := make([]byte, 0, len(payload)+len(newValue)-valLen)
	out = append(out, payload[:capStart]...)
	capacity := make([]byte, 4)
	binary.LittleEndian.PutUint32(capacity, uint32(len(newValue)*scale))
	out = append(out, capacity...)
	out = append(out, byte(len(newValue)))
	out = append(out, []byte(newValue)...)
	out = append(out, payload[valStart+valLen:]...)
	return out, nil
}

func ociHasKey(payload []byte, key string) bool {
	_, _, _, err := ociLocateValue(payload, key)
	return err == nil
}
