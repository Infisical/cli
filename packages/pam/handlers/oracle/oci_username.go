package oracle

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	ociMaxUsernameLength      = 128
	ociUsernameCapacityFactor = 3
)

var ociPointerPlaceholder = []byte{0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

func ociIsIdentifierByte(b byte) bool {
	return b > 0x20 && b < 0x7F
}

func ociLocateUsername(payload []byte) (lenPos int, userLen int, err error) {
	limit := bytes.Index(payload, []byte("AUTH_"))
	if limit < 0 {
		limit = len(payload)
	}
	found := -1
	for at := 0; at+len(ociPointerPlaceholder) < limit; at++ {
		if !bytes.Equal(payload[at:at+len(ociPointerPlaceholder)], ociPointerPlaceholder) {
			continue
		}
		pos := at + len(ociPointerPlaceholder)
		n := int(payload[pos])
		if n < 1 || n > ociMaxUsernameLength || pos+1+n > limit {
			continue
		}
		valid := true
		for _, b := range payload[pos+1 : pos+1+n] {
			if !ociIsIdentifierByte(b) {
				valid = false
				break
			}
		}
		if valid {
			found = pos
		}
	}
	if found < 0 {
		return 0, 0, errAuthRequestHasNoUsername
	}
	return found, int(payload[found]), nil
}

func ociLocateUsernameCapacity(payload []byte, userLen, limit int) (int, error) {
	at := bytes.Index(payload[:limit], ociPointerPlaceholder)
	if at < 0 {
		return 0, fmt.Errorf("auth request carries no pointer placeholder")
	}
	capAt := at + len(ociPointerPlaceholder)
	if capAt+4 > limit {
		return 0, fmt.Errorf("auth request ends before the username capacity")
	}
	declared := int(binary.LittleEndian.Uint32(payload[capAt : capAt+4]))
	if declared != userLen*ociUsernameCapacityFactor {
		return 0, fmt.Errorf("username capacity is %d for a %d byte username", declared, userLen)
	}
	return capAt, nil
}

func ociRewriteAuthRequestUser(payload []byte, newUser string) ([]byte, error) {
	if len(newUser) < 1 || len(newUser) > ociMaxUsernameLength {
		return nil, errAuthRequestHasNoUsername
	}
	lenPos, userLen, err := ociLocateUsername(payload)
	if err != nil {
		return nil, err
	}
	capAt, err := ociLocateUsernameCapacity(payload, userLen, lenPos)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(payload)-userLen+len(newUser))
	out = append(out, payload[:lenPos]...)
	out = append(out, byte(len(newUser)))
	out = append(out, newUser...)
	out = append(out, payload[lenPos+1+userLen:]...)
	binary.LittleEndian.PutUint32(out[capAt:capAt+4], uint32(len(newUser)*ociUsernameCapacityFactor))
	return out, nil
}
