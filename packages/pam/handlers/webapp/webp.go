package webapp

import (
	"encoding/binary"
	"errors"
)

var errNotWebP = errors.New("not a WebP image")

// webpSize reads an image's pixel size from its WebP header, which is all the gateway needs from
// it. The standard library has no WebP decoder.
func webpSize(data []byte) (int, int, error) {
	if len(data) < 20 || string(data[0:4]) != "RIFF" || string(data[8:12]) != "WEBP" {
		return 0, 0, errNotWebP
	}
	chunk := data[12:]
	switch string(chunk[0:4]) {
	case "VP8X":
		if len(chunk) < 18 {
			return 0, 0, errNotWebP
		}
		width := 1 + (int(chunk[12]) | int(chunk[13])<<8 | int(chunk[14])<<16)
		height := 1 + (int(chunk[15]) | int(chunk[16])<<8 | int(chunk[17])<<16)
		return width, height, nil
	case "VP8 ":
		if len(chunk) < 18 {
			return 0, 0, errNotWebP
		}
		frame := chunk[8:]
		if frame[3] != 0x9d || frame[4] != 0x01 || frame[5] != 0x2a {
			return 0, 0, errNotWebP
		}
		width := int(binary.LittleEndian.Uint16(frame[6:8]) & 0x3fff)
		height := int(binary.LittleEndian.Uint16(frame[8:10]) & 0x3fff)
		return width, height, nil
	case "VP8L":
		if len(chunk) < 13 || chunk[8] != 0x2f {
			return 0, 0, errNotWebP
		}
		bits := binary.LittleEndian.Uint32(chunk[9:13])
		return int(bits&0x3fff) + 1, int(bits>>14&0x3fff) + 1, nil
	}
	return 0, 0, errNotWebP
}
