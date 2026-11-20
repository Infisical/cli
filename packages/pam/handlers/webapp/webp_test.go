package webapp

import (
	"encoding/binary"
	"testing"
)

func riff(chunk []byte) []byte {
	out := []byte("RIFF")
	out = binary.LittleEndian.AppendUint32(out, uint32(4+len(chunk)))
	out = append(out, "WEBP"...)
	return append(out, chunk...)
}

func webpChunk(name string, data []byte) []byte {
	out := []byte(name)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(data)))
	return append(out, data...)
}

// fakeWebP is a lossless WebP header of the given size followed by body. It is not a decodable
// image, only enough for webpSize.
func fakeWebP(width, height int, body []byte) []byte {
	data := []byte{0x2f}
	data = binary.LittleEndian.AppendUint32(data, uint32(width-1)|uint32(height-1)<<14)
	return riff(webpChunk("VP8L", append(data, body...)))
}

func TestWebPSize(t *testing.T) {
	lossy := []byte{0, 0, 0, 0x9d, 0x01, 0x2a}
	lossy = binary.LittleEndian.AppendUint16(lossy, 1920)
	lossy = binary.LittleEndian.AppendUint16(lossy, 1200)
	lossy = append(lossy, make([]byte, 16)...)

	extended := make([]byte, 10)
	extended[4], extended[5], extended[6] = 0xff, 0x04, 0x00
	extended[7], extended[8], extended[9] = 0x1f, 0x03, 0x00
	extended = append(extended, make([]byte, 16)...)

	cases := []struct {
		name          string
		data          []byte
		width, height int
	}{
		{"lossy", riff(webpChunk("VP8 ", lossy)), 1920, 1200},
		{"lossless", fakeWebP(1265, 800, make([]byte, 16)), 1265, 800},
		{"extended", riff(webpChunk("VP8X", extended)), 1280, 800},
	}
	for _, tc := range cases {
		w, h, err := webpSize(tc.data)
		if err != nil || w != tc.width || h != tc.height {
			t.Errorf("%s: %d x %d, %v; want %d x %d", tc.name, w, h, err, tc.width, tc.height)
		}
	}
	for name, bad := range map[string][]byte{
		"empty":     nil,
		"short":     riff(webpChunk("VP8L", []byte{0x2f})),
		"jpeg":      append([]byte{0xff, 0xd8, 0xff}, make([]byte, 40)...),
		"bad lossy": riff(webpChunk("VP8 ", make([]byte, 24))),
		"unknown":   riff(webpChunk("ALPH", make([]byte, 24))),
	} {
		if _, _, err := webpSize(bad); err == nil {
			t.Errorf("%s parsed as WebP", name)
		}
	}
}

func TestScreenshotScale(t *testing.T) {
	cases := []struct{ css, dsf, want float64 }{
		{1280, 1, 1},
		{1920, 1, 1},
		{1280, 2, 0.75},
		{2560, 1, 0.75},
		{1265, 1.5, 1},
		{1400, 1.5, 1920.0 / (1400 * 1.5)},
	}
	for _, tc := range cases {
		got := screenshotScale(tc.css, tc.dsf)
		if got != tc.want || tc.css*tc.dsf*got > screenshotMaxWidth+1e-9 {
			t.Errorf("screenshotScale(%v, %v) = %v, want %v", tc.css, tc.dsf, got, tc.want)
		}
	}
}
