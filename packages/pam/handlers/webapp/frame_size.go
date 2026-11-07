package webapp

import (
	"bytes"
	"image"
	"image/jpeg"
)

const maxFrameEventBytes = 384 << 10

// SessionEvent base64 wraps an envelope that already contains a base64 JPEG.
const maxFrameJPEGBytes = (380 << 10) * 9 / 16

type captureSettings struct {
	quality int
	width   int
	height  int
}

func fitFrameJPEG(data []byte) ([]byte, int, int, int, error) {
	source, err := jpeg.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, 0, 0, 0, err
	}
	for {
		bounds := source.Bounds()
		for _, quality := range []int{60, 45, 30} {
			var encoded bytes.Buffer
			if err := jpeg.Encode(&encoded, source, &jpeg.Options{Quality: quality}); err != nil {
				return nil, 0, 0, 0, err
			}
			if encoded.Len() <= maxFrameJPEGBytes {
				return encoded.Bytes(), bounds.Dx(), bounds.Dy(), quality, nil
			}
		}
		width, height := max(1, bounds.Dx()*3/4), max(1, bounds.Dy()*3/4)
		resized := image.NewRGBA(image.Rect(0, 0, width, height))
		for y := range height {
			for x := range width {
				resized.Set(x, y, source.At(bounds.Min.X+x*bounds.Dx()/width, bounds.Min.Y+y*bounds.Dy()/height))
			}
		}
		source = resized
	}
}

func (s *Supervisor) applyCaptureSettings(v *surface) {
	s.mu.Lock()
	if s.ending || s.active != v.Seq {
		s.mu.Unlock()
		return
	}
	err := s.call(v.session, "Page.stopScreencast", map[string]any{}, nil)
	if err == nil {
		err = s.startCapture(v)
	}
	s.mu.Unlock()
	if err != nil {
		s.recordingFailure(err)
	}
}
