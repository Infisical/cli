package certscan

import (
	"errors"

	"go.mozilla.org/pkcs7"
)

const maxPKCS7NestingDepth = 1024

var (
	errPKCS7TooDeeplyNested = errors.New("pkcs7: structure nested too deeply")
	errPKCS7MalformedBER    = errors.New("pkcs7: malformed BER structure")
)

func parsePKCS7(der []byte) (*pkcs7.PKCS7, error) {
	if err := ensurePKCS7NestingWithinLimit(der); err != nil {
		return nil, err
	}
	return pkcs7.Parse(der)
}

func ensurePKCS7NestingWithinLimit(ber []byte) error {
	if len(ber) == 0 {
		return nil
	}
	w := &berWalker{ber: ber, budget: 4*len(ber) + maxPKCS7NestingDepth}
	_, err := w.walk(0, 0, len(ber))
	return err
}

type berWalker struct {
	ber    []byte
	budget int
}

func (w *berWalker) walk(offset, depth, limit int) (int, error) {
	if w.budget <= 0 {
		return offset, errPKCS7MalformedBER
	}
	w.budget--

	if depth > maxPKCS7NestingDepth {
		return offset, errPKCS7TooDeeplyNested
	}
	if offset >= limit {
		return offset, errPKCS7MalformedBER
	}

	b := w.ber[offset]
	offset++
	if offset >= limit {
		return offset, errPKCS7MalformedBER
	}

	if b&0x1f == 0x1f {
		for offset < limit && w.ber[offset] >= 0x80 {
			offset++
		}
		offset++
		if offset >= limit {
			return offset, errPKCS7MalformedBER
		}
	}

	kind := b & 0x20

	l := w.ber[offset]
	offset++
	if offset > limit {
		return offset, errPKCS7MalformedBER
	}

	length := 0
	indefinite := false
	switch {
	case l > 0x80:
		numberOfBytes := int(l & 0x7f)
		if numberOfBytes > 4 || offset+numberOfBytes > limit {
			return offset, errPKCS7MalformedBER
		}
		if numberOfBytes == 4 && int(w.ber[offset]) > 0x7f {
			return offset, errPKCS7MalformedBER
		}
		if int(w.ber[offset]) == 0x0 {
			return offset, errPKCS7MalformedBER
		}
		for range numberOfBytes {
			length = length*256 + int(w.ber[offset])
			offset++
		}
	case l == 0x80:
		indefinite = true
	default:
		length = int(l)
	}

	if length < 0 {
		return offset, errPKCS7MalformedBER
	}

	if indefinite {
		if kind == 0 {
			return offset, errPKCS7MalformedBER
		}
		for {
			var err error
			offset, err = w.walk(offset, depth+1, limit)
			if err != nil {
				return offset, err
			}
			if offset+2 > limit {
				return offset, errPKCS7MalformedBER
			}
			if w.ber[offset] == 0x0 && w.ber[offset+1] == 0x0 {
				return offset + 2, nil
			}
		}
	}

	contentEnd := offset + length
	if contentEnd > limit {
		return offset, errPKCS7MalformedBER
	}

	if kind == 0 {
		return contentEnd, nil
	}

	for offset < contentEnd {
		var err error
		offset, err = w.walk(offset, depth+1, contentEnd)
		if err != nil {
			return offset, err
		}
	}
	return contentEnd, nil
}
